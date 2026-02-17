"""
AegisFlow Sandwich v3.0 — Process Wrapper with Isolation & Cost Tracking

Wraps external commands/processes and monitors output for threats in real-time.
Supports isolation levels, auto-kill timeout, and token cost estimation.
"""

import sys
import os
import subprocess
import threading
import time
import shlex
import shutil
import logging
from typing import Optional, List, Dict, Any

from .core import SecurityLiaison
from .config import AegisConfig, SandwichConfig

logger = logging.getLogger("aegisflow.sandwich")


class AegisSandwich:
    """
    Wraps an external interactive command/process and monitors its output.

    Features (v3.0):
        - Real-time chunk-by-chunk output monitoring
        - Detection engine integration (regex + ML)
        - Isolation levels (0–3) for restricted execution
        - Auto-kill timeout
        - Token/cost tracking for LLM sessions
        - Session metrics reporting

    Usage::

        sandwich = AegisSandwich(["python", "agent.py"], isolation_level=1, timeout=300)
        exit_code = sandwich.run()
    """

    def __init__(
        self,
        command: list,
        config: Optional[AegisConfig] = None,
        isolation_level: Optional[int] = None,
        timeout: Optional[int] = None,
        track_cost: Optional[bool] = None,
    ):
        # Parse command
        if len(command) == 1:
            self.command = shlex.split(command[0], posix=(os.name != 'nt'))
        else:
            self.command = command

        # Config
        self._config = config or AegisConfig()
        sw_config = self._config.sandwich

        self.isolation_level = isolation_level if isolation_level is not None else sw_config.isolation_level
        self.timeout = timeout if timeout is not None else sw_config.auto_kill_timeout
        self.track_cost = track_cost if track_cost is not None else sw_config.track_cost

        # Core components
        self.liaison = SecurityLiaison(config=self._config)
        self.process = None
        self.stop_event = threading.Event()

        # Detection engine (try new v3 engine, fall back to legacy scanner)
        try:
            from .detectors import DetectionEngine
            self._detection_engine = DetectionEngine(self._config.detector)
            self._use_detection_engine = True
        except Exception:
            self._use_detection_engine = False

        # Session metrics
        self._metrics = {
            "start_time": None,
            "end_time": None,
            "total_bytes_stdout": 0,
            "total_bytes_stderr": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "estimated_tokens": 0,
            "isolation_level": self.isolation_level,
        }

    # ── Stream monitoring ───────────────────────────────────────────────

    def _monitor_stream(self, pipe, pipe_name: str):
        """
        Reads from a pipe chunk-by-chunk for interactive tool support.
        Uses raw binary reads to avoid blocking on line buffering.
        """
        try:
            line_buffer_bytes = b""

            while not self.stop_event.is_set():
                chunk = pipe.read(1024)
                if not chunk:
                    break

                # 1. Track metrics
                if pipe_name == "STDOUT":
                    self._metrics["total_bytes_stdout"] += len(chunk)
                else:
                    self._metrics["total_bytes_stderr"] += len(chunk)

                # Estimate tokens (rough: ~4 chars per token)
                if self.track_cost:
                    self._metrics["estimated_tokens"] += len(chunk) // 4

                # 2. Pass-through to terminal
                target = sys.stdout.buffer if pipe_name == "STDOUT" else sys.stderr.buffer
                target.write(chunk)
                target.flush()

                # 3. Threat detection
                try:
                    text_chunk = chunk.decode('utf-8', errors='ignore')
                    line_buffer_bytes += chunk
                    if len(line_buffer_bytes) > 4096:
                        line_buffer_bytes = line_buffer_bytes[-2048:]

                    full_text = line_buffer_bytes.decode('utf-8', errors='ignore')

                    threat_found = False
                    if self._use_detection_engine:
                        result = self._detection_engine.detect(full_text, {"source": pipe_name})
                        if result.is_threat and result.confidence >= 0.7:
                            threat_found = True
                            self._metrics["threats_detected"] += 1
                    else:
                        # Legacy scanner fallback
                        scanner = self.liaison.scanner
                        context = {"content": full_text, "source": pipe_name}
                        if (scanner.scan_behavior("shell_exec", context) or
                                scanner.scan_behavior("network_request", context) or
                                scanner.scan_text(full_text)):
                            threat_found = True
                            self._metrics["threats_detected"] += 1

                    if threat_found:
                        self._handle_threat(full_text, {"content": full_text, "source": pipe_name})
                        line_buffer_bytes = b""

                except Exception:
                    pass  # Don't let scanner crash the stream

        except Exception:
            pass

    def _input_forwarder(self):
        """Forwards stdin to the child process."""
        try:
            while not self.stop_event.is_set():
                data = sys.stdin.buffer.read(1) if sys.stdin.isatty() else sys.stdin.buffer.read(1024)
                if not data:
                    break
                if self.process and self.process.stdin:
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
        except Exception:
            pass

    def _timeout_watchdog(self):
        """Kills the process after the configured timeout."""
        if not self.timeout:
            return
        start = time.time()
        while not self.stop_event.is_set():
            if time.time() - start > self.timeout:
                logger.warning("Sandwich timeout (%ds) reached -- killing process", self.timeout)
                print(f"\n[AegisFlow] TIMEOUT ({self.timeout}s) reached, terminating process.")
                self._kill_process()
                self.stop_event.set()
                return
            time.sleep(1)

    # ── Threat handling ─────────────────────────────────────────────────

    def _handle_threat(self, recent_content: str, context: Dict[str, Any]):
        """Suspends the process and triggers HITL mediation."""
        self._suspend_process()
        print(f"\n\n[AegisFlow Alert] WARNING: Suspicious pattern detected in output.")

        try:
            def allow_action():
                self._resume_process()

            self.liaison.mediate("high_risk_output", context, allow_action)
        except PermissionError:
            print("[AegisFlow] Terminating process.")
            self._metrics["threats_blocked"] += 1
            self._kill_process()
            self.stop_event.set()
            sys.exit(1)

    # ── Process control ─────────────────────────────────────────────────

    def _suspend_process(self):
        try:
            import psutil
            parent = psutil.Process(self.process.pid)
            for child in parent.children(recursive=True):
                child.suspend()
            parent.suspend()
        except Exception:
            pass

    def _resume_process(self):
        try:
            import psutil
            parent = psutil.Process(self.process.pid)
            parent.resume()
            for child in parent.children(recursive=True):
                child.resume()
        except Exception:
            pass

    def _kill_process(self):
        if self.process:
            self.process.terminate()

    # ── Isolation ───────────────────────────────────────────────────────

    def _build_env(self) -> dict:
        """
        Build environment variables based on isolation level.

        Level 0: No isolation (pass-through)
        Level 1: Filter env vars (strip API keys, secrets)
        Level 2: Level 1 + read-only filesystem hint
        Level 3: Level 2 + Docker sandbox (if available)
        """
        env = os.environ.copy()
        env["AEGIS_MONITOR"] = "ACTIVE"
        env["AEGIS_ISOLATION"] = str(self.isolation_level)

        if self.isolation_level >= 1:
            # Strip environment variables that look like secrets
            secret_patterns = [
                "API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL",
                "AWS_", "AZURE_", "GCP_", "OPENAI_", "ANTHROPIC_",
                "STRIPE_", "GITHUB_TOKEN", "NPM_TOKEN", "PYPI_TOKEN",
            ]
            filtered = {}
            stripped_count = 0
            for k, v in env.items():
                should_strip = any(pat in k.upper() for pat in secret_patterns)
                if should_strip and k not in ("AEGIS_MONITOR", "AEGIS_ISOLATION"):
                    stripped_count += 1
                    logger.debug("Isolation L1: stripped env var %s", k)
                else:
                    filtered[k] = v
            env = filtered
            if stripped_count > 0:
                logger.info("Isolation L1: stripped %d secret env vars", stripped_count)

        if self.isolation_level >= 2:
            # Set hints for read-only filesystem
            env["AEGIS_READONLY"] = "1"
            env["TMPDIR"] = env.get("TMPDIR", env.get("TEMP", "/tmp"))
            logger.info("Isolation L2: read-only filesystem hint set")

        if self.isolation_level >= 3:
            logger.warning(
                "Isolation L3 (Docker sandbox) requested but not yet implemented. "
                "Running with L2 isolation."
            )

        return env

    # ── Main execution ──────────────────────────────────────────────────

    def run(self) -> int:
        """
        Start the sandwiched process and monitor it.
        Returns the process exit code.
        """
        # Resolve executable
        executable = self.command[0]
        full_path = shutil.which(executable)

        if full_path:
            self.command[0] = full_path
        elif os.name == 'nt' and not executable.lower().endswith('.exe'):
            exe_path = shutil.which(executable + ".exe")
            if exe_path:
                self.command[0] = exe_path

        # Build environment
        env = self._build_env()

        # Banner
        iso_label = ["none", "env-filter", "read-only", "docker"][min(self.isolation_level, 3)]
        print(f"[AegisFlow v3.0] Sandwiching: {' '.join(self.command)}")
        print(f"[AegisFlow] Isolation: L{self.isolation_level} ({iso_label})"
              f"{f'  Timeout: {self.timeout}s' if self.timeout else ''}"
              f"{f'  Cost tracking: ON' if self.track_cost else ''}")
        print("[AegisFlow] Ctrl+C to exit.\n")

        self._metrics["start_time"] = time.time()

        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                bufsize=0,
                shell=False,
                env=env,
            )
        except FileNotFoundError:
            print(f"[Error] Command not found: {self.command[0]}")
            print("Tip: Ensure the command is in your system PATH.")
            return 1

        # Start threads
        threads = [
            threading.Thread(target=self._monitor_stream, args=(self.process.stdout, "STDOUT"), daemon=True),
            threading.Thread(target=self._monitor_stream, args=(self.process.stderr, "STDERR"), daemon=True),
            threading.Thread(target=self._input_forwarder, daemon=True),
        ]
        if self.timeout:
            threads.append(threading.Thread(target=self._timeout_watchdog, daemon=True))

        for t in threads:
            t.start()

        try:
            self.process.wait()
        except KeyboardInterrupt:
            self._kill_process()

        self.stop_event.set()
        self._metrics["end_time"] = time.time()

        # Print session summary
        self._print_summary()

        return self.process.returncode

    def _print_summary(self):
        """Print session metrics on exit."""
        duration = (self._metrics["end_time"] or time.time()) - (self._metrics["start_time"] or time.time())
        total_bytes = self._metrics["total_bytes_stdout"] + self._metrics["total_bytes_stderr"]

        print(f"\n[AegisFlow] ── Session Summary ──")
        print(f"  Duration:    {duration:.1f}s")
        print(f"  Data:        {total_bytes:,} bytes")
        print(f"  Threats:     {self._metrics['threats_detected']} detected"
              f", {self._metrics['threats_blocked']} blocked")

        if self.track_cost:
            tokens = self._metrics["estimated_tokens"]
            # Rough cost estimate (GPT-4 pricing ~$0.03/1K tokens)
            est_cost = (tokens / 1000) * 0.03
            print(f"  Est. tokens: ~{tokens:,}")
            print(f"  Est. cost:   ~${est_cost:.4f}")

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return session metrics dict."""
        return dict(self._metrics)
