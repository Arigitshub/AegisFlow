import argparse
import sys
import os
import subprocess
import threading
import queue
import time
import signal
from .core import SecurityLiaison, ThreatLevel

class AegisSandwich:
    """
    Wraps an external interactive command/process and monitors its output for high-risk patterns.
    Designed for interactive CLI tools (like 'ollama run', 'python -i', 'bash').
    Uses threads to read stdout/stderr without blocking stdin.
    """
    
    def __init__(self, command: list):
        self.command = command
        self.liaison = SecurityLiaison()
        self.scanner = self.liaison.scanner
        self.process = None
        self.stop_event = threading.Event()

    def _monitor_stream(self, pipe, pipe_name):
        """
        Reads from a pipe character-by-character or line-by-line to support interactive tools.
        For simplicity and safety in v1, we use line-buffering but flush often.
        """
        try:
            # We use a simple line reader here. For true PTY support (like colored progress bars),
            # we would need the 'pty' module (Linux/macOS only) or 'pywinpty' (Windows).
            # Since we want cross-platform standard lib, we stick to subprocess pipes.
            # This might lose some color/formatting but ensures we can intercept text.
            
            for line in iter(pipe.readline, ''):
                if self.stop_event.is_set():
                    break
                
                if not line:
                    break

                # Scan the line for threats
                context = {"content": line.strip(), "source": pipe_name}
                
                # Check for Redlines
                if self.scanner.scan_behavior("shell_exec", context) or \
                   self.scanner.scan_behavior("network_request", context):
                   
                    # High Risk Detected!
                    # We can't easily suspend just the *printing* in standard pipes without buffering everything.
                    # But we can pause execution of the process via OS signals.
                    
                    self._handle_threat(line, context)
                else:
                    # Safe to print
                    print(line, end='', flush=True)
                    
        except Exception:
            pass

    def _handle_threat(self, line, context):
        """
        Handles a detected threat by suspending the process and asking for user override.
        """
        # 1. Suspend Process
        self._suspend_process()
        
        # 2. Clear current line to avoid messy output
        print(f"\n[AegisFlow Alert] Suspicious output detected in {context['source']}: {line.strip()}")
        
        # 3. Ask User (HITL)
        try:
            def allow_action():
                self._resume_process()
                print(line, end='', flush=True) # Print the blocked line
                
            self.liaison.mediate("high_risk_output", context, allow_action)
            
        except PermissionError:
            print("[AegisFlow] Terminating process.")
            self._kill_process()
            self.stop_event.set()
            sys.exit(1)

    def _suspend_process(self):
        try:
            import psutil
            parent = psutil.Process(self.process.pid)
            for child in parent.children(recursive=True):
                child.suspend()
            parent.suspend()
        except:
            pass

    def _resume_process(self):
        try:
            import psutil
            parent = psutil.Process(self.process.pid)
            parent.resume()
            for child in parent.children(recursive=True):
                child.resume()
        except:
            pass

    def _kill_process(self):
         if self.process:
            self.process.terminate()

    def run(self):
        """
        Executes the interactive command.
        """
        print(f"[AegisFlow] Wrapping interactive session: {' '.join(self.command)}")
        print("[AegisFlow] Monitoring active. Press Ctrl+C to exit.")
        
        # Use simple subprocess for now. 
        # For true interactive shell (stdin passthrough), we need to stream stdin too.
        
        try:
            # We use bufsize=1 (line buffered) and text=True for easier line scanning
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=sys.stdin, # Connect stdin directly to parent!
                text=True,
                bufsize=1,
                encoding='utf-8', 
                errors='replace'
            )
        except FileNotFoundError:
            print(f"[Error] Command not found: {self.command[0]}")
            return 1

        # Start monitoring threads for output
        t_out = threading.Thread(target=self._monitor_stream, args=(self.process.stdout, "STDOUT"))
        t_err = threading.Thread(target=self._monitor_stream, args=(self.process.stderr, "STDERR"))
        t_out.daemon = True
        t_err.daemon = True
        t_out.start()
        t_err.start()

        # Wait for process to finish
        try:
            self.process.wait()
        except KeyboardInterrupt:
            self._kill_process()
            
        self.stop_event.set()
        return self.process.returncode
