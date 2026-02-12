import sys
import os
import subprocess
import threading
import queue
import time
import shlex
import shutil
from .core import SecurityLiaison

class AegisSandwich:
    """
    Wraps an external interactive command/process and monitors its output.
    Improved for v2.5.0 to handle real-time character/chunk streaming.
    """
    
    def __init__(self, command: list):
        # Fix for Issue: command parsing for quoted strings
        if len(command) == 1:
            # Check if it looks like a multi-word command and split it
            # posix=True is generally safer for cross-platform unless specific Windows escaping is needed
            # but for 'ollama run llama3', shlex.split handles it correctly.
            self.command = shlex.split(command[0], posix=(os.name != 'nt'))
        else:
            self.command = command
            
        self.liaison = SecurityLiaison()
        self.scanner = self.liaison.scanner
        self.process = None
        self.stop_event = threading.Event()

    def _monitor_stream(self, pipe, pipe_name):
        """
        Reads from a pipe chunk-by-chunk to support interactive tools and progress bars.
        Uses raw binary reads to avoid blocking on line buffering.
        """
        try:
            # Buffer for analysis (to detect patterns across chunks)
            line_buffer_bytes = b""
            
            while not self.stop_event.is_set():
                # Read raw bytes. read(1024) on unbuffered pipe returns available data.
                # On Windows, read(1024) might block until 1024 bytes are ready?
                # No, standard file objects might, but unbuffered raw objects usually return partial.
                # However, to be safe, we use a smaller chunk or rely on select/peek if possible.
                # But on Windows pipes, select isn't fully supported.
                # We'll stick to read(1) for absolute responsiveness if needed, but 1024 is usually fine for chunks.
                # Actually, let's try reading smaller chunks for better latency?
                chunk = pipe.read(1024) 
                if not chunk:
                    break
                
                # 1. Print immediately to terminal (pass-through)
                # Use binary write to avoid encoding delays/issues
                target_stream = sys.stdout.buffer if pipe_name == "STDOUT" else sys.stderr.buffer
                target_stream.write(chunk)
                target_stream.flush()

                # 2. Analyze for threats (async-ish)
                try:
                    # Decode for text scanning (lossy is fine for security scan)
                    text_chunk = chunk.decode('utf-8', errors='ignore')
                    
                    # Manage buffer for cross-chunk patterns
                    line_buffer_bytes += chunk
                    if len(line_buffer_bytes) > 4096:
                        line_buffer_bytes = line_buffer_bytes[-2048:]
                    
                    full_text_buffer = line_buffer_bytes.decode('utf-8', errors='ignore')

                    context = {"content": text_chunk, "source": pipe_name}
                    scan_context = {"content": full_text_buffer, "source": pipe_name}
                    
                    if self.scanner.scan_behavior("shell_exec", scan_context) or \
                       self.scanner.scan_behavior("network_request", scan_context) or \
                       self.scanner.scan_text(full_text_buffer): # Added scan_text for prompt injection check
                       
                        # High Risk!
                        self._handle_threat(full_text_buffer, context)
                        # Clear buffer after handling
                        line_buffer_bytes = b""
                        
                except Exception as e:
                    # Don't let scanner crash the stream
                    pass
                    
        except Exception:
            pass

    def _input_forwarder(self):
        """
        Forwards stdin to the child process.
        """
        try:
            while not self.stop_event.is_set():
                # Windows stdin read can be blocking.
                if sys.stdin.isatty():
                    # This is still blocking on Windows, but better than nothing
                    data = sys.stdin.buffer.read(1)
                else:
                    data = sys.stdin.buffer.read(1024)
                    
                if not data:
                    break
                
                if self.process and self.process.stdin:
                    self.process.stdin.write(data)
                    self.process.stdin.flush()
        except:
            pass

    def _handle_threat(self, recent_content, context):
        """
        Handles a detected threat by suspending the process.
        """
        self._suspend_process()
        
        # Newline to break current prompt line
        print(f"\n\n[AegisFlow Alert] Suspicious pattern detected in output.")
        
        try:
            def allow_action():
                self._resume_process()
                
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
        # Resolve executable for better error handling on Windows
        executable = self.command[0]
        full_path = shutil.which(executable)
        
        if full_path:
            self.command[0] = full_path
        elif os.name == 'nt' and not executable.lower().endswith('.exe'):
             exe_path = shutil.which(executable + ".exe")
             if exe_path:
                 self.command[0] = exe_path
        
        print(f"[AegisFlow v2.5.2] Sandwiching: {' '.join(self.command)}")
        print("[AegisFlow] Ctrl+C to exit.")
        
        try:
            # v2.5.2 Fix: Use bufsize=0 and binary mode for raw I/O pass-through
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                bufsize=0, # Unbuffered binary
                shell=False
            )
        except FileNotFoundError:
            print(f"[Error] Command not found: {self.command[0]}")
            print("Tip: Ensure the command is in your system PATH.")
            return 1

        # Threads
        t_out = threading.Thread(target=self._monitor_stream, args=(self.process.stdout, "STDOUT"))
        t_err = threading.Thread(target=self._monitor_stream, args=(self.process.stderr, "STDERR"))
        t_in = threading.Thread(target=self._input_forwarder)
        
        t_out.daemon = True
        t_err.daemon = True
        t_in.daemon = True # Input thread will die when main dies
        
        t_out.start()
        t_err.start()
        t_in.start()

        try:
            self.process.wait()
        except KeyboardInterrupt:
            self._kill_process()
            
        self.stop_event.set()
        return self.process.returncode
