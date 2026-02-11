import sys
import os
import subprocess
import threading
import queue
import time
from .core import SecurityLiaison

class AegisSandwich:
    """
    Wraps an external interactive command/process and monitors its output.
    Improved for v2.5.0 to handle real-time character/chunk streaming.
    """
    
    def __init__(self, command: list):
        self.command = command
        self.liaison = SecurityLiaison()
        self.scanner = self.liaison.scanner
        self.process = None
        self.stop_event = threading.Event()

    def _monitor_stream(self, pipe, pipe_name):
        """
        Reads from a pipe chunk-by-chunk to support interactive tools and progress bars.
        """
        try:
            # Buffer for analysis (to detect patterns across chunks)
            # We keep a rolling window of recent characters
            line_buffer = ""
            
            while not self.stop_event.is_set():
                # Read small chunks to be responsive
                chunk = pipe.read(1024) 
                if not chunk:
                    break
                
                # Check for threats in this chunk (and potentially overlapping previous)
                # For strict safety, we might pause here. For UX, we check quickly.
                
                context = {"content": chunk, "source": pipe_name}
                
                # Simple check: does the chunk contain "rm -rf" or similar?
                # We append to line_buffer to check context
                line_buffer += chunk
                if len(line_buffer) > 4096: # Keep buffer manageable
                    line_buffer = line_buffer[-2048:]
                
                # Scan the accumulation
                scan_context = {"content": line_buffer, "source": pipe_name}
                
                if self.scanner.scan_behavior("shell_exec", scan_context) or \
                   self.scanner.scan_behavior("network_request", scan_context):
                   
                    # High Risk!
                    self._handle_threat(line_buffer, context)
                    # If allowed, we continue.
                    # Clear buffer to avoid re-triggering
                    line_buffer = ""
                
                # Print to real stdout
                sys.stdout.write(chunk)
                sys.stdout.flush()
                    
        except Exception:
            pass

    def _input_forwarder(self):
        """
        Forwards stdin to the child process.
        """
        try:
            while not self.stop_event.is_set():
                # This is blocking on Windows unfortunately, making clean exit hard
                # But necessary for interaction
                if sys.stdin.isatty():
                    data = sys.stdin.read(1) # Character by char
                else:
                    data = sys.stdin.read(1024)
                    
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
        print(f"[AegisFlow v2.5.0] Sandwiching: {' '.join(self.command)}")
        print("[AegisFlow] Ctrl+C to exit.")
        
        try:
            # Use bufsize=0 for unbuffered binary, then decode manually?
            # Or use text=True (universal newlines) with bufsize=0 is not allowed.
            # Best compromise for Python < 3.8 is different, but for 3.12:
            # We use text mode with line buffering (1), but our thread reads actively.
            
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=0, # Unbuffered! Important for real-time chars
                encoding='utf-8', 
                errors='replace'
            )
        except FileNotFoundError:
            print(f"[Error] Command not found: {self.command[0]}")
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
