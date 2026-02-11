import subprocess
import threading
import queue
import time
import os
import signal
import psutil
from .core import SecurityLiaison, ThreatLevel

class AegisSandwich:
    """
    Wraps an external command/process and monitors its output for high-risk patterns.
    If a threat is detected, the child process is suspended until the user approves.
    """
    
    def __init__(self, command: list):
        self.command = command
        self.liaison = SecurityLiaison()
        self.scanner = self.liaison.scanner
        self.process = None
        self.output_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.is_suspended = False

    def _reader(self, pipe, pipe_name):
        """
        Reads lines from a pipe and puts them in the queue.
        """
        try:
            with pipe:
                for line in iter(pipe.readline, b''):
                    if self.stop_event.is_set():
                        break
                    self.output_queue.put((pipe_name, line.decode(errors='replace').rstrip()))
        except Exception:
            pass

    def _suspend_process(self):
        """
        Suspends the child process (and its children) using psutil.
        """
        try:
            parent = psutil.Process(self.process.pid)
            for child in parent.children(recursive=True):
                child.suspend()
            parent.suspend()
            self.is_suspended = True
            print("[AegisFlow] Process Suspended.")
        except psutil.NoSuchProcess:
            pass

    def _resume_process(self):
        """
        Resumes the child process (and its children).
        """
        try:
            parent = psutil.Process(self.process.pid)
            parent.resume()
            for child in parent.children(recursive=True):
                child.resume()
            self.is_suspended = False
            print("[AegisFlow] Process Resumed.")
        except psutil.NoSuchProcess:
            pass

    def run(self):
        """
        Executes the command wrapped in the AegisSandwich.
        """
        print(f"[AegisFlow] Launching protected process: {' '.join(self.command)}")
        
        try:
            # Start the process
            # We use bufsize=1 (line buffered) and universal_newlines=False for binary handling
            self.process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE, # Pass through stdin if needed, but tricky here
                bufsize=1,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            )
        except FileNotFoundError:
            print(f"[AegisFlow Error] Command not found: {self.command[0]}")
            return
            
        # Start reader threads
        t_out = threading.Thread(target=self._reader, args=(self.process.stdout, "STDOUT"))
        t_err = threading.Thread(target=self._reader, args=(self.process.stderr, "STDERR"))
        t_out.daemon = True
        t_err.daemon = True
        t_out.start()
        t_err.start()

        try:
            while True:
                # Check if process has exited
                if self.process.poll() is not None and self.output_queue.empty():
                    break
                
                try:
                    # Non-blocking get from queue
                    source, line = self.output_queue.get(timeout=0.1)
                except queue.Empty:
                    continue

                # Scan the output line for threats
                # We check for behavioral redlines in the output (e.g. "Deleting file...", "rm -rf")
                # This assumes the agent prints what it's doing or the tool output reflects it.
                
                context = {"content": line, "source": source}
                
                if self.scanner.scan_behavior("shell_exec", context) or \
                   self.scanner.scan_behavior("network_request", context):
                    
                    # High Risk Detected!
                    # 1. Suspend the process immediately
                    self._suspend_process()
                    
                    # 2. Mediate via Liaison (HitL)
                    try:
                        def resume_callback():
                            self._resume_process()
                            return line # Allow line to be printed
                            
                        # This will prompt the user
                        self.liaison.mediate(f"high_risk_output_detected ({source})", context, resume_callback)
                        
                    except PermissionError:
                        # User said NO. Kill the process.
                        print(f"[AegisFlow] Terminating process due to denied action.")
                        try:
                            parent = psutil.Process(self.process.pid)
                            for child in parent.children(recursive=True):
                                child.kill()
                            parent.kill()
                        except:
                            self.process.kill()
                        break
                
                # If no threat or approved, print the line to our stdout
                print(line)

        except KeyboardInterrupt:
            print("\n[AegisFlow] Interrupted by user.")
            if self.process:
                self.process.terminate()
        finally:
            self.stop_event.set()
            if self.process and self.process.poll() is None:
                self.process.terminate()
            
            # Clean exit
            if self.process:
                return self.process.returncode
            return 0
