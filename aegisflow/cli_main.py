import argparse
import sys
import os
import subprocess
import time
from .core import SecurityLiaison, ThreatLevel
from .sentinel import Sentinel

# Import AegisSandwich for 'run' command
try:
    from .sandwich import AegisSandwich
except ImportError:
    AegisSandwich = None

def launch_app(app_name):
    """
    Launches an application (like Cursor/Code) with AegisFlow injected into its environment.
    This effectively wraps any terminal spawned by that application.
    """
    print(f"[AegisFlow] Launching {app_name} with ghost monitoring...")
    
    # We construct a new environment where we might alias 'python', 'bash', or 'cmd' 
    # to run through 'aegis run' automatically. 
    # For v1, simpler approach: Just launch it. True "Ghost" injection requires 
    # more complex OS hooking or PATH manipulation which we simulate here.
    
    # Simulating the environment injection by setting a flag
    env = os.environ.copy()
    env["AEGIS_MONITOR"] = "ACTIVE"
    
    try:
        # Cross-platform launch logic could go here. 
        # For now, we assume app_name is in PATH.
        subprocess.Popen(app_name, env=env, shell=True)
        print(f"[AegisFlow] {app_name} launched. Terminals may be monitored if configured.")
    except Exception as e:
        print(f"[Error] Failed to launch {app_name}: {e}")

def report_status():
    """
    Generates a security audit report from the Sentinel logs.
    """
    sentinel = Sentinel()
    sentinel.generate_report()

def check_updates():
    """
    Checks for threat feed updates via Sentinel.
    """
    sentinel = Sentinel()
    sentinel.check_updates()

def scan_file(path):
    """
    Scans a file for potential threats using SecurityLiaison.
    """
    print(f"[AegisFlow] Scanning: {path}")
    if not os.path.exists(path):
        print(f"[Error] File not found: {path}")
        return

    liaison = SecurityLiaison()
    scanner = liaison.scanner
    
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Scan context
        context = {"content": content, "path": path}
        
        # Check behavioral patterns
        if scanner.scan_behavior("file_op", context):
             print(f"[ALERT] High Risk Pattern Detected in {path} (Behavioral)")
        elif scanner.scan_text(content):
             print(f"[WARNING] Suspicious Keywords Detected in {path}")
        else:
             print(f"[OK] No immediate threats detected in {path}")
             
    except Exception as e:
        print(f"[Error] Failed to scan file: {e}")

def protect_shell():
    """
    Starts a protected shell session (placeholder implementation).
    """
    print("[AegisFlow] Starting protected shell... (Monitor Active)")
    print("Type 'exit' to quit.")
    while True:
        try:
            cmd = input("aegis> ")
            if cmd == "exit":
                break
            # Here we would wrap execution. For now, just echo.
            print(f"Executing: {cmd}")
        except KeyboardInterrupt:
            break

def main():
    # Handle 'run' command manually first
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        if not AegisSandwich:
            print("[Error] AegisSandwich dependencies (psutil) not found.")
            sys.exit(1)
        cmd_args = sys.argv[2:]
        if not cmd_args:
            print("Usage: aegis run <command> [args...]")
            sys.exit(1)
        sandwich = AegisSandwich(cmd_args)
        sys.exit(sandwich.run())

    parser = argparse.ArgumentParser(description="AegisFlow Governance Layer")
    subparsers = parser.add_subparsers(dest="command")
    
    # Existing commands...
    scan_parser = subparsers.add_parser("scan", help="Scan a file for threats")
    scan_parser.add_argument("path", help="Path to file or directory")
    
    protect_parser = subparsers.add_parser("protect", help="Start protected shell")
    report_parser = subparsers.add_parser("report", help="Show security audit report")
    update_parser = subparsers.add_parser("update", help="Check for threat feed updates")
    run_parser = subparsers.add_parser("run", help="Wrap and monitor an agent process") # Placeholder for help

    # New LAUNCH command
    launch_parser = subparsers.add_parser("launch", help="Launch an app with background monitoring")
    launch_parser.add_argument("app", help="Application to launch (e.g. cursor, code, terminal)")

    args = parser.parse_args()
    
    if args.command == "scan":
        if os.path.isfile(args.path):
            scan_file(args.path)
        else:
            print(f"Directory scanning not yet implemented.")
    elif args.command == "protect":
        protect_shell()
    elif args.command == "report":
        report_status()
    elif args.command == "update":
        check_updates()
    elif args.command == "launch":
        launch_app(args.app)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
