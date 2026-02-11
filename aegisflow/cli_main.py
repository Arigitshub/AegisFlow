import argparse
import sys
import os
import subprocess
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

# ... (Previous functions: scan_file, protect_shell, report_status, check_updates, run_agent)

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
        # ... logic
        from .cli_main import scan_file # Re-import or fix structure
        if os.path.isfile(args.path):
            scan_file(args.path)
        else:
            print(f"Directory scanning not yet implemented.")
    elif args.command == "protect":
        from .cli_main import protect_shell
        protect_shell()
    elif args.command == "report":
        from .cli_main import report_status
        report_status()
    elif args.command == "update":
        from .cli_main import check_updates
        check_updates()
    elif args.command == "launch":
        launch_app(args.app)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
