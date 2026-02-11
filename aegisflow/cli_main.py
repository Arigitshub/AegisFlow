from .sentinel import Sentinel

def report_status():
    sentinel = Sentinel()
    sentinel.generate_report()

def check_updates():
    sentinel = Sentinel()
    sentinel.check_updates()

def main():
    import argparse
    import os
    
    # We need to manually parse arguments because 'run' consumes the rest of the line
    if len(sys.argv) > 1 and sys.argv[1] == "run":
        # Handle run command manually to pass all args to sandwich
        cmd_args = sys.argv[2:]
        if not cmd_args:
            print("Usage: aegis run <command> [args...]")
            sys.exit(1)
            
        try:
            from .sandwich import AegisSandwich
            sandwich = AegisSandwich(cmd_args)
            return sandwich.run()
        except ImportError as e:
            print(f"[Error] Failed to load AegisSandwich: {e}")
            sys.exit(1)

    parser = argparse.ArgumentParser(description="AegisFlow Governance Layer")
    subparsers = parser.add_subparsers(dest="command")
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a file for threats")
    scan_parser.add_argument("path", help="Path to file or directory")
    
    # protect command
    protect_parser = subparsers.add_parser("protect", help="Start protected shell")
    
    # report command
    report_parser = subparsers.add_parser("report", help="Show security audit report")
    
    # update command
    update_parser = subparsers.add_parser("update", help="Check for threat feed updates")
    
    # run command help placeholder
    run_parser = subparsers.add_parser("run", help="Wrap and monitor an agent process (e.g., 'aegis run python agent.py')")

    args = parser.parse_args()
    
    if args.command == "scan":
        # ... (scan logic from previous implementation)
        from .cli import scan_file # Re-use or move logic
        if os.path.isfile(args.path):
            scan_file(args.path)
        else:
            print(f"Directory scanning not yet implemented. Please point to a file.")
    elif args.command == "protect":
        from .cli import protect_shell
        protect_shell()
    elif args.command == "report":
        report_status()
    elif args.command == "update":
        check_updates()
    else:
        parser.print_help()
