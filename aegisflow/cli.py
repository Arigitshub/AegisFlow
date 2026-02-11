import argparse
import sys
import os
from .core import SecurityLiaison, ThreatLevel

def scan_file(file_path):
    """
    Statically scans a file for dangerous patterns using BehavioralScanner.
    """
    liaison = SecurityLiaison()
    print(f"Scanning {file_path}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Context for scanning file content
        context = {"content": content, "path": file_path}
        
        # Check for behavioral redlines in the code itself (static analysis attempt)
        # Note: This is a heuristic scan, not a full AST parse.
        
        # We simulate "action_type" as if the code was executing these things
        threats = []
        if liaison.scanner.scan_behavior("shell_exec", context):
             threats.append("Contains Recursive/Dangerous Shell Commands")
        if liaison.scanner.scan_behavior("network_request", context):
             threats.append("Contains Suspicious Network Requests")
             
        if threats:
            print(f"[!] potential threats detected in {file_path}:")
            for t in threats:
                print(f"  - {t}")
            return False
        else:
            print(f"[+] No obvious threats found in {file_path}.")
            return True
            
    except Exception as e:
        print(f"[!] Error scanning file: {e}")
        return False

def protect_shell():
    """
    Starts an interactive protected shell (REPL) where commands are vetted.
    """
    liaison = SecurityLiaison()
    print("AegisFlow Protected Shell (v2.0)")
    print("Type 'exit' to quit.")
    
    while True:
        try:
            user_input = input("aegis> ")
            if user_input.lower() in ["exit", "quit"]:
                break
                
            # Treat input as a potential command to execute
            # In a real scenario, this would wrap execution. 
            # Here we just demonstrate the vetting logic.
            
            context = {"content": user_input, "command": user_input}
            
            # Helper to execute (simulated)
            def execute_command():
                print(f"Executing: {user_input}")
                # os.system(user_input) # DANGEROUS in demo, keep it simulated or careful
                return "Executed"

            try:
                # Assess risk of the command as a shell execution
                liaison.mediate("shell_exec", context, execute_command)
            except PermissionError:
                pass # Already handled by mediate printing
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")

from .sentinel import Sentinel

def report_status():
    sentinel = Sentinel()
    sentinel.generate_report()

def check_updates():
    sentinel = Sentinel()
    sentinel.check_updates()

def main():
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
    
    args = parser.parse_args()
    
    if args.command == "scan":
        if os.path.isfile(args.path):
            scan_file(args.path)
        else:
            print(f"Directory scanning not yet implemented. Please point to a file.")
    elif args.command == "protect":
        protect_shell()
    elif args.command == "report":
        report_status()
    elif args.command == "update":
        check_updates()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
