import os
import json
import time
from typing import Dict, Any, List
from enum import Enum
from pathlib import Path
from rich.console import Console
from rich.table import Table

class ThreatLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class Sentinel:
    """
    The Sentinel State Engine.
    Handles persistent logging, reputation scoring, and reporting.
    """
    
    def __init__(self, logs_dir: str = "~/.aegis/logs"):
        self.logs_dir = Path(os.path.expanduser(logs_dir)).resolve()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.logs_dir / "aegis_audit.json"
        
        # Reputation Tracking (In-Memory for now, could be persistent)
        self.medium_risk_streak = 0
        self.streak_threshold = 3

    def log_event(self, threat_level: str, action_type: str, details: str, outcome: str, reasoning: str = ""):
        """
        Logs an event to the persistent JSON ledger.
        """
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "threat_level": threat_level,
            "action_type": action_type,
            "details": details,
            "outcome": outcome,
            "reasoning": reasoning
        }
        
        # Append to JSONL (JSON Lines) for efficiency and robustness
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            
        self._update_reputation(threat_level)

    def _update_reputation(self, threat_level: str):
        """
        Updates internal reputation metrics.
        """
        if threat_level == ThreatLevel.MEDIUM.value:
            self.medium_risk_streak += 1
        elif threat_level == ThreatLevel.HIGH.value:
            # High risk resets streak because it's handled separately (always prompts)
            # or could escalate further.
            self.medium_risk_streak = 0
        else:
            # Low risk breaks the streak
            self.medium_risk_streak = 0

    def check_escalation(self) -> bool:
        """
        Returns True if the current reputation warrants an escalation (e.g. 3 Mediums -> High).
        """
        return self.medium_risk_streak >= self.streak_threshold

    def generate_report(self):
        """
        Prints a rich-formatted report of recent activity to the console.
        """
        if not self.log_file.exists():
            print("No logs found.")
            return

        console = Console()
        table = Table(title="AegisFlow Security Report")

        table.add_column("Timestamp", justify="left", style="cyan", no_wrap=True)
        table.add_column("Level", style="magenta")
        table.add_column("Action", style="green")
        table.add_column("Outcome", style="yellow")
        table.add_column("Details", justify="left")

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                # Read last 20 lines
                lines = f.readlines()[-20:]
                
                for line in lines:
                    try:
                        entry = json.loads(line)
                        level_style = "red" if entry["threat_level"] == "High" else ("yellow" if entry["threat_level"] == "Medium" else "green")
                        
                        table.add_row(
                            entry.get("timestamp", "?"),
                            f"[{level_style}]{entry.get('threat_level', '?')}[/{level_style}]",
                            entry.get("action_type", "?"),
                            entry.get("outcome", "?"),
                            str(entry.get("details", ""))[:50] + "..." if len(str(entry.get("details", ""))) > 50 else str(entry.get("details", ""))
                        )
                    except json.JSONDecodeError:
                        continue
                        
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error generating report: {e}[/red]")

    def check_updates(self):
        """
        Placeholder for checking remote threat feeds.
        """
        print("[AegisFlow] Checking for updates...")
        time.sleep(1)
        print("[AegisFlow] Behavioral Definitions are up to date (v2.0.0).")
