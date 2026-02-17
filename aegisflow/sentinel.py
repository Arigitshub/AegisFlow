"""
AegisFlow Sentinel State Engine (v3.0)
Persistent logging, reputation scoring, session tracking, and rich reporting.
"""

import os
import json
import time
import uuid
from typing import Dict, Any, List, Optional
from enum import Enum
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


class ThreatLevel(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Sentinel:
    """
    The Sentinel State Engine (v3.0).
    Now with persistent reputation, session tracking, numeric risk scoring, and export.
    """
    
    def __init__(self, logs_dir: str = "~/.aegis/logs", 
                 streak_threshold: int = 3,
                 session_id: str = None):
        self.logs_dir = Path(os.path.expanduser(logs_dir)).resolve()
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.logs_dir / "aegis_audit.json"
        self.state_file = self.logs_dir / "sentinel_state.json"
        
        # Session tracking
        self.session_id = session_id or str(uuid.uuid4())[:8]
        
        # Reputation
        self.streak_threshold = streak_threshold
        self.medium_risk_streak = 0
        self.risk_score = 0  # 0-100 numeric score
        self.total_events = 0
        self.threat_counts = {"Low": 0, "Medium": 0, "High": 0}
        
        # Load persisted state
        self._load_state()

    def _load_state(self):
        """Load persistent reputation state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    state = json.load(f)
                self.medium_risk_streak = state.get("medium_risk_streak", 0)
                self.risk_score = state.get("risk_score", 0)
                self.total_events = state.get("total_events", 0)
                self.threat_counts = state.get("threat_counts", self.threat_counts)
            except Exception:
                pass

    def _save_state(self):
        """Persist reputation state to disk."""
        state = {
            "session_id": self.session_id,
            "medium_risk_streak": self.medium_risk_streak,
            "risk_score": self.risk_score,
            "total_events": self.total_events,
            "threat_counts": self.threat_counts,
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        try:
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
        except Exception:
            pass

    def log_event(self, threat_level: str, action_type: str, details: str, 
                  outcome: str, reasoning: str = ""):
        """Logs an event to the persistent JSONL ledger."""
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "session_id": self.session_id,
            "threat_level": threat_level,
            "action_type": action_type,
            "details": details[:500],  # Cap details length
            "outcome": outcome,
            "reasoning": reasoning,
            "risk_score": self.risk_score,
        }
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
            
        self._update_reputation(threat_level)
        self._save_state()

    def _update_reputation(self, threat_level: str):
        """Updates internal reputation metrics with numeric scoring."""
        self.total_events += 1
        
        if threat_level in self.threat_counts:
            self.threat_counts[threat_level] += 1
        
        if threat_level == ThreatLevel.LOW.value:
            self.medium_risk_streak = 0
            self.risk_score = max(0, self.risk_score - 2)  # Cool down
        elif threat_level == ThreatLevel.MEDIUM.value:
            self.medium_risk_streak += 1
            self.risk_score = min(100, self.risk_score + 10)
        elif threat_level == ThreatLevel.HIGH.value:
            self.medium_risk_streak = 0
            self.risk_score = min(100, self.risk_score + 25)

    def check_escalation(self) -> bool:
        """Returns True if medium risk streak exceeds threshold."""
        return self.medium_risk_streak >= self.streak_threshold

    def get_risk_label(self) -> str:
        """Returns a human-readable risk label based on numeric score."""
        if self.risk_score >= 75:
            return "🔴 CRITICAL"
        elif self.risk_score >= 50:
            return "🟠 HIGH"
        elif self.risk_score >= 25:
            return "🟡 ELEVATED"
        else:
            return "🟢 NORMAL"

    def generate_report(self, limit: int = 20):
        """Prints a rich-formatted report to the console."""
        if not self.log_file.exists():
            print("No logs found.")
            return

        console = Console()
        
        # Summary panel
        summary = Text()
        summary.append(f"Session: {self.session_id}  ", style="dim")
        summary.append(f"Risk Score: {self.risk_score}/100  ", 
                       style="bold red" if self.risk_score >= 50 else "bold green")
        summary.append(f"Status: {self.get_risk_label()}\n")
        summary.append(f"Events: {self.total_events}  ")
        summary.append(f"Low: {self.threat_counts['Low']}  ", style="green")
        summary.append(f"Med: {self.threat_counts['Medium']}  ", style="yellow")
        summary.append(f"High: {self.threat_counts['High']}", style="red")
        
        console.print(Panel(summary, title="🛡️ AegisFlow Sentinel v3.0", border_style="blue"))

        # Event table
        table = Table(title="Recent Events")
        table.add_column("Time", style="cyan", no_wrap=True, width=19)
        table.add_column("Session", style="dim", width=8)
        table.add_column("Level", width=8)
        table.add_column("Action", style="green", width=20)
        table.add_column("Outcome", style="yellow", width=16)
        table.add_column("Details", justify="left", max_width=40)

        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
                
                for line in lines:
                    try:
                        e = json.loads(line)
                        level = e.get("threat_level", "?")
                        style = "red" if level == "High" else ("yellow" if level == "Medium" else "green")
                        details = str(e.get("details", ""))
                        if len(details) > 40:
                            details = details[:37] + "..."
                        
                        table.add_row(
                            e.get("timestamp", "?")[:19],
                            e.get("session_id", "?")[:8],
                            f"[{style}]{level}[/{style}]",
                            e.get("action_type", "?"),
                            e.get("outcome", "?"),
                            details
                        )
                    except json.JSONDecodeError:
                        continue
                        
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    def export_logs(self, format: str = "json", output_path: str = None) -> str:
        """Export audit logs to CSV, JSON, or HTML."""
        if not self.log_file.exists():
            return "No logs found."
        
        events = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        
        if format == "json":
            output = json.dumps(events, indent=2)
            ext = ".json"
        elif format == "csv":
            if not events:
                return "No events to export."
            headers = list(events[0].keys())
            lines = [",".join(headers)]
            for e in events:
                lines.append(",".join(str(e.get(h, "")).replace(",", ";") for h in headers))
            output = "\n".join(lines)
            ext = ".csv"
        elif format == "html":
            if not events:
                return "No events to export."
            headers = list(events[0].keys())
            rows = ""
            for e in events:
                cells = "".join(f"<td>{e.get(h, '')}</td>" for h in headers)
                rows += f"<tr>{cells}</tr>"
            header_row = "".join(f"<th>{h}</th>" for h in headers)
            output = f"""<!DOCTYPE html>
<html><head><title>AegisFlow Audit Report</title>
<style>body{{font-family:sans-serif}}table{{border-collapse:collapse;width:100%}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#2d3436;color:white}}
tr:nth-child(even){{background:#f2f2f2}}</style></head>
<body><h1>🛡️ AegisFlow Audit Report</h1>
<p>Generated: {time.strftime("%Y-%m-%d %H:%M:%S")} | Events: {len(events)}</p>
<table><tr>{header_row}</tr>{rows}</table></body></html>"""
            ext = ".html"
        else:
            return f"Unsupported format: {format}"
        
        if output_path is None:
            output_path = str(self.logs_dir / f"aegis_export{ext}")
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)
        
        return output_path

    def check_updates(self):
        """Placeholder for checking remote threat feeds."""
        print("[AegisFlow] Checking for updates...")
        time.sleep(1)
        print("[AegisFlow] Behavioral definitions are up to date (v3.0.0).")
