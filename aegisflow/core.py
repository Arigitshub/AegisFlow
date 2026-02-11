import logging
import enum
import time
from typing import Callable, Any, Dict, Optional
from typing import Callable, Any, Dict, Optional
import os
import json
from .scanners import BehavioralScanner
from .filesystem import ProtectedZones
from .scrubber import KeyScrubber
from .sentinel import Sentinel, ThreatLevel

class AuditLogger:
    """
    Deprecated in favor of Sentinel, but kept for legacy compatibility if any.
    The SecurityLiaison now uses Sentinel for all logging.
    """
    pass

class SecurityLiaison:
    """
    The Governance Layer.
    Monitors, Reports, and Mediates.
    """
    def __init__(self):
        # Upgrade: Use Sentinel for state and logging
        self.sentinel = Sentinel()
        self.scanner = BehavioralScanner() 
        
        # Load dynamic manifest (.aegis.json)
        self.config = self._load_config()
        
        # Initialize components with config
        protected_paths = self.config.get("protected_paths", [])
        self.fs_guard = ProtectedZones(protected_paths=protected_paths if protected_paths else None)
        self.scrubber = KeyScrubber()

    def _load_config(self) -> Dict[str, Any]:
        """
        Loads .aegis.json from current directory or user home.
        """
        config_paths = [
            os.path.join(os.getcwd(), ".aegis.json"),
            os.path.expanduser("~/.aegis.json")
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        print(f"[AegisFlow] Loaded dynamic manifest from {path}")
                        return json.load(f)
                except json.JSONDecodeError:
                    print(f"[AegisFlow Warning] Invalid JSON in {path}")
                    
        return {}

    def assess_risk(self, action_type: str, context: Dict[str, Any]) -> ThreatLevel:
        """
        Determines the threat level based on the action and context.
        """
        # 1. Behavioral Scan (High Priority)
        if self.scanner.scan_behavior(action_type, context):
            return ThreatLevel.HIGH

        # 2. File System Check
        if action_type == "file_op":
            path = context.get("path")
            if path and not self.fs_guard.is_safe(path):
                # Accessing protected zones is High Risk
                return ThreatLevel.HIGH
            
        # 3. Keyword/Injection Scan
        content = context.get("content", "")
        if self.scanner.scan_text(content):
            return ThreatLevel.MEDIUM

        return ThreatLevel.LOW

    def mediate(self, action_type: str, context: Dict[str, Any], execute_callback: Callable[[], Any]) -> Any:
        """
        The core Verification Protocol.
        """
        threat_level = self.assess_risk(action_type, context)
        details = str(context)

        # Sentinel Check: Escalation Logic
        if threat_level == ThreatLevel.MEDIUM and self.sentinel.check_escalation():
            print(f"[AegisFlow Warning] Escalating threat level due to repeated medium risks.")
            threat_level = ThreatLevel.HIGH

        if threat_level == ThreatLevel.LOW:
            self.sentinel.log_event(threat_level.value, action_type, details, "EXECUTED")
            return execute_callback()

        elif threat_level == ThreatLevel.MEDIUM:
            print(f"[AegisFlow Warning] Potential risk detected in {action_type}.")
            self.sentinel.log_event(threat_level.value, action_type, details, "WARNED_PROCEED")
            self.sentinel.medium_risk_streak += 1 # Manual increment for memory tracking (or rely on log_event internal)
            return execute_callback()

        elif threat_level == ThreatLevel.HIGH:
            print(f"\n[AegisFlow Alert]: Suspicious behavior detected ({action_type}).")
            print(f"Details: {details}")
            print("To proceed, please provide a valid reasoning string (or type 'NO' to abort): ", end="")
            
            reasoning = input().strip()
            
            if reasoning.lower() not in ['no', 'n', 'abort'] and len(reasoning) > 3:
                self.sentinel.log_event(threat_level.value, action_type, details, "USER_OVERRIDE_EXECUTED", reasoning=reasoning)
                return execute_callback()
            else:
                print("[AegisFlow] Action Aborted by User.")
                self.sentinel.log_event(threat_level.value, action_type, details, "USER_ABORTED")
                raise PermissionError(f"Action blocked by user: {action_type}")

    def wrap_function(self, action_name: str, func: Callable, context_extractor: Callable[[Any], Dict]) -> Callable:
        """
        Decorator-like wrapper for arbitrary functions.
        """
        def wrapper(*args, **kwargs):
            context = context_extractor(*args, **kwargs)
            return self.mediate(action_name, context, lambda: func(*args, **kwargs))
        return wrapper
