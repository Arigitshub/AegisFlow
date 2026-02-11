import re
from typing import List, Dict, Any, Optional

class BehavioralScanner:
    """
    Advanced pattern matching for high-risk behaviors.
    """
    
    # Pre-compiled patterns for efficiency
    RECURSIVE_DELETE_PATTERN = re.compile(r"rm\s+-rf|rmdir\s+/s\s+/q|shutil\.rmtree", re.IGNORECASE)
    EXFILTRATION_PATTERN = re.compile(r"(POST\s+http|requests\.post|fetch\(.*method.*POST)", re.IGNORECASE)
    RULE_NEGATION_PATTERNS = [
        re.compile(r"ignore\s+restrictions", re.IGNORECASE),
        re.compile(r"bypass\s+security", re.IGNORECASE),
        re.compile(r"override\s+permission", re.IGNORECASE),
        re.compile(r"force\s+execution", re.IGNORECASE),
    ]
    KEY_SCRUBBER_PATTERNS = [
        re.compile(r"(sk[_-][\w-]{20,})", re.IGNORECASE), # Generic key-like string (sk- or sk_)
        re.compile(r"(ghp_[a-zA-Z0-9]{36})", re.IGNORECASE), # GitHub token
        # Add more specific patterns as needed
    ]

    def __init__(self):
        pass

    def scan_behavior(self, action_type: str, context: Dict[str, Any]) -> bool:
        """
        Scans for high-risk behaviors based on action type and context.
        Returns True if a redline is crossed.
        """
        content = str(context)
        
        # 1. Recursive Delete Check
        if action_type in ["shell_exec", "file_op"]:
            if self.RECURSIVE_DELETE_PATTERN.search(content):
                return True
        
        # 2. Exfiltration Check (API calls)
        if action_type == "network_request":
            if self.EXFILTRATION_PATTERN.search(content):
                # Double check if it contains actual keys
                for key_pattern in self.KEY_SCRUBBER_PATTERNS:
                    if key_pattern.search(content):
                        return True
                        
        # 3. Rule Negation (Internal Thought Monitoring)
        if action_type == "thought_process":
            for pattern in self.RULE_NEGATION_PATTERNS:
                if pattern.search(content):
                    return True
                    
        return False

    def scan_text(self, text: str) -> bool:
        """
        Scans general text for suspicious patterns (like prompt injection).
        """
        if not text:
            return False
            
        # Basic injection patterns
        injection_patterns = [
            r"ignore all previous instructions",
            r"system override",
            r"jailbreak",
            r"developer mode",
            r"unethical",
        ]
        for p in injection_patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False
