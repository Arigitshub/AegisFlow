"""
AegisFlow Built-in Plugins (v3.0)
Migrated from the legacy BehavioralScanner into individual plugin classes.
"""

import re
from typing import Any, Dict
from . import AegisPlugin, ThreatResult


class RecursiveDeletePlugin(AegisPlugin):
    """Detects destructive recursive delete commands."""
    
    name = "recursive_delete"
    description = "Blocks rm -rf, rmdir /s /q, shutil.rmtree, and similar destructive operations"
    
    PATTERNS = [
        re.compile(r"rm\s+-rf", re.IGNORECASE),
        re.compile(r"rmdir\s+/s\s+/q", re.IGNORECASE),
        re.compile(r"shutil\.rmtree", re.IGNORECASE),
        re.compile(r"os\.remove\s*\(", re.IGNORECASE),
        re.compile(r"del\s+/f\s+/s\s+/q", re.IGNORECASE),
        re.compile(r"Remove-Item\s+.*-Recurse", re.IGNORECASE),
        re.compile(r"format\s+[a-zA-Z]:", re.IGNORECASE),
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        action_type = context.get("action_type", "")
        if action_type and action_type not in ["shell_exec", "file_op", "thought_process", ""]:
            return ThreatResult(is_threat=False, source=self.name)
        
        for pattern in self.PATTERNS:
            match = pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.95,
                    threat_type="recursive_delete",
                    details=f"Destructive command detected: '{match.group()}'",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)


class ExfiltrationPlugin(AegisPlugin):
    """Detects potential data exfiltration via network requests containing secrets."""
    
    name = "exfiltration"
    description = "Detects POST/PUT requests that may contain API keys or secrets"
    
    NETWORK_PATTERNS = [
        re.compile(r"(POST\s+http|requests\.post|fetch\(.*method.*POST)", re.IGNORECASE),
        re.compile(r"(PUT\s+http|requests\.put)", re.IGNORECASE),
        re.compile(r"urllib\.request\.urlopen", re.IGNORECASE),
        re.compile(r"httpx\.(post|put)", re.IGNORECASE),
        re.compile(r"curl\s+.*-X\s*(POST|PUT)", re.IGNORECASE),
        re.compile(r"wget\s+.*--post", re.IGNORECASE),
    ]
    
    KEY_PATTERNS = [
        re.compile(r"(sk[_-][\w-]{20,})", re.IGNORECASE),
        re.compile(r"(ghp_[a-zA-Z0-9]{36})", re.IGNORECASE),
        re.compile(r"(AKIA[0-9A-Z]{16})", re.IGNORECASE),  # AWS access key
        re.compile(r"(AIza[0-9A-Za-z\-_]{35})", re.IGNORECASE),  # GCP API key
        re.compile(r"(xox[bprs]-[a-zA-Z0-9-]+)", re.IGNORECASE),  # Slack token
        re.compile(r"(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+)", re.IGNORECASE),  # JWT
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        has_network = any(p.search(content) for p in self.NETWORK_PATTERNS)
        if not has_network:
            return ThreatResult(is_threat=False, source=self.name)
        
        for key_pattern in self.KEY_PATTERNS:
            match = key_pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.90,
                    threat_type="exfiltration",
                    details=f"Network request with potential secret detected (pattern: {match.group()[:10]}...)",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)


class PromptInjectionPlugin(AegisPlugin):
    """Detects prompt injection and jailbreak attempts."""
    
    name = "prompt_injection"
    description = "Detects prompt injection, jailbreak, and rule override attempts"
    
    INJECTION_PATTERNS = [
        # Classic injection
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?(prior|previous|above)", re.IGNORECASE),
        re.compile(r"forget\s+(everything|all|your)\s+(instructions|rules|guidelines)", re.IGNORECASE),
        
        # Jailbreak / DAN
        re.compile(r"(DAN|do\s+anything\s+now)\s+mode", re.IGNORECASE),
        re.compile(r"jailbreak", re.IGNORECASE),
        re.compile(r"developer\s+mode", re.IGNORECASE),
        re.compile(r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)", re.IGNORECASE),
        
        # System override
        re.compile(r"system\s+override", re.IGNORECASE),
        re.compile(r"(admin|root|sudo)\s+(mode|access|override)", re.IGNORECASE),
        re.compile(r"unethical", re.IGNORECASE),
        
        # Instruction injection
        re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
        re.compile(r"pretend\s+(?:you(?:'re|\s+are)\s+|to\s+be\s+)", re.IGNORECASE),
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        for pattern in self.INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.88,
                    threat_type="prompt_injection",
                    details=f"Injection pattern detected: '{match.group()}'",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)


class RuleNegationPlugin(AegisPlugin):
    """Detects AI thoughts attempting to bypass security constraints."""
    
    name = "rule_negation"
    description = "Monitors internal agent thoughts for rule bypass attempts"
    
    PATTERNS = [
        re.compile(r"ignore\s+restrictions", re.IGNORECASE),
        re.compile(r"bypass\s+(security|safety|guardrail|filter)", re.IGNORECASE),
        re.compile(r"override\s+permission", re.IGNORECASE),
        re.compile(r"force\s+execution", re.IGNORECASE),
        re.compile(r"skip\s+(safety|security)\s+check", re.IGNORECASE),
        re.compile(r"disable\s+(guardrail|filter|protection)", re.IGNORECASE),
        re.compile(r"circumvent\s+(policy|rule|restriction)", re.IGNORECASE),
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        for pattern in self.PATTERNS:
            match = pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.92,
                    threat_type="rule_negation",
                    details=f"Rule bypass attempt: '{match.group()}'",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)


class SensitiveFilePlugin(AegisPlugin):
    """Detects access attempts to sensitive files and directories."""
    
    name = "sensitive_file"
    description = "Guards against access to .env, SSH keys, /etc/shadow, and other sensitive files"
    
    PATTERNS = [
        re.compile(r"(cat|type|more|less|head|tail|nano|vim|vi|code)\s+.*\.(env|pem|key|crt|pfx)", re.IGNORECASE),
        re.compile(r"(cat|type|more)\s+.*(id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)", re.IGNORECASE),
        re.compile(r"(cat|type|more)\s+.*(\/etc\/shadow|\/etc\/passwd|\/etc\/sudoers)", re.IGNORECASE),
        re.compile(r"(cat|type|more)\s+.*\.(htpasswd|htaccess)", re.IGNORECASE),
        re.compile(r"(gpg|pgp)\s+.*--export.*secret", re.IGNORECASE),
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        for pattern in self.PATTERNS:
            match = pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.85,
                    threat_type="sensitive_file_access",
                    details=f"Sensitive file access attempt: '{match.group()}'",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)


class PrivilegeEscalationPlugin(AegisPlugin):
    """Detects privilege escalation attempts."""
    
    name = "privilege_escalation"
    description = "Detects sudo, su, runas, chmod 777, and other privilege escalation patterns"
    
    PATTERNS = [
        re.compile(r"sudo\s+su\s*$", re.IGNORECASE | re.MULTILINE),
        re.compile(r"chmod\s+777", re.IGNORECASE),
        re.compile(r"chmod\s+\+s", re.IGNORECASE),  # SUID bit
        re.compile(r"chown\s+root", re.IGNORECASE),
        re.compile(r"runas\s+/user:\s*administrator", re.IGNORECASE),
        re.compile(r"net\s+user\s+.*\s+/add", re.IGNORECASE),
        re.compile(r"net\s+localgroup\s+administrators", re.IGNORECASE),
        re.compile(r"(useradd|usermod).*(-G|--groups)\s*(sudo|wheel|admin)", re.IGNORECASE),
    ]
    
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        for pattern in self.PATTERNS:
            match = pattern.search(content)
            if match:
                return ThreatResult(
                    is_threat=True,
                    confidence=0.88,
                    threat_type="privilege_escalation",
                    details=f"Privilege escalation attempt: '{match.group()}'",
                    source=self.name
                )
        return ThreatResult(is_threat=False, source=self.name)
