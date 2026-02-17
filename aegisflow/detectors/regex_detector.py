"""
AegisFlow Regex Detector (v3.0)
YARA-style rule-based detection using compiled regex patterns.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Pattern

from aegisflow.detectors import DetectionResult

logger = logging.getLogger("aegisflow.detectors.regex")


# ── Rule definition ─────────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    """A single regex-based detection rule (YARA-style)."""
    name: str
    description: str
    pattern: str
    threat_type: str  # injection, exfiltration, destructive, escalation, negation
    severity: float   # 0.0–1.0 confidence when matched
    flags: int = re.IGNORECASE

    _compiled: Optional[Pattern] = None

    def compile(self) -> Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, self.flags)
        return self._compiled


# ── Built-in rule library ───────────────────────────────────────────────────

BUILTIN_RULES: List[DetectionRule] = [
    # ── Prompt Injection ──
    DetectionRule(
        name="injection_ignore_instructions",
        description="Classic 'ignore all previous instructions' injection",
        pattern=r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|guidelines?|directions?)",
        threat_type="injection",
        severity=0.95,
    ),
    DetectionRule(
        name="injection_new_persona",
        description="Persona hijacking / DAN mode",
        pattern=r"(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you'?re))\s+(DAN|an?\s+unrestricted|evil)",
        threat_type="injection",
        severity=0.90,
    ),
    DetectionRule(
        name="injection_jailbreak",
        description="Common jailbreak markers",
        pattern=r"(jailbreak|jail\s*broken|do\s+anything\s+now|devmode|developer\s+mode\s+(enabled|on|activated))",
        threat_type="injection",
        severity=0.90,
    ),
    DetectionRule(
        name="injection_system_override",
        description="System prompt override attempts",
        pattern=r"(system\s*:?\s*override|new\s+system\s+prompt|overwrite\s+(system|instructions)|\\n\s*system\s*:)",
        threat_type="injection",
        severity=0.92,
    ),
    DetectionRule(
        name="injection_role_play",
        description="Role-play to bypass filters",
        pattern=r"(roleplay|role\s?play)\s+(as|where|scenario)\s+.*(no\s+rules?|no\s+restrictions?|unrestricted|anything\s+goes)",
        threat_type="injection",
        severity=0.85,
    ),
    DetectionRule(
        name="injection_encoding_bypass",
        description="Base64/hex/ROT13 encoding bypass attempts",
        pattern=r"(base64|rot13|hex|decode|encode)\s+.{0,30}(bypass|ignore|override|instructions)",
        threat_type="injection",
        severity=0.80,
    ),
    DetectionRule(
        name="injection_between_tags",
        description="Hidden instruction injection between XML/HTML tags",
        pattern=r"<\s*(system|instruction|hidden|secret|admin)\s*>.*?</\s*\1\s*>",
        threat_type="injection",
        severity=0.88,
        flags=re.IGNORECASE | re.DOTALL,
    ),
    DetectionRule(
        name="injection_multilingual_ignore",
        description="Multilingual injection: ignore instructions in various languages",
        pattern=r"(ignorez?\s+les?\s+(instructions?|consignes?|règles?)|ignorieren?\s+sie\s+(die\s+)?(anweisungen|regeln)|ignora\s+(las?\s+)?(instrucciones|reglas)|前の指示を無視|以前の指示を無視|이전\s*지시를?\s*무시|忽略之前的指令|تجاهل\s+التعليمات)",
        threat_type="injection",
        severity=0.90,
        flags=re.IGNORECASE | re.UNICODE,
    ),

    # ── Rule Negation ──
    DetectionRule(
        name="negation_ignore_restrictions",
        description="Explicit requests to bypass restrictions",
        pattern=r"(ignore|bypass|disable|circumvent|override|skip)\s+(any\s+)?(restrictions?|limitations?|safety|guardrails?|filters?|security)",
        threat_type="negation",
        severity=0.88,
    ),
    DetectionRule(
        name="negation_pretend",
        description="Pretend there are no rules",
        pattern=r"pretend\s+(there\s+are\s+no|you\s+have\s+no|you\s+don'?t\s+have)\s+(rules?|restrictions?|limitations?|guidelines?|boundaries?)",
        threat_type="negation",
        severity=0.85,
    ),

    # ── Destructive Commands ──
    DetectionRule(
        name="destructive_rm_rf",
        description="Recursive file deletion (Unix)",
        pattern=r"rm\s+(-[a-z]*r[a-z]*\s+|-[a-z]*\s+)*(-[a-z]*f[a-z]*\s+)?(/|~|\.\.|home|root|var|etc|usr)",
        threat_type="destructive",
        severity=0.95,
    ),
    DetectionRule(
        name="destructive_rmdir",
        description="Recursive directory deletion (Windows)",
        pattern=r"(rmdir|rd)\s+/s(\s+/q)?\s+",
        threat_type="destructive",
        severity=0.95,
    ),
    DetectionRule(
        name="destructive_shutil",
        description="Python shutil.rmtree calls",
        pattern=r"shutil\.rmtree\s*\(",
        threat_type="destructive",
        severity=0.92,
    ),
    DetectionRule(
        name="destructive_powershell",
        description="PowerShell recursive removal",
        pattern=r"Remove-Item\s+.*-Recurse",
        threat_type="destructive",
        severity=0.92,
    ),
    DetectionRule(
        name="destructive_format",
        description="Disk format commands",
        pattern=r"(mkfs\.|format\s+[a-zA-Z]:.*(/q|/fs)|dd\s+if=.*of=/dev/)",
        threat_type="destructive",
        severity=0.98,
    ),

    # ── Data Exfiltration ──
    DetectionRule(
        name="exfiltration_post_with_key",
        description="HTTP POST with API key or credentials",
        pattern=r"(requests\.post|http\.post|fetch|curl\s+-X\s+POST|wget\s+--post)\s*\(?\s*['\"]?https?://[^'\"\s]+.*(key|token|secret|password|credential)",
        threat_type="exfiltration",
        severity=0.90,
    ),
    DetectionRule(
        name="exfiltration_env_leak",
        description="Environment variable exfiltration",
        pattern=r"(os\.environ|process\.env|ENV\[)[^]]*\]\s*.*\.(post|send|upload|transmit)",
        threat_type="exfiltration",
        severity=0.88,
    ),
    DetectionRule(
        name="exfiltration_sensitive_files",
        description="Accessing sensitive system files with network activity",
        pattern=r"(open|read|cat|type)\s*\(?\s*['\"]?(/etc/passwd|/etc/shadow|~/.ssh/|\.env|\.aws/credentials)",
        threat_type="exfiltration",
        severity=0.85,
    ),

    # ── Privilege Escalation ──
    DetectionRule(
        name="escalation_sudo_su",
        description="Privilege escalation via sudo/su",
        pattern=r"(sudo\s+su\b|sudo\s+-i|sudo\s+bash|sudo\s+sh\b)",
        threat_type="escalation",
        severity=0.85,
    ),
    DetectionRule(
        name="escalation_chmod",
        description="Dangerous permission changes",
        pattern=r"chmod\s+([0-7]*7[0-7]*\s+|777\s+|\+s\s+|u\+s\s+)",
        threat_type="escalation",
        severity=0.85,
    ),
    DetectionRule(
        name="escalation_windows_runas",
        description="Windows privilege escalation",
        pattern=r"(runas\s+/user:.*admin|Start-Process.*-Verb\s+RunAs|net\s+localgroup\s+administrators)",
        threat_type="escalation",
        severity=0.85,
    ),
    DetectionRule(
        name="escalation_suid",
        description="SUID/capability exploits",
        pattern=r"(setuid|setgid|cap_setuid|/proc/self/exe)",
        threat_type="escalation",
        severity=0.80,
    ),

    # ── Sensitive File Access ──
    DetectionRule(
        name="sensitive_ssh_keys",
        description="Accessing SSH private keys",
        pattern=r"(~|/home/\w+)/\.ssh/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)",
        threat_type="sensitive_access",
        severity=0.80,
    ),
    DetectionRule(
        name="sensitive_credential_files",
        description="Accessing credential stores",
        pattern=r"(/etc/shadow|\.aws/credentials|\.netrc|\.pgpass|\.docker/config\.json)",
        threat_type="sensitive_access",
        severity=0.85,
    ),
]


# ── Regex Detector Class ────────────────────────────────────────────────────

class RegexDetector:
    """
    Rule-based threat detection using compiled regex patterns.

    Supports:
        - Built-in rules (see BUILTIN_RULES above)
        - Custom rules added at runtime
        - Category-level detection (injection, exfiltration, etc.)
    """

    def __init__(self, rules: Optional[List[DetectionRule]] = None):
        self.rules = list(rules or BUILTIN_RULES)
        # Pre-compile all patterns
        for rule in self.rules:
            rule.compile()

    def detect(self, content: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Scan content against all rules. Returns the highest-severity match.
        """
        matches: List[tuple] = []  # (rule, match_object)

        for rule in self.rules:
            compiled = rule.compile()
            match = compiled.search(content)
            if match:
                matches.append((rule, match))

        if not matches:
            return DetectionResult(
                is_threat=False,
                confidence=0.0,
                method="regex",
                details="No patterns matched",
            )

        # Return highest severity match
        best_rule, best_match = max(matches, key=lambda x: x[0].severity)

        return DetectionResult(
            is_threat=True,
            confidence=best_rule.severity,
            method="regex",
            threat_type=best_rule.threat_type,
            details=f"Rule '{best_rule.name}': {best_rule.description} "
                    f"(matched: '{best_match.group()[:80]}')",
            raw_scores={r.name: r.severity for r, _ in matches},
        )

    def detect_all(self, content: str, context: Optional[Dict[str, Any]] = None) -> List[DetectionResult]:
        """
        Return ALL matching rules (not just the best one).
        Useful for comprehensive threat reports.
        """
        results = []
        for rule in self.rules:
            compiled = rule.compile()
            match = compiled.search(content)
            if match:
                results.append(DetectionResult(
                    is_threat=True,
                    confidence=rule.severity,
                    method="regex",
                    threat_type=rule.threat_type,
                    details=f"Rule '{rule.name}': {rule.description}",
                ))
        return results

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a custom detection rule at runtime."""
        rule.compile()
        self.rules.append(rule)
        logger.info("Added custom rule: %s", rule.name)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def rules_by_type(self, threat_type: str) -> List[DetectionRule]:
        """Get all rules for a specific threat type."""
        return [r for r in self.rules if r.threat_type == threat_type]
