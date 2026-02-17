"""
AegisFlow Core (v3.0)
The SecurityLiaison — central orchestrator for all security checks.
"""

import logging
import enum
import time
import asyncio
from typing import Callable, Any, Dict, Optional, List

from .config import AegisConfig, load_config
from .plugins import PluginRegistry, ThreatResult
from .rails import RailChain, RailResult, builtin_injection_rail, builtin_secret_scrub_rail
from .filesystem import ProtectedZones
from .scrubber import KeyScrubber
from .sentinel import Sentinel, ThreatLevel


class AuditLogger:
    """Deprecated in v3.0 — kept for backward compatibility. Use Sentinel instead."""
    pass


class SecurityLiaison:
    """
    The Governance Layer (v3.0).
    Monitors, Reports, and Mediates using the plugin system and rail chains.
    """
    
    def __init__(self, config: AegisConfig = None):
        # Load config
        self.config = config or load_config()
        
        # Initialize plugin registry
        self.plugins = PluginRegistry(
            disabled_plugins=self.config.disabled_plugins
        )
        
        # Sentinel state engine
        self.sentinel = Sentinel(
            logs_dir=self.config.sentinel.logs_dir,
            streak_threshold=self.config.sentinel.streak_threshold
        )
        
        # File system guard
        protected = self.config.protected_paths if self.config.protected_paths else None
        self.fs_guard = ProtectedZones(protected_paths=protected)
        
        # Key scrubber
        self.scrubber = KeyScrubber()
        
        # Rail chains (users can add custom rails)
        self.input_rails = RailChain(name="input")
        self.output_rails = RailChain(name="output")
        
        # Add built-in rails
        self.input_rails.add(builtin_injection_rail)
        self.output_rails.add(builtin_secret_scrub_rail)
        
        # Legacy scanner (kept for backward compat)
        try:
            from .scanners import BehavioralScanner
            self.scanner = BehavioralScanner()
        except ImportError:
            self.scanner = None

    def assess_risk(self, action_type: str, context: Dict[str, Any]) -> ThreatLevel:
        """
        Determines the threat level using the plugin system.
        Falls back to legacy scanner if no plugins detect threats.
        """
        content = context.get("content", str(context))
        plugin_context = {**context, "action_type": action_type}
        
        # 1. Plugin-based detection (primary)
        threat = self.plugins.get_highest_threat(content, plugin_context)
        if threat and threat.confidence >= 0.9:
            return ThreatLevel.HIGH
        elif threat and threat.confidence >= 0.7:
            return ThreatLevel.MEDIUM
        
        # 2. File system check
        if action_type == "file_op":
            path = context.get("path")
            if path and not self.fs_guard.is_safe(path):
                return ThreatLevel.HIGH
        
        # 3. Legacy scanner fallback
        if self.scanner:
            if self.scanner.scan_behavior(action_type, context):
                return ThreatLevel.HIGH
            if self.scanner.scan_text(content):
                return ThreatLevel.MEDIUM
        
        return ThreatLevel.LOW

    def mediate(self, action_type: str, context: Dict[str, Any], 
                execute_callback: Callable[[], Any]) -> Any:
        """
        The core Verification Protocol (v3.0).
        Now runs input/output rails around the action.
        """
        content = context.get("content", str(context))
        
        # ── Input Rails ──
        input_result = self.input_rails.run(content, context)
        if not input_result.passed:
            self.sentinel.log_event(
                ThreatLevel.HIGH.value, action_type, 
                f"Input rail blocked: {input_result.reason}", "RAIL_BLOCKED"
            )
            raise PermissionError(
                f"Blocked by input rail [{input_result.rail_name}]: {input_result.reason}"
            )
        
        # Update content if rails modified it
        if input_result.modified_content is not None:
            context = {**context, "content": input_result.modified_content}
        
        # ── Risk Assessment ──
        threat_level = self.assess_risk(action_type, context)
        details = str(context)

        # Sentinel escalation check
        if threat_level == ThreatLevel.MEDIUM and self.sentinel.check_escalation():
            print(f"[AegisFlow] ⚠ Escalating due to risk streak.")
            threat_level = ThreatLevel.HIGH

        # ── Mediation by threat level ──
        if threat_level == ThreatLevel.LOW:
            self.sentinel.log_event(threat_level.value, action_type, details, "EXECUTED")
            result = execute_callback()
            
        elif threat_level == ThreatLevel.MEDIUM:
            print(f"[AegisFlow] ⚠ Potential risk in {action_type}.")
            self.sentinel.log_event(threat_level.value, action_type, details, "WARNED_PROCEED")
            
            if self.config.strict_mode:
                print(f"[AegisFlow] Strict mode: treating MEDIUM as HIGH.")
                return self._prompt_user(action_type, details, context, execute_callback)
            
            result = execute_callback()
            
        elif threat_level == ThreatLevel.HIGH:
            result = self._prompt_user(action_type, details, context, execute_callback)
        else:
            result = execute_callback()
        
        # ── Output Rails ──
        if isinstance(result, str):
            output_result = self.output_rails.run(result, context)
            if not output_result.passed:
                self.sentinel.log_event(
                    ThreatLevel.HIGH.value, action_type,
                    f"Output rail blocked: {output_result.reason}", "OUTPUT_BLOCKED"
                )
                return f"[AegisFlow] Response blocked: {output_result.reason}"
            if output_result.modified_content is not None:
                result = output_result.modified_content
        
        return result
    
    def _prompt_user(self, action_type: str, details: str, 
                     context: Dict[str, Any], execute_callback: Callable) -> Any:
        """Handles HIGH risk prompting with reasoning string requirement."""
        print(f"\n[AegisFlow Alert] 🚨 Suspicious behavior: {action_type}")
        print(f"Details: {details[:200]}...")
        print("Provide reasoning to proceed (or 'NO' to abort): ", end="")
        
        reasoning = input().strip()
        
        if reasoning.lower() not in ['no', 'n', 'abort'] and len(reasoning) > 3:
            self.sentinel.log_event(
                ThreatLevel.HIGH.value, action_type, details, 
                "USER_OVERRIDE", reasoning=reasoning
            )
            return execute_callback()
        else:
            print("[AegisFlow] ✋ Action aborted.")
            self.sentinel.log_event(
                ThreatLevel.HIGH.value, action_type, details, "USER_ABORTED"
            )
            raise PermissionError(f"Action blocked by user: {action_type}")

    async def async_mediate(self, action_type: str, context: Dict[str, Any],
                            execute_callback: Callable) -> Any:
        """
        Async version of mediate() for non-blocking workflows.
        The execute_callback can be either sync or async.
        """
        content = context.get("content", str(context))
        
        # Input rails (sync — they're fast)
        input_result = self.input_rails.run(content, context)
        if not input_result.passed:
            self.sentinel.log_event(
                ThreatLevel.HIGH.value, action_type,
                f"Input rail blocked: {input_result.reason}", "RAIL_BLOCKED"
            )
            raise PermissionError(
                f"Blocked by input rail [{input_result.rail_name}]: {input_result.reason}"
            )
        
        if input_result.modified_content is not None:
            context = {**context, "content": input_result.modified_content}
        
        # Risk assessment
        threat_level = self.assess_risk(action_type, context)
        
        if threat_level == ThreatLevel.HIGH:
            raise PermissionError(
                f"HIGH risk detected in async mode: {action_type}. "
                "Use sync mediate() for interactive approval."
            )
        
        self.sentinel.log_event(threat_level.value, action_type, str(context), "ASYNC_EXECUTED")
        
        # Execute (support both sync and async callbacks)
        if asyncio.iscoroutinefunction(execute_callback):
            result = await execute_callback()
        else:
            result = execute_callback()
        
        # Output rails
        if isinstance(result, str):
            output_result = self.output_rails.run(result, context)
            if output_result.modified_content is not None:
                result = output_result.modified_content
        
        return result

    def wrap_function(self, action_name: str, func: Callable, 
                      context_extractor: Callable[[Any], Dict]) -> Callable:
        """Decorator-like wrapper for arbitrary functions."""
        def wrapper(*args, **kwargs):
            context = context_extractor(*args, **kwargs)
            return self.mediate(action_name, context, lambda: func(*args, **kwargs))
        return wrapper
