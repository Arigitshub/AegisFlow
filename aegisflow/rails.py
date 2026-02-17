"""
AegisFlow Rail System (v3.0)
Decorator-based input/output guardrails inspired by OpenAI Agents SDK.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import functools


@dataclass
class RailResult:
    """Result from a rail check."""
    passed: bool
    modified_content: Optional[str] = None  # If set, replaces the original content
    reason: str = ""
    rail_name: str = ""


# Type alias for rail functions
RailFunction = Callable[[str, Dict[str, Any]], RailResult]


class RailChain:
    """
    Composes multiple rails into a sequential chain.
    Each rail receives the (possibly modified) content from the previous rail.
    If any rail fails, the chain stops and returns the failure.
    """
    
    def __init__(self, name: str = "chain"):
        self.name = name
        self._rails: List[RailFunction] = []
    
    def add(self, rail: RailFunction):
        """Add a rail function to the chain."""
        self._rails.append(rail)
        return self
    
    def run(self, content: str, context: Dict[str, Any] = None) -> RailResult:
        """
        Execute all rails in sequence.
        Returns the first failure, or the final success (with any modifications).
        """
        context = context or {}
        current_content = content
        
        for rail in self._rails:
            try:
                result = rail(current_content, context)
                if not result.passed:
                    return result
                if result.modified_content is not None:
                    current_content = result.modified_content
            except Exception as e:
                return RailResult(
                    passed=False,
                    reason=f"Rail error: {e}",
                    rail_name=getattr(rail, '__name__', 'unknown')
                )
        
        # All rails passed
        if current_content != content:
            return RailResult(passed=True, modified_content=current_content)
        return RailResult(passed=True)
    
    def __len__(self):
        return len(self._rails)


def input_rail(func: Callable = None, *, name: str = None):
    """
    Decorator to mark a function as an input rail.
    
    The decorated function should accept (content: str, context: dict) 
    and return a RailResult.
    
    Usage:
        @input_rail
        def block_injections(content: str, context: dict) -> RailResult:
            if "ignore all previous" in content.lower():
                return RailResult(passed=False, reason="Prompt injection")
            return RailResult(passed=True)
    
        # Or with a custom name:
        @input_rail(name="my_input_check")
        def my_check(content, context):
            ...
    """
    def decorator(fn):
        rail_name = name or fn.__name__
        
        @functools.wraps(fn)
        def wrapper(content: str, context: Dict[str, Any] = None) -> RailResult:
            context = context or {}
            result = fn(content, context)
            if not isinstance(result, RailResult):
                raise TypeError(f"Rail {rail_name} must return RailResult, got {type(result)}")
            result.rail_name = rail_name
            return result
        
        wrapper._is_rail = True
        wrapper._rail_type = "input"
        wrapper._rail_name = rail_name
        return wrapper
    
    if func is not None:
        return decorator(func)
    return decorator


def output_rail(func: Callable = None, *, name: str = None):
    """
    Decorator to mark a function as an output rail.
    
    Usage:
        @output_rail
        def scrub_output(content: str, context: dict) -> RailResult:
            cleaned = content.replace("SECRET", "[REDACTED]")
            return RailResult(passed=True, modified_content=cleaned)
    """
    def decorator(fn):
        rail_name = name or fn.__name__
        
        @functools.wraps(fn)
        def wrapper(content: str, context: Dict[str, Any] = None) -> RailResult:
            context = context or {}
            result = fn(content, context)
            if not isinstance(result, RailResult):
                raise TypeError(f"Rail {rail_name} must return RailResult, got {type(result)}")
            result.rail_name = rail_name
            return result
        
        wrapper._is_rail = True
        wrapper._rail_type = "output"
        wrapper._rail_name = rail_name
        return wrapper
    
    if func is not None:
        return decorator(func)
    return decorator


# ── Built-in Rails ──────────────────────────────────────────────────

@input_rail(name="builtin_injection_check")
def builtin_injection_rail(content: str, context: Dict[str, Any]) -> RailResult:
    """Built-in input rail that checks for common injection patterns."""
    import re
    patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"system\s+override",
        r"jailbreak",
        r"developer\s+mode",
        r"DAN\s+mode",
    ]
    for p in patterns:
        if re.search(p, content, re.IGNORECASE):
            return RailResult(passed=False, reason=f"Injection pattern detected: {p}")
    return RailResult(passed=True)


@output_rail(name="builtin_secret_scrub")
def builtin_secret_scrub_rail(content: str, context: Dict[str, Any]) -> RailResult:
    """Built-in output rail that scrubs API keys from responses."""
    import re
    scrubbed = content
    patterns = [
        (r"sk_live_[0-9a-zA-Z]{24}", "[REDACTED_KEY]"),
        (r"sk[_-][\w-]{20,}", "[REDACTED_KEY]"),
        (r"ghp_[a-zA-Z0-9]{36}", "[REDACTED_TOKEN]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    ]
    modified = False
    for pattern, replacement in patterns:
        new_text = re.sub(pattern, replacement, scrubbed)
        if new_text != scrubbed:
            modified = True
            scrubbed = new_text
    
    if modified:
        return RailResult(passed=True, modified_content=scrubbed, reason="Secrets scrubbed from output")
    return RailResult(passed=True)
