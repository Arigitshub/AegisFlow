"""
AegisFlow v3.0 — The Universal Security Layer for AI Agents.

Usage:
    from aegisflow import SecurityLiaison, AegisConfig
    from aegisflow.rails import input_rail, output_rail, RailResult
    from aegisflow.plugins import AegisPlugin, ThreatResult
"""

__version__ = "3.0.0"

# Core
from .core import SecurityLiaison

# Config
from .config import AegisConfig, load_config

# Rail System
from .rails import (
    input_rail, 
    output_rail, 
    RailResult, 
    RailChain,
)

# Plugin System
from .plugins import (
    AegisPlugin,
    ThreatResult,
    PluginRegistry,
)

# Components
from .scanners import BehavioralScanner
from .filesystem import ProtectedZones
from .scrubber import KeyScrubber
from .sentinel import Sentinel, ThreatLevel

# Optional: LLM Integration
try:
    from .llm import SafeGenerator
except ImportError:
    SafeGenerator = None

# Optional: Process Wrapper
try:
    from .sandwich import AegisSandwich
except ImportError:
    AegisSandwich = None


__all__ = [
    # Core
    "SecurityLiaison",
    "AegisConfig",
    "load_config",
    # Rails
    "input_rail",
    "output_rail",
    "RailResult",
    "RailChain",
    # Plugins
    "AegisPlugin",
    "ThreatResult",
    "PluginRegistry",
    # Components
    "BehavioralScanner",
    "ProtectedZones",
    "KeyScrubber",
    "Sentinel",
    "ThreatLevel",
    # Optional
    "SafeGenerator",
    "AegisSandwich",
]
