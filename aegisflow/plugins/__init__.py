"""
AegisFlow Plugin System (v3.0)
Extensible plugin architecture for threat detection.
"""

import importlib
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ThreatResult:
    """Result from a plugin scan."""
    is_threat: bool
    confidence: float = 1.0  # 0.0 to 1.0
    threat_type: str = ""    # e.g., "recursive_delete", "injection", "exfiltration"
    details: str = ""        # Human-readable explanation
    source: str = ""         # Which plugin detected it


class AegisPlugin(ABC):
    """
    Base class for all AegisFlow security plugins.
    
    To create a custom plugin:
        1. Subclass AegisPlugin
        2. Set `name` and `description` class attributes
        3. Implement `scan(content, context) -> ThreatResult`
        4. Place in aegisflow/plugins/ or register via config
    
    Example:
        class MyPlugin(AegisPlugin):
            name = "my_plugin"
            description = "Detects custom threats"
            
            def scan(self, content: str, context: dict) -> ThreatResult:
                if "dangerous_pattern" in content:
                    return ThreatResult(
                        is_threat=True,
                        confidence=0.95,
                        threat_type="custom_threat",
                        details="Found dangerous_pattern in content",
                        source=self.name
                    )
                return ThreatResult(is_threat=False, source=self.name)
    """
    
    name: str = "unnamed_plugin"
    description: str = "No description"
    enabled: bool = True
    
    @abstractmethod
    def scan(self, content: str, context: Dict[str, Any]) -> ThreatResult:
        """
        Scan content for threats.
        
        Args:
            content: The text content to scan
            context: Additional context (action_type, path, source, etc.)
        
        Returns:
            ThreatResult with detection details
        """
        pass


class PluginRegistry:
    """
    Discovers, loads, and manages AegisFlow plugins.
    Auto-discovers plugins from the aegisflow.plugins package.
    """
    
    def __init__(self, disabled_plugins: List[str] = None):
        self._plugins: List[AegisPlugin] = []
        self._disabled: set = set(disabled_plugins or [])
        self._discover_builtin_plugins()
    
    def _discover_builtin_plugins(self):
        """Auto-discover all plugin classes in aegisflow.plugins submodules."""
        try:
            package = importlib.import_module("aegisflow.plugins")
            for importer, modname, ispkg in pkgutil.iter_modules(package.__path__):
                if modname.startswith("_"):
                    continue
                try:
                    module = importlib.import_module(f"aegisflow.plugins.{modname}")
                    # Find all AegisPlugin subclasses in the module
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) 
                            and issubclass(attr, AegisPlugin) 
                            and attr is not AegisPlugin):
                            plugin_instance = attr()
                            if plugin_instance.name not in self._disabled:
                                self._plugins.append(plugin_instance)
                except Exception as e:
                    print(f"[AegisFlow] Warning: Failed to load plugin module {modname}: {e}")
        except Exception as e:
            print(f"[AegisFlow] Warning: Plugin discovery failed: {e}")
    
    def register(self, plugin: AegisPlugin):
        """Manually register a plugin instance."""
        if plugin.name not in self._disabled:
            self._plugins.append(plugin)
    
    def scan_all(self, content: str, context: Dict[str, Any]) -> List[ThreatResult]:
        """
        Run all enabled plugins against the content.
        Returns list of ThreatResults (only threats, not clean results).
        """
        results = []
        for plugin in self._plugins:
            if not plugin.enabled:
                continue
            try:
                result = plugin.scan(content, context)
                if result.is_threat:
                    results.append(result)
            except Exception as e:
                print(f"[AegisFlow] Warning: Plugin {plugin.name} error: {e}")
        return results
    
    def get_highest_threat(self, content: str, context: Dict[str, Any]) -> Optional[ThreatResult]:
        """
        Run all plugins and return the highest-confidence threat, or None.
        """
        results = self.scan_all(content, context)
        if not results:
            return None
        return max(results, key=lambda r: r.confidence)
    
    @property
    def plugins(self) -> List[AegisPlugin]:
        return list(self._plugins)
    
    def __len__(self) -> int:
        return len(self._plugins)
