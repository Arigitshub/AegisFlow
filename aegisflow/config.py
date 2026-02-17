"""
AegisFlow Configuration System (v3.0)
Pydantic-based typed configuration with .aegis.json / .aegis.yaml support.
"""

import os
import json
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    from pydantic import BaseModel, Field
except ImportError:
    # Fallback for environments without pydantic
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return self.__dict__
    
    def Field(default=None, description=None):
        return default


class PluginConfig(BaseModel):
    """Configuration for individual plugins."""
    name: str = Field(default="", description="Plugin name")
    enabled: bool = Field(default=True, description="Whether this plugin is active")
    settings: Dict[str, Any] = Field(default_factory=dict, description="Plugin-specific settings")


class DetectorConfig(BaseModel):
    """Configuration for the detection engine."""
    use_ml: bool = Field(default=False, description="Enable ML-based detection (requires transformers)")
    ml_model: str = Field(default="protectai/deberta-v3-base-prompt-injection-v2", description="HuggingFace model for injection detection")
    ml_confidence_threshold: float = Field(default=0.85, description="Minimum confidence to flag as threat")
    fallback_to_regex: bool = Field(default=True, description="Fall back to regex if ML unavailable")


class SentinelConfig(BaseModel):
    """Configuration for the Sentinel state engine."""
    logs_dir: str = Field(default="~/.aegis/logs", description="Directory for audit logs")
    streak_threshold: int = Field(default=3, description="Medium risk streak count before escalation")
    persist_state: bool = Field(default=True, description="Persist reputation state to disk")
    webhook_url: Optional[str] = Field(default=None, description="HTTP webhook for HIGH risk alerts")
    session_id: Optional[str] = Field(default=None, description="Session ID for multi-agent tracking")


class SandwichConfig(BaseModel):
    """Configuration for the AegisSandwich process wrapper."""
    isolation_level: int = Field(default=0, description="0=none, 1=filter env, 2=read-only fs, 3=docker")
    auto_kill_timeout: Optional[int] = Field(default=None, description="Auto-kill after N seconds (None=disabled)")
    track_cost: bool = Field(default=False, description="Estimate token cost for LLM sessions")


class AegisConfig(BaseModel):
    """
    Root configuration for AegisFlow.
    Loaded from .aegis.json or .aegis.yaml in CWD or home directory.
    """
    # Core settings
    strict_mode: bool = Field(default=False, description="Strict mode blocks MEDIUM risks too")
    protected_paths: List[str] = Field(default_factory=list, description="Additional paths to protect")
    
    # Sub-configs
    detector: DetectorConfig = Field(default_factory=DetectorConfig)
    sentinel: SentinelConfig = Field(default_factory=SentinelConfig)
    sandwich: SandwichConfig = Field(default_factory=SandwichConfig)
    
    # Plugin overrides
    plugins: List[PluginConfig] = Field(default_factory=list, description="Plugin configurations")
    disabled_plugins: List[str] = Field(default_factory=list, description="Plugin names to disable")


def load_config() -> AegisConfig:
    """
    Loads AegisFlow configuration from .aegis.json or .aegis.yaml.
    Searches CWD first, then home directory. Returns defaults if no config found.
    """
    config_candidates = [
        (Path.cwd() / ".aegis.json", "json"),
        (Path.cwd() / ".aegis.yaml", "yaml"),
        (Path.cwd() / ".aegis.yml", "yaml"),
        (Path.home() / ".aegis.json", "json"),
        (Path.home() / ".aegis.yaml", "yaml"),
        (Path.home() / ".aegis.yml", "yaml"),
    ]
    
    for path, fmt in config_candidates:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    if fmt == "json":
                        data = json.load(f)
                    elif fmt == "yaml":
                        try:
                            import yaml
                            data = yaml.safe_load(f)
                        except ImportError:
                            print(f"[AegisFlow] Warning: PyYAML not installed, skipping {path}")
                            continue
                    else:
                        continue
                
                print(f"[AegisFlow] Loaded config from {path}")
                return AegisConfig(**data)
                
            except Exception as e:
                print(f"[AegisFlow] Warning: Failed to load {path}: {e}")
                continue
    
    return AegisConfig()
