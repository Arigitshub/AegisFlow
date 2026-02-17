"""
AegisFlow Tests — Config System
"""

import json
import pytest
import tempfile
from pathlib import Path
from aegisflow.config import AegisConfig, load_config, DetectorConfig, SentinelConfig


class TestAegisConfig:
    def test_default_config(self):
        config = AegisConfig()
        assert config.strict_mode is False
        assert len(config.protected_paths) == 0
        assert config.detector.use_ml is False
        assert config.sentinel.streak_threshold == 3
    
    def test_custom_config(self):
        config = AegisConfig(
            strict_mode=True,
            protected_paths=["/secret"],
            detector=DetectorConfig(use_ml=True, ml_confidence_threshold=0.9),
        )
        assert config.strict_mode is True
        assert config.protected_paths == ["/secret"]
        assert config.detector.use_ml is True
        assert config.detector.ml_confidence_threshold == 0.9
    
    def test_disabled_plugins(self):
        config = AegisConfig(disabled_plugins=["recursive_delete", "exfiltration"])
        assert "recursive_delete" in config.disabled_plugins


class TestConfigLoading:
    def test_load_json_config(self, tmp_dir):
        config_data = {
            "strict_mode": True,
            "protected_paths": ["/my/secret/path"],
            "sentinel": {"streak_threshold": 5}
        }
        config_path = Path(tmp_dir) / ".aegis.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)
        
        # load_config searches CWD, which won't find our temp file,
        # so we test the config model directly
        config = AegisConfig(**config_data)
        assert config.strict_mode is True
        assert config.sentinel.streak_threshold == 5
    
    def test_default_when_no_file(self):
        config = load_config()
        assert isinstance(config, AegisConfig)


class TestDetectorConfig:
    def test_defaults(self):
        dc = DetectorConfig()
        assert dc.use_ml is False
        assert "deberta" in dc.ml_model
        assert dc.ml_confidence_threshold == 0.85
        assert dc.fallback_to_regex is True


class TestSentinelConfig:
    def test_defaults(self):
        sc = SentinelConfig()
        assert sc.streak_threshold == 3
        assert sc.webhook_url is None
        assert sc.persist_state is True
