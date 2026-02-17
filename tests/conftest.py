"""
AegisFlow Test Suite — conftest.py
Shared fixtures for all tests.
"""

import os
import json
import shutil
import tempfile
import pytest
from pathlib import Path

from aegisflow.config import AegisConfig
from aegisflow.core import SecurityLiaison
from aegisflow.sentinel import Sentinel, ThreatLevel
from aegisflow.plugins import PluginRegistry
from aegisflow.rails import RailChain


@pytest.fixture
def tmp_dir():
    """Temporary directory that is cleaned up after each test."""
    d = tempfile.mkdtemp(prefix="aegis_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def sentinel(tmp_dir):
    """Sentinel with logs in a temp directory."""
    return Sentinel(logs_dir=tmp_dir, session_id="test-session")


@pytest.fixture
def config(tmp_dir):
    """Basic AegisConfig with temp log directory."""
    return AegisConfig(
        sentinel={"logs_dir": tmp_dir, "streak_threshold": 3}
    )


@pytest.fixture
def liaison(config):
    """SecurityLiaison with test config."""
    return SecurityLiaison(config=config)


@pytest.fixture
def plugin_registry():
    """Fresh plugin registry with built-in plugins."""
    return PluginRegistry()
