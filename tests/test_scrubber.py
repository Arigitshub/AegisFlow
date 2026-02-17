"""
AegisFlow Tests — Scrubber
"""

import pytest
from aegisflow.scrubber import KeyScrubber


class TestKeyScrubber:
    def setup_method(self):
        self.scrubber = KeyScrubber()
    
    def test_scrub_api_key(self):
        text = "My API key is sk_test_FAKE0KEY0DATA0"
        result = self.scrubber.scrub(text)
        assert "sk_test_" not in result
        assert "[REDACTED]" in result
    
    def test_scrub_email(self):
        text = "Contact me at user@example.com"
        result = self.scrubber.scrub(text)
        assert "user@example.com" not in result
        assert "[REDACTED]" in result
    
    def test_no_secrets_unchanged(self):
        text = "This is a completely normal message"
        result = self.scrubber.scrub(text)
        assert result == text
    
    def test_multiple_secrets(self):
        text = "Key1: sk_test_abc123xyz Key2: ghp_abcdefghij1234567890abcdefghijklmnop"
        result = self.scrubber.scrub(text)
        assert "sk_test_" not in result
        assert "ghp_" not in result
