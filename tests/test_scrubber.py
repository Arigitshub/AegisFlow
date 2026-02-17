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


class TestStructuredScrubbing:
    def setup_method(self):
        self.scrubber = KeyScrubber()
    
    def test_scrub_nested_dict(self):
        data = {
            "user": {
                "name": "John",
                "email": "john@example.com",
                "notes": "Call me at 212-555-1234"
            },
            "meta": {"version": "1.0"}
        }
        result = self.scrubber.scrub_structured(data)
        assert "[REDACTED]" in result["user"]["email"]
        assert "[REDACTED]" in result["user"]["notes"]
        assert result["meta"]["version"] == "1.0"
    
    def test_scrub_list_values(self):
        data = {
            "contacts": ["alice@test.com", "safe text", "bob@test.com"]
        }
        result = self.scrubber.scrub_structured(data)
        assert result["contacts"][1] == "safe text"
        assert "[REDACTED]" in result["contacts"][0]
    
    def test_preserves_non_string_values(self):
        data = {"count": 42, "active": True, "label": "safe"}
        result = self.scrubber.scrub_structured(data)
        assert result["count"] == 42
        assert result["active"] is True


class TestEntityReport:
    def setup_method(self):
        self.scrubber = KeyScrubber()

    def test_reports_entities(self):
        text = "Email me at admin@aegis.dev with SSN 123-45-6789"
        entities = self.scrubber.get_entity_report(text)
        assert len(entities) >= 2
        types = {e["type"] for e in entities}
        assert "email" in types
        assert "ssn" in types
    
    def test_reports_empty_for_clean(self):
        entities = self.scrubber.get_entity_report("Hello world!")
        assert len(entities) == 0
