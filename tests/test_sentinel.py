"""
AegisFlow Tests — Sentinel State Engine
"""

import json
import pytest
from pathlib import Path
from aegisflow.sentinel import Sentinel, ThreatLevel


class TestSentinel:
    def test_log_event_creates_file(self, sentinel, tmp_dir):
        sentinel.log_event("Low", "test_action", "test details", "EXECUTED")
        log_file = Path(tmp_dir) / "aegis_audit.json"
        assert log_file.exists()
    
    def test_log_event_content(self, sentinel, tmp_dir):
        sentinel.log_event("High", "dangerous_action", "rm -rf /", "USER_ABORTED")
        log_file = Path(tmp_dir) / "aegis_audit.json"
        with open(log_file, "r") as f:
            event = json.loads(f.readline())
        assert event["threat_level"] == "High"
        assert event["action_type"] == "dangerous_action"
        assert event["session_id"] == "test-session"
    
    def test_medium_streak_escalation(self, sentinel):
        for _ in range(3):
            sentinel.log_event("Medium", "risky", "details", "WARNED_PROCEED")
        assert sentinel.check_escalation()
    
    def test_low_breaks_streak(self, sentinel):
        sentinel.log_event("Medium", "risky", "details", "WARNED_PROCEED")
        sentinel.log_event("Medium", "risky", "details", "WARNED_PROCEED")
        sentinel.log_event("Low", "safe", "details", "EXECUTED")
        assert not sentinel.check_escalation()
    
    def test_risk_score_increases_medium(self, sentinel):
        initial = sentinel.risk_score
        sentinel.log_event("Medium", "test", "details", "WARNED")
        assert sentinel.risk_score == initial + 10
    
    def test_risk_score_increases_high(self, sentinel):
        initial = sentinel.risk_score
        sentinel.log_event("High", "test", "details", "BLOCKED")
        assert sentinel.risk_score == initial + 25
    
    def test_risk_score_decreases_low(self, sentinel):
        sentinel.risk_score = 50
        sentinel.log_event("Low", "safe", "details", "EXECUTED")
        assert sentinel.risk_score == 48
    
    def test_risk_score_capped_at_100(self, sentinel):
        sentinel.risk_score = 95
        sentinel.log_event("High", "test", "details", "BLOCKED")
        assert sentinel.risk_score == 100
    
    def test_risk_score_floor_at_0(self, sentinel):
        sentinel.risk_score = 1
        sentinel.log_event("Low", "test", "details", "EXECUTED")
        assert sentinel.risk_score == 0


class TestSentinelPersistence:
    def test_state_persists(self, tmp_dir):
        s1 = Sentinel(logs_dir=tmp_dir, session_id="s1")
        s1.log_event("High", "test", "details", "BLOCKED")
        s1.log_event("Medium", "test", "details", "WARNED")
        
        # Create a new sentinel from the same directory
        s2 = Sentinel(logs_dir=tmp_dir, session_id="s2")
        assert s2.risk_score == s1.risk_score
        assert s2.total_events == 2
    
    def test_state_file_created(self, tmp_dir):
        s = Sentinel(logs_dir=tmp_dir)
        s.log_event("Low", "test", "details", "OK")
        state_file = Path(tmp_dir) / "sentinel_state.json"
        assert state_file.exists()


class TestSentinelExport:
    def test_export_json(self, sentinel, tmp_dir):
        sentinel.log_event("Low", "test", "details", "OK")
        sentinel.log_event("High", "danger", "bad stuff", "BLOCKED")
        
        path = sentinel.export_logs(format="json")
        assert path.endswith(".json")
        with open(path, "r") as f:
            data = json.load(f)
        assert len(data) == 2
    
    def test_export_csv(self, sentinel, tmp_dir):
        sentinel.log_event("Low", "test", "details", "OK")
        path = sentinel.export_logs(format="csv")
        assert path.endswith(".csv")
    
    def test_export_html(self, sentinel, tmp_dir):
        sentinel.log_event("Medium", "test", "details", "WARNED")
        path = sentinel.export_logs(format="html")
        assert path.endswith(".html")
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        assert "AegisFlow Audit Report" in html


class TestRiskLabels:
    def test_normal(self):
        s = Sentinel.__new__(Sentinel)
        s.risk_score = 10
        assert "NORMAL" in s.get_risk_label()
    
    def test_elevated(self):
        s = Sentinel.__new__(Sentinel)
        s.risk_score = 30
        assert "ELEVATED" in s.get_risk_label()
    
    def test_high(self):
        s = Sentinel.__new__(Sentinel)
        s.risk_score = 60
        assert "HIGH" in s.get_risk_label()
    
    def test_critical(self):
        s = Sentinel.__new__(Sentinel)
        s.risk_score = 80
        assert "CRITICAL" in s.get_risk_label()
