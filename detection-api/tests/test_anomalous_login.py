import pytest
from unittest.mock import patch

from rules.anomalous_login import AnomalousLoginRule
from models import AlertSeverity


@pytest.fixture
def rule():
    return AnomalousLoginRule()


def _candidates(ips_with_counts: list) -> dict:
    return {"aggregations": {"by_ip": {"buckets": [
        {"key": ip, "doc_count": c} for ip, c in ips_with_counts
    ]}}}


def _success(found: bool, username: str = "admin") -> dict:
    hits = [{"@timestamp": "2026-04-27T10:00:30.000Z", "username": username}] if found else []
    return {"hits": {"total": {"value": len(hits)},
                      "hits": [{"_source": h} for h in hits]}}


class TestAnomalousLoginRule:
    def test_alerts_when_success_follows_failures(self, rule, mock_es):
        with patch("es_client.search", side_effect=[_candidates([("1.2.3.4", 7)]), _success(True)]), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "1.2.3.4"
        assert alerts[0].severity == AlertSeverity.high
        assert alerts[0].details["failed_before_success"] == 7
        assert alerts[0].details["successful_user"] == "admin"

    def test_no_alert_when_no_success(self, rule, mock_es):
        with patch("es_client.search", side_effect=[_candidates([("1.2.3.4", 7)]), _success(False)]), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_no_alert_when_no_candidates(self, rule, mock_es):
        with patch("es_client.search", return_value=_candidates([])):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_dedup_skips_existing(self, rule, mock_es):
        with patch("es_client.search", side_effect=[_candidates([("1.2.3.4", 5)]), _success(True)]), \
             patch("es_client.alert_exists", return_value=True):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_details_contain_window(self, rule, mock_es):
        with patch("es_client.search", side_effect=[_candidates([("1.2.3.4", 4)]), _success(True)]), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert "window_minutes" in alerts[0].details

    def test_candidate_below_failure_threshold_ignored(self, rule, mock_es):
        with patch("es_client.search", return_value=_candidates([("1.2.3.4", 2)])):
            alerts = rule.detect(mock_es)
        assert alerts == []
