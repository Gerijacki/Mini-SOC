import pytest
from unittest.mock import patch

from rules.brute_force import BruteForceRule
from models import AlertSeverity


@pytest.fixture
def rule():
    return BruteForceRule()


def _agg(buckets: list) -> dict:
    return {"aggregations": {"by_ip": {"buckets": buckets}}}


def _bucket(ip: str, count: int) -> dict:
    return {"key": ip, "doc_count": count,
            "first_seen": {"value_as_string": "2026-04-27T10:00:00.000Z"},
            "last_seen":  {"value_as_string": "2026-04-27T10:00:30.000Z"}}


class TestBruteForceRule:
    def test_triggers_above_threshold(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("185.220.101.45", 8)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 1
        assert alerts[0].source_ip == "185.220.101.45"
        assert alerts[0].event_count == 8
        assert alerts[0].rule_name == "BruteForceRule"

    def test_no_alert_below_threshold(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.2.3.4", 2)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_dedup_skips_existing_alert(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.2.3.4", 20)])), \
             patch("es_client.alert_exists", return_value=True):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_severity_medium_at_5(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.1.1.1", 5)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].severity == AlertSeverity.medium

    def test_severity_high_at_11(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.1.1.1", 11)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].severity == AlertSeverity.high

    def test_severity_critical_at_20(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.1.1.1", 20)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].severity == AlertSeverity.critical

    def test_multiple_ips_each_get_alert(self, rule, mock_es):
        buckets = [_bucket(f"1.1.1.{i}", 10) for i in range(3)]
        with patch("es_client.search", return_value=_agg(buckets)), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 3

    def test_details_contain_expected_fields(self, rule, mock_es):
        with patch("es_client.search", return_value=_agg([_bucket("1.2.3.4", 8)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        d = alerts[0].details
        assert all(k in d for k in ["failed_attempts", "window_seconds", "threshold", "first_seen", "last_seen"])
