import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


@pytest.fixture
def mock_es():
    m = MagicMock()
    m.cluster.health.return_value = {"status": "yellow"}
    m.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
    return m


@pytest.fixture
def client(mock_es):
    with patch("responder.get_es_client", return_value=mock_es):
        import responder
        responder.blocked_ips.clear()
        with TestClient(responder.app) as c:
            yield c, mock_es


def _payload(ip: str = "185.220.101.45", severity: str = "high", rule: str = "BruteForceRule") -> dict:
    return {
        "timestamp": "2026-04-27T10:00:00.000Z",
        "rule_name": rule,
        "source_ip": ip,
        "severity": severity,
        "details": {"failed_attempts": 8},
        "response_taken": "pending",
        "event_count": 8,
    }


class TestHealthEndpoint:
    def test_returns_ok(self, client):
        c, _ = client
        resp = c.get("/health")
        assert resp.status_code == 200

    def test_mode_is_simulate(self, client):
        c, _ = client
        assert c.get("/health").json()["mode"] == "simulate"

    def test_initial_active_blocks_is_zero(self, client):
        c, _ = client
        assert c.get("/health").json()["active_blocks_in_memory"] == 0


class TestRespondEndpoint:
    def test_respond_returns_responded(self, client):
        c, _ = client
        resp = c.post("/respond", json=_payload())
        assert resp.status_code == 200
        assert resp.json()["status"] == "responded"

    def test_respond_simulate_action_text(self, client):
        c, _ = client
        resp = c.post("/respond", json=_payload())
        assert "[SIMULATED]" in resp.json()["action"]

    def test_respond_records_ip_in_memory(self, client):
        c, _ = client
        import responder
        c.post("/respond", json=_payload(ip="10.0.0.99"))
        assert "10.0.0.99" in responder.blocked_ips

    def test_dedup_second_call_returns_already_blocked(self, client):
        c, _ = client
        c.post("/respond", json=_payload(ip="10.0.0.1"))
        resp2 = c.post("/respond", json=_payload(ip="10.0.0.1"))
        assert resp2.json()["status"] == "already_blocked"

    def test_dedup_different_ips_both_responded(self, client):
        c, _ = client
        r1 = c.post("/respond", json=_payload(ip="1.1.1.1"))
        r2 = c.post("/respond", json=_payload(ip="2.2.2.2"))
        assert r1.json()["status"] == "responded"
        assert r2.json()["status"] == "responded"

    def test_expired_block_allows_new_response(self, client):
        c, _ = client
        import responder
        # Manually set an already-expired entry
        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        responder.blocked_ips["9.9.9.9"] = past
        resp = c.post("/respond", json=_payload(ip="9.9.9.9"))
        assert resp.json()["status"] == "responded"

    def test_writes_to_es(self, client):
        c, mock_es = client
        c.post("/respond", json=_payload(ip="3.3.3.3"))
        mock_es.index.assert_called_once()
        call_kwargs = mock_es.index.call_args
        doc = call_kwargs.kwargs.get("document") or call_kwargs[1].get("document")
        assert doc["source_ip"] == "3.3.3.3"
        assert doc["rule_name"] == "BruteForceRule"


class TestBlockedEndpoint:
    def test_returns_list(self, client):
        c, mock_es = client
        mock_es.search.return_value = {
            "hits": {"total": {"value": 1}, "hits": [
                {"_source": {"source_ip": "1.2.3.4", "reason": "BruteForceRule"}}
            ]}
        }
        resp = c.get("/blocked")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_empty_when_no_blocks(self, client):
        c, mock_es = client
        mock_es.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}
        resp = c.get("/blocked")
        assert resp.json() == []
