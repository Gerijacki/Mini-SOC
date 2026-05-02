import re

from scenarios import brute_force, suspicious_login, command_exec
from utils.ip_pool import ATTACKER_IPS, TRUSTED_IPS, get_attacker_ip, get_trusted_ip

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
REQUIRED_FIELDS = {"@timestamp", "log_type", "source_ip", "username", "action", "status",
                   "hostname", "pid", "message", "scenario"}


# ---------------------------------------------------------------------------
# ip_pool
# ---------------------------------------------------------------------------

class TestIpPool:
    def test_attacker_pool_has_entries(self):
        assert len(ATTACKER_IPS) >= 10

    def test_attacker_entry_has_required_keys(self):
        for entry in ATTACKER_IPS:
            assert "ip" in entry
            assert "country" in entry
            assert "asn" in entry

    def test_trusted_pool_has_entries(self):
        assert len(TRUSTED_IPS) >= 5

    def test_get_attacker_ip_returns_dict(self):
        ip = get_attacker_ip()
        assert isinstance(ip, dict)
        assert "ip" in ip

    def test_get_trusted_ip_returns_string(self):
        ip = get_trusted_ip()
        assert isinstance(ip, str)
        assert "." in ip

    def test_attacker_and_trusted_disjoint(self):
        attacker_ips = {e["ip"] for e in ATTACKER_IPS}
        trusted_ips = set(TRUSTED_IPS)
        assert attacker_ips.isdisjoint(trusted_ips), "Attacker and trusted IP pools must not overlap"


# ---------------------------------------------------------------------------
# brute_force scenario
# ---------------------------------------------------------------------------

class TestBruteForceScenario:
    def test_generates_correct_failure_count(self):
        events = brute_force.generate_burst(burst_size=8)
        failures = [e for e in events if e["status"] == "failure"]
        assert len(failures) == 8

    def test_all_failures_from_same_ip(self):
        events = brute_force.generate_burst(burst_size=10)
        failures = [e for e in events if e["status"] == "failure"]
        ips = {e["source_ip"] for e in failures}
        assert len(ips) == 1

    def test_all_events_are_ssh_login(self):
        events = brute_force.generate_burst(burst_size=5)
        for e in events:
            assert e["action"] == "ssh_login"

    def test_required_fields_present(self):
        events = brute_force.generate_burst(burst_size=3)
        for e in events:
            missing = REQUIRED_FIELDS - e.keys()
            assert not missing, f"Missing fields: {missing}"

    def test_timestamp_is_iso8601(self):
        events = brute_force.generate_burst(burst_size=2)
        for e in events:
            assert TIMESTAMP_RE.match(e["@timestamp"]), f"Bad timestamp: {e['@timestamp']}"

    def test_scenario_field_is_brute_force(self):
        events = brute_force.generate_burst(burst_size=3)
        failures = [e for e in events if e["status"] == "failure"]
        for e in failures:
            assert e["scenario"] == "brute_force"

    def test_message_contains_ip(self):
        events = brute_force.generate_burst(burst_size=1)
        failure = [e for e in events if e["status"] == "failure"][0]
        assert failure["source_ip"] in failure["message"]

    def test_source_ip_from_attacker_pool(self):
        attacker_ips = {e["ip"] for e in ATTACKER_IPS}
        events = brute_force.generate_burst(burst_size=5)
        ips = {e["source_ip"] for e in events}
        assert ips.issubset(attacker_ips)


# ---------------------------------------------------------------------------
# suspicious_login scenario
# ---------------------------------------------------------------------------

class TestSuspiciousLoginScenario:
    def test_returns_single_event(self):
        events = suspicious_login.generate_burst()
        assert len(events) == 1

    def test_event_is_success(self):
        events = suspicious_login.generate_burst()
        assert events[0]["status"] == "success"
        assert events[0]["action"] == "ssh_login"

    def test_event_is_off_hours(self):
        for _ in range(30):
            events = suspicious_login.generate_burst()
            e = events[0]
            assert e.get("is_off_hours") is True
            assert e["hour"] in [0, 1, 2, 3, 4, 22, 23]

    def test_required_fields_present(self):
        events = suspicious_login.generate_burst()
        for e in events:
            missing = REQUIRED_FIELDS - e.keys()
            assert not missing, f"Missing fields: {missing}"

    def test_scenario_field(self):
        events = suspicious_login.generate_burst()
        assert events[0]["scenario"] == "suspicious_login"


# ---------------------------------------------------------------------------
# command_exec scenario
# ---------------------------------------------------------------------------

class TestCommandExecScenario:
    def test_contains_command_event(self):
        for _ in range(10):
            events = command_exec.generate_burst()
            cmd_events = [e for e in events if e["log_type"] == "command"]
            assert len(cmd_events) >= 1

    def test_command_events_have_command_field(self):
        for _ in range(5):
            events = command_exec.generate_burst()
            for e in [x for x in events if x["log_type"] == "command"]:
                assert "command" in e
                assert len(e["command"]) > 0

    def test_command_event_action(self):
        events = command_exec.generate_burst()
        for e in [x for x in events if x["log_type"] == "command"]:
            assert e["action"] == "command_execution"
            assert e["scenario"] == "command_exec"

    def test_timestamp_is_iso8601(self):
        events = command_exec.generate_burst()
        for e in events:
            assert TIMESTAMP_RE.match(e["@timestamp"]), f"Bad timestamp: {e['@timestamp']}"
