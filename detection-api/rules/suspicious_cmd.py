import logging
import os

from elasticsearch import Elasticsearch

import es_client
from models import Alert, AlertSeverity
from rules.base import DetectionRule

logger = logging.getLogger(__name__)

INDEX_LOGS = os.getenv("INDEX_LOGS", "soc-logs")

DANGEROUS_PATTERNS = [
    ("nc ",       AlertSeverity.critical),
    ("base64 -d", AlertSeverity.critical),
    ("python3 -c", AlertSeverity.critical),
    ("curl ",     AlertSeverity.high),
    ("wget ",     AlertSeverity.high),
    ("cat /etc/shadow", AlertSeverity.high),
    ("/tmp/.",    AlertSeverity.high),
    ("chmod 777", AlertSeverity.medium),
    ("crontab",   AlertSeverity.medium),
    ("find / -perm", AlertSeverity.medium),
]


class SuspiciousCommandRule(DetectionRule):
    name = "SuspiciousCommandRule"
    description = "Execution of dangerous commands detected in shell logs"

    def detect(self, client: Elasticsearch) -> list[Alert]:
        should_clauses = [
            {"match_phrase": {"command": pattern}}
            for pattern, _ in DANGEROUS_PATTERNS
        ]

        resp = es_client.search(client, f"{INDEX_LOGS}-*", {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"log_type": "command"}},
                        {"range": {"@timestamp": {"gte": "now-60s"}}},
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
            "size": 50,
        })

        alerts = []
        seen_ips: set[str] = set()

        for hit in resp["hits"]["hits"]:
            src = hit["_source"]
            ip = src.get("source_ip", "unknown")
            cmd = src.get("command", "")

            if ip in seen_ips:
                continue
            if es_client.alert_exists(client, ip, self.name, window_minutes=1):
                continue

            severity = AlertSeverity.medium
            matched_pattern = "unknown"
            for pattern, sev in DANGEROUS_PATTERNS:
                if pattern in cmd:
                    severity = sev
                    matched_pattern = pattern
                    break

            alert = Alert(
                rule_name=self.name,
                source_ip=ip,
                severity=severity,
                event_count=1,
                details={
                    "command": cmd,
                    "matched_pattern": matched_pattern,
                    "username": src.get("username"),
                    "hostname": src.get("hostname"),
                    "timestamp": src.get("@timestamp"),
                },
            )
            logger.warning("[%s] ALERT — ip=%s pattern=%s severity=%s cmd=%s",
                           self.name, ip, matched_pattern, severity, cmd[:80])
            alerts.append(alert)
            seen_ips.add(ip)

        return alerts
