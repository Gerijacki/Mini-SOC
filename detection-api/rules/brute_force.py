import logging
import os

from elasticsearch import Elasticsearch

import es_client
from models import Alert
from rules.base import DetectionRule

logger = logging.getLogger(__name__)

THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW", "60"))
INDEX_LOGS = os.getenv("INDEX_LOGS", "soc-logs")


class BruteForceRule(DetectionRule):
    name = "BruteForceRule"
    description = f"SSH brute force: >{THRESHOLD} failed logins from same IP within {WINDOW}s"

    def detect(self, client: Elasticsearch) -> list[Alert]:
        resp = es_client.search(client, f"{INDEX_LOGS}-*", {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"status": "failure"}},
                        {"term": {"action": "ssh_login"}},
                        {"range": {"@timestamp": {"gte": f"now-{WINDOW}s"}}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {
                    "terms": {"field": "source_ip", "size": 100},
                    "aggs": {
                        "first_seen": {"min": {"field": "@timestamp"}},
                        "last_seen":  {"max": {"field": "@timestamp"}},
                    },
                }
            },
            "size": 0,
        })

        alerts = []
        for bucket in resp["aggregations"]["by_ip"]["buckets"]:
            count = bucket["doc_count"]
            if count < THRESHOLD:
                continue

            ip = bucket["key"]
            if es_client.alert_exists(client, ip, self.name):
                continue

            alert = Alert(
                rule_name=self.name,
                source_ip=ip,
                severity=self.get_severity(count),
                event_count=count,
                details={
                    "failed_attempts": count,
                    "window_seconds": WINDOW,
                    "threshold": THRESHOLD,
                    "first_seen": bucket["first_seen"]["value_as_string"],
                    "last_seen":  bucket["last_seen"]["value_as_string"],
                },
            )
            logger.warning("[%s] ALERT — %s | ip=%s count=%d severity=%s",
                           self.name, self.description, ip, count, alert.severity)
            alerts.append(alert)

        return alerts
