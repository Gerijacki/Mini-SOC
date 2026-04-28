import logging
import os

from elasticsearch import Elasticsearch

import es_client
from models import Alert, AlertSeverity
from rules.base import DetectionRule

logger = logging.getLogger(__name__)

INDEX_LOGS = os.getenv("INDEX_LOGS", "soc-logs")
FAILURE_THRESHOLD = 3
WINDOW_MINUTES = 5


class AnomalousLoginRule(DetectionRule):
    name = "AnomalousLoginRule"
    description = f"Successful login after ≥{FAILURE_THRESHOLD} failures from same IP within {WINDOW_MINUTES}m"

    def detect(self, client: Elasticsearch) -> list[Alert]:
        # Phase 1: IPs with enough failures
        resp = es_client.search(client, f"{INDEX_LOGS}-*", {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"status": "failure"}},
                        {"term": {"action": "ssh_login"}},
                        {"range": {"@timestamp": {"gte": f"now-{WINDOW_MINUTES}m"}}},
                    ]
                }
            },
            "aggs": {
                "by_ip": {"terms": {"field": "source_ip", "size": 100}}
            },
            "size": 0,
        })

        candidates = {
            b["key"]: b["doc_count"]
            for b in resp["aggregations"]["by_ip"]["buckets"]
            if b["doc_count"] >= FAILURE_THRESHOLD
        }

        if not candidates:
            return []

        # Phase 2: check which candidates also had a success
        alerts = []
        for ip, failure_count in candidates.items():
            success_resp = es_client.search(client, f"{INDEX_LOGS}-*", {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"source_ip": ip}},
                            {"term": {"status": "success"}},
                            {"term": {"action": "ssh_login"}},
                            {"range": {"@timestamp": {"gte": f"now-{WINDOW_MINUTES}m"}}},
                        ]
                    }
                },
                "size": 1,
            })

            if success_resp["hits"]["total"]["value"] == 0:
                continue
            if es_client.alert_exists(client, ip, self.name):
                continue

            hit = success_resp["hits"]["hits"][0]["_source"]
            alert = Alert(
                rule_name=self.name,
                source_ip=ip,
                severity=AlertSeverity.high,
                event_count=failure_count,
                details={
                    "failed_before_success": failure_count,
                    "successful_user": hit.get("username"),
                    "window_minutes": WINDOW_MINUTES,
                    "success_timestamp": hit.get("@timestamp"),
                },
            )
            logger.warning("[%s] ALERT — ip=%s failures=%d user=%s",
                           self.name, ip, failure_count, hit.get("username"))
            alerts.append(alert)

        return alerts
