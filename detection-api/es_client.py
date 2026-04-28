import logging
import os
import time

from elasticsearch import Elasticsearch, NotFoundError

logger = logging.getLogger(__name__)

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_ALERTS = os.getenv("INDEX_ALERTS", "soc-alerts")
INDEX_BLOCKED = os.getenv("INDEX_BLOCKED", "soc-blocked-ips")


def get_client() -> Elasticsearch:
    return Elasticsearch(hosts=[ES_HOST])


def wait_for_elasticsearch(max_retries: int = 30, delay: int = 5) -> Elasticsearch:
    client = get_client()
    for attempt in range(1, max_retries + 1):
        try:
            health = client.cluster.health(wait_for_status="yellow", timeout="5s")
            logger.info("Elasticsearch ready — status: %s", health["status"])
            return client
        except Exception as exc:
            logger.warning("ES not ready (attempt %d/%d): %s", attempt, max_retries, exc)
            time.sleep(delay)
    raise RuntimeError("Elasticsearch did not become available in time")


def bootstrap_indices(client: Elasticsearch) -> None:
    _create_index_template(client)
    _ensure_index(client, INDEX_ALERTS, {
        "mappings": {
            "properties": {
                "@timestamp":    {"type": "date"},
                "rule_name":     {"type": "keyword"},
                "source_ip":     {"type": "keyword"},
                "severity":      {"type": "keyword"},
                "response_taken":{"type": "keyword"},
                "event_count":   {"type": "integer"},
                "details":       {"type": "object", "dynamic": True},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    })
    _ensure_index(client, INDEX_BLOCKED, {
        "mappings": {
            "properties": {
                "@timestamp":             {"type": "date"},
                "source_ip":              {"type": "keyword"},
                "reason":                 {"type": "keyword"},
                "rule_name":              {"type": "keyword"},
                "severity":               {"type": "keyword"},
                "action_taken":           {"type": "text"},
                "block_duration_seconds": {"type": "integer"},
                "expires_at":             {"type": "date"},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    })


def _create_index_template(client: Elasticsearch) -> None:
    template_name = "soc-logs-template"
    try:
        client.indices.get_index_template(name=template_name)
        return
    except NotFoundError:
        pass

    client.indices.put_index_template(
        name=template_name,
        body={
            "index_patterns": ["soc-logs-*"],
            "template": {
                "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                "mappings": {
                    "properties": {
                        "@timestamp":    {"type": "date"},
                        "source_ip":     {"type": "keyword"},
                        "source_country":{"type": "keyword"},
                        "source_asn":    {"type": "keyword"},
                        "username":      {"type": "keyword"},
                        "action":        {"type": "keyword"},
                        "status":        {"type": "keyword"},
                        "log_type":      {"type": "keyword"},
                        "scenario":      {"type": "keyword"},
                        "hostname":      {"type": "keyword"},
                        "command":       {"type": "keyword"},
                        "pid":           {"type": "integer"},
                        "port":          {"type": "integer"},
                        "hour":          {"type": "integer"},
                        "is_off_hours":  {"type": "boolean"},
                        "message":       {"type": "text"},
                    }
                },
            },
        },
    )
    logger.info("Created index template: %s", template_name)


def _ensure_index(client: Elasticsearch, index: str, body: dict) -> None:
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=body)
        logger.info("Created index: %s", index)


def search(client: Elasticsearch, index: str, query: dict) -> dict:
    return client.search(index=index, body=query)


def write_alert(client: Elasticsearch, doc: dict) -> str:
    resp = client.index(index=INDEX_ALERTS, document=doc)
    return resp["_id"]


def alert_exists(client: Elasticsearch, source_ip: str, rule_name: str, window_minutes: int = 5) -> bool:
    resp = client.search(
        index=INDEX_ALERTS,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"source_ip": source_ip}},
                        {"term": {"rule_name": rule_name}},
                        {"range": {"@timestamp": {"gte": f"now-{window_minutes}m"}}},
                    ]
                }
            },
            "size": 1,
        },
    )
    return resp["hits"]["total"]["value"] > 0
