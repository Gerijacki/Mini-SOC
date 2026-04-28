import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Thread

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI

import es_client as esc
from models import Alert, HealthResponse
from rules.anomalous_login import AnomalousLoginRule
from rules.brute_force import BruteForceRule
from rules.suspicious_cmd import SuspiciousCommandRule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("detection-api")

POLL_INTERVAL = int(os.getenv("DETECTION_POLL_INTERVAL", "15"))
RESPONSE_URL = "http://response-system:8001/respond"
RAG_URL = "http://rag-enricher:8003/enrich"
INDEX_ALERTS = os.getenv("INDEX_ALERTS", "soc-alerts")

RULES = [BruteForceRule(), AnomalousLoginRule(), SuspiciousCommandRule()]

state = {
    "es_client": None,
    "last_poll": None,
    "alerts_generated": 0,
    "scheduler": None,
}


def run_detection_cycle() -> None:
    client = state["es_client"]
    if client is None:
        return

    state["last_poll"] = datetime.now(timezone.utc).isoformat()
    cycle_alerts: list[Alert] = []

    for rule in RULES:
        try:
            found = rule.detect(client)
            cycle_alerts.extend(found)
        except Exception as exc:
            logger.error("Rule %s failed: %s", rule.name, exc)

    for alert in cycle_alerts:
        try:
            with httpx.Client(timeout=3.0) as http:
                resp = http.post(RAG_URL, json={
                    "rule_name": alert.rule_name,
                    "source_ip": alert.source_ip,
                    "severity": alert.severity.value,
                    "details": alert.details,
                })
                if resp.status_code == 200:
                    enrichment = resp.json()
                    if enrichment:
                        alert.details.update(enrichment)
                        logger.info(
                            "Alert enriched — techniques=%s confidence=%.2f",
                            enrichment.get("mitre_techniques", []),
                            enrichment.get("threat_confidence", 0),
                        )
        except Exception as exc:
            logger.debug("RAG enrichment unavailable: %s", exc)

        try:
            doc = alert.to_es_doc()
            alert_id = esc.write_alert(client, doc)
            logger.info("Alert written to ES: %s (id=%s)", alert.rule_name, alert_id)
        except Exception as exc:
            logger.error("Failed to write alert to ES: %s", exc)
            continue

        try:
            with httpx.Client(timeout=5.0) as http:
                http.post(RESPONSE_URL, json=alert.model_dump())
        except Exception as exc:
            logger.warning("Could not reach response-system: %s", exc)

    state["alerts_generated"] += len(cycle_alerts)


def _init_background() -> None:
    """Connects to ES and starts the scheduler — runs in a background thread
    so the HTTP server is available immediately for health checks."""
    logger.info("Background init: waiting for Elasticsearch...")
    client = esc.wait_for_elasticsearch()
    esc.bootstrap_indices(client)
    state["es_client"] = client

    scheduler = BackgroundScheduler()
    scheduler.add_job(run_detection_cycle, "interval", seconds=POLL_INTERVAL, id="detection")
    scheduler.start()
    state["scheduler"] = scheduler
    logger.info("Detection scheduler started — poll interval: %ds", POLL_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fire-and-forget: ES init runs in background, HTTP server starts immediately
    t = Thread(target=_init_background, daemon=True)
    t.start()
    yield
    if state["scheduler"]:
        state["scheduler"].shutdown(wait=False)


app = FastAPI(title="SOC Detection API", lifespan=lifespan)


@app.get("/health", response_model=HealthResponse)
def health():
    ready = state["es_client"] is not None
    return HealthResponse(
        status="ok" if ready else "starting",
        es_connected=ready,
        rules_loaded=len(RULES),
        last_poll=state["last_poll"],
        alerts_generated=state["alerts_generated"],
    )


@app.get("/alerts")
def get_alerts(size: int = 20):
    client = state["es_client"]
    if client is None:
        return []
    resp = esc.search(client, INDEX_ALERTS, {
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": size,
    })
    return [h["_source"] for h in resp["hits"]["hits"]]


@app.get("/rules")
def list_rules():
    return [{"name": r.name, "description": r.description} for r in RULES]


@app.post("/trigger")
def trigger_detection():
    run_detection_cycle()
    return {"status": "detection cycle executed", "last_poll": state["last_poll"]}
