import logging
import os
import subprocess
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from threading import Thread
from typing import Any

from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from fastapi import FastAPI
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("response-system")

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_BLOCKED = os.getenv("INDEX_BLOCKED", "soc-blocked-ips")
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "simulate")
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "3600"))

blocked_ips: dict[str, datetime] = {}
_state: dict[str, Elasticsearch | None] = {"es": None}


class AlertPayload(BaseModel):
    timestamp: str
    rule_name: str
    source_ip: str
    severity: str
    details: dict[str, Any] = {}
    response_taken: str = "pending"
    event_count: int = 0


def get_es_client() -> Elasticsearch:
    client = Elasticsearch(hosts=[ES_HOST])
    for _ in range(20):
        try:
            client.cluster.health(wait_for_status="yellow", timeout="5s")
            return client
        except Exception:
            time.sleep(5)
    return client


def _init_background() -> None:
    """Connect to ES in background — HTTP server starts immediately for health checks."""
    _state["es"] = get_es_client()
    logger.info("Response system connected to Elasticsearch — mode: %s", RESPONSE_MODE)


@asynccontextmanager
async def lifespan(app: FastAPI):
    t = Thread(target=_init_background, daemon=True)
    t.start()
    yield
    _state["es"] = None


app = FastAPI(title="SOC Response System", lifespan=lifespan)


def _is_already_blocked(ip: str) -> bool:
    expiry = blocked_ips.get(ip)
    if expiry is None:
        return False
    if datetime.now(timezone.utc) < expiry:
        return True
    del blocked_ips[ip]
    return False


def _block_ip(ip: str) -> str:
    if RESPONSE_MODE == "enforce":
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            return f"[ENFORCED] Blocked {ip} via iptables"
        except subprocess.CalledProcessError as exc:
            logger.error("iptables failed: %s", exc)
            return f"[ENFORCE_FAILED] {exc}"
    return f"[SIMULATED] Would block {ip} via iptables -A INPUT -s {ip} -j DROP"


def _record_block(alert: AlertPayload, action: str) -> None:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=BLOCK_DURATION)
    doc = {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "source_ip": alert.source_ip,
        "reason": alert.rule_name,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "action_taken": action,
        "block_duration_seconds": BLOCK_DURATION,
        "expires_at": expires.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "details": alert.details,
    }
    if _state["es"] is not None:
        try:
            _state["es"].index(index=INDEX_BLOCKED, document=doc)
        except Exception as exc:
            logger.error("Failed to write block record to ES: %s", exc)
    blocked_ips[alert.source_ip] = expires


@app.post("/respond")
def respond(alert: AlertPayload):
    ip = alert.source_ip

    if _is_already_blocked(ip):
        logger.debug("IP %s already blocked, skipping", ip)
        return {"status": "already_blocked", "ip": ip}

    action = _block_ip(ip)
    _record_block(alert, action)

    log_fn = logger.critical if alert.severity in ("critical", "high") else logger.warning
    log_fn("RESPONSE — %s | rule=%s severity=%s", action, alert.rule_name, alert.severity)

    return {"status": "responded", "ip": ip, "action": action, "mode": RESPONSE_MODE}


@app.get("/blocked")
def get_blocked(size: int = 50):
    if _state["es"] is None:
        return []
    try:
        resp = _state["es"].search(
            index=INDEX_BLOCKED,
            body={
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": size,
            },
        )
        return [h["_source"] for h in resp["hits"]["hits"]]
    except Exception as exc:
        return {"error": str(exc)}


@app.get("/health")
def health():
    return {
        "status": "ok" if _state["es"] is not None else "starting",
        "mode": RESPONSE_MODE,
        "active_blocks_in_memory": len(blocked_ips),
    }
