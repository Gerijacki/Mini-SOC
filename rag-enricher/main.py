import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Thread
from typing import Any

import httpx
import numpy as np
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

from seeder import MITRE_TECHNIQUES, MODEL_NAME, seed_chromadb

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("rag-enricher")

TOP_K = 3
MIN_CONFIDENCE = 0.35
SIM_THRESHOLD = 0.55        # min cosine similarity to draw an edge between techniques
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")

_state: dict[str, Any] = {
    "collection": None,
    "model": None,
    "ready": False,
}


class EnrichRequest(BaseModel):
    rule_name: str
    source_ip: str
    severity: str
    details: dict[str, Any] = {}


def _init_background() -> None:
    try:
        collection = seed_chromadb()
        model = SentenceTransformer(MODEL_NAME)
        _state["collection"] = collection
        _state["model"] = model
        _state["ready"] = True
        logger.info("RAG enricher ready — %d techniques indexed", collection.count())
    except Exception as exc:
        logger.error("RAG enricher init failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    t = Thread(target=_init_background, daemon=True)
    t.start()
    yield


app = FastAPI(title="SOC RAG Enricher", lifespan=lifespan)


def _build_query(req: EnrichRequest) -> str:
    parts = [req.rule_name.replace("_", " ")]
    if req.severity in ("critical", "high"):
        parts.append(f"high severity {req.severity} attack")
    for val in req.details.values():
        if isinstance(val, str) and len(val) < 100:
            parts.append(val)
    return " ".join(parts)


# ── Enrichment ────────────────────────────────────────────────────────────────

@app.post("/enrich")
def enrich(req: EnrichRequest) -> dict[str, Any]:
    if not _state["ready"]:
        return {}

    query = _build_query(req)
    embedding = _state["model"].encode([query]).tolist()

    results = _state["collection"].query(
        query_embeddings=embedding,
        n_results=min(TOP_K, _state["collection"].count()),
        include=["documents", "metadatas", "distances"],
    )

    techniques: list[str] = []
    tactics: list[str] = []
    urls: list[str] = []
    summaries: list[str] = []
    best_confidence = 0.0

    for i, (doc_id, metadata, distance) in enumerate(
        zip(results["ids"][0], results["metadatas"][0], results["distances"][0])
    ):
        confidence = max(0.0, 1.0 - distance)
        if confidence < MIN_CONFIDENCE:
            continue
        if i == 0:
            best_confidence = round(confidence, 3)

        techniques.append(doc_id)
        tactic = metadata["tactic"].split(" / ")[0]
        if tactic not in tactics:
            tactics.append(tactic)
        urls.append(metadata["url"])
        summaries.append(f"{metadata['name']} ({doc_id}): {metadata['mitigation']}")

    if not techniques:
        return {}

    return {
        "mitre_techniques": techniques,
        "mitre_tactics": tactics,
        "threat_summary": " | ".join(summaries[:2]),
        "threat_confidence": best_confidence,
        "mitre_urls": urls,
    }


# ── Inspection ────────────────────────────────────────────────────────────────

@app.get("/collection")
def get_collection() -> list[dict[str, Any]]:
    if not _state["ready"]:
        return []
    col = _state["collection"]
    data = col.get(include=["documents", "metadatas"])
    return [
        {"id": id_, "metadata": meta, "snippet": doc[:200]}
        for id_, meta, doc in zip(data["ids"], data["metadatas"], data["documents"])
    ]


@app.get("/health")
def health() -> dict[str, Any]:
    collection = _state["collection"]
    return {
        "status": "ok" if _state["ready"] else "starting",
        "collection_count": collection.count() if collection else 0,
        "model": MODEL_NAME,
    }


@app.get("/status")
def status() -> dict[str, Any]:
    return {
        "techniques": [t["id"] for t in MITRE_TECHNIQUES],
        "total": len(MITRE_TECHNIQUES),
        "ready": _state["ready"],
    }


# ── 3-D Visualization ─────────────────────────────────────────────────────────

@app.get("/viz")
def viz():
    return FileResponse(Path(__file__).parent / "viz.html", media_type="text/html")


@app.get("/viz/data")
def viz_data() -> dict[str, Any]:
    if not _state["ready"]:
        return {"nodes": [], "links": []}

    col = _state["collection"]
    data = col.get(include=["embeddings", "metadatas"])
    ids: list[str] = data["ids"]
    embeddings: list[list[float]] = data["embeddings"]
    metadatas: list[dict] = data["metadatas"]

    # MITRE technique nodes
    nodes: list[dict] = []
    for id_, meta in zip(ids, metadatas):
        nodes.append({
            "id": id_,
            "name": meta["name"],
            "tactic": meta["tactic"].split(" / ")[0],
            "mitigation": meta["mitigation"],
            "url": meta["url"],
            "type": "technique",
            "val": 5,
        })

    # Pairwise cosine similarity edges between techniques
    links: list[dict] = []
    emb = np.array(embeddings, dtype=np.float32)
    norms = np.linalg.norm(emb, axis=1, keepdims=True)
    emb_n = emb / np.maximum(norms, 1e-8)
    sim = np.dot(emb_n, emb_n.T)
    n = len(ids)
    for i in range(n):
        for j in range(i + 1, n):
            s = float(sim[i, j])
            if s >= SIM_THRESHOLD:
                links.append({
                    "source": ids[i],
                    "target": ids[j],
                    "value": round(s, 3),
                    "type": "similarity",
                })

    # Fetch recent alerts from Elasticsearch (best-effort)
    try:
        resp = httpx.post(
            f"{ES_HOST}/soc-alerts/_search",
            json={
                "query": {"match_all": {}},
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 60,
            },
            timeout=3.0,
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            seen_ips: dict[str, dict] = {}
            tech_set = set(ids)

            for hit in hits:
                src = hit["_source"]
                alert_id = f"alert-{hit['_id'][:8]}"
                ip = src.get("source_ip", "unknown")
                severity = src.get("severity", "medium")
                rule = src.get("rule_name", "?")
                mitre_techs: list[str] = src.get("details", {}).get("mitre_techniques", [])

                nodes.append({
                    "id": alert_id,
                    "name": rule,
                    "severity": severity,
                    "source_ip": ip,
                    "timestamp": src.get("@timestamp", ""),
                    "type": "alert",
                    "val": {"critical": 10, "high": 7, "medium": 5, "low": 3}.get(severity, 5),
                })

                ip_id = f"ip-{ip}"
                if ip_id not in seen_ips:
                    seen_ips[ip_id] = {"id": ip_id, "name": ip, "type": "ip", "val": 4, "count": 0}
                seen_ips[ip_id]["count"] += 1
                seen_ips[ip_id]["val"] = min(4 + seen_ips[ip_id]["count"], 9)

                links.append({"source": ip_id, "target": alert_id, "type": "ip_alert", "value": 1})

                for tech_id in mitre_techs:
                    if tech_id in tech_set:
                        links.append({
                            "source": alert_id,
                            "target": tech_id,
                            "type": "alert_technique",
                            "value": 2,
                        })

            nodes.extend(seen_ips.values())
    except Exception as exc:
        logger.debug("Alert fetch for viz skipped: %s", exc)

    return {"nodes": nodes, "links": links}
