"""
Kibana setup — runs once at container startup.

Configures:
  1. Data views (index patterns) for all three SOC indices
  2. SOC Overview dashboard with 6 visualizations
  3. Kibana Stack Alerting rules (brute force, suspicious cmd, anomalous login)
"""
import json
import logging
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("kibana-setup")

KIBANA_HOST = os.getenv("KIBANA_HOST", "http://kibana:5601")
HEADERS = {"kbn-xsrf": "true", "Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# Readiness
# ---------------------------------------------------------------------------

def wait_for_kibana(max_retries: int = 40, delay: int = 10) -> None:
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(f"{KIBANA_HOST}/api/status", timeout=5)
            level = resp.json().get("status", {}).get("overall", {}).get("level", "")
            if level == "available":
                logger.info("Kibana ready")
                return
            logger.info("Kibana status: %s (attempt %d/%d)", level, attempt, max_retries)
        except Exception as exc:
            logger.warning("Kibana not ready yet (%d/%d): %s", attempt, max_retries, exc)
        time.sleep(delay)
    raise RuntimeError("Kibana did not become available")


# ---------------------------------------------------------------------------
# Data views
# ---------------------------------------------------------------------------

def create_data_view(title: str, dv_id: str, time_field: str = "@timestamp") -> None:
    check = requests.get(f"{KIBANA_HOST}/api/data_views/data_view/{dv_id}", headers=HEADERS, timeout=5)
    if check.status_code == 200:
        logger.info("Data view already exists: %s", title)
        return
    payload = {"data_view": {"id": dv_id, "title": title, "timeFieldName": time_field}}
    resp = requests.post(f"{KIBANA_HOST}/api/data_views/data_view", headers=HEADERS, json=payload, timeout=10)
    if resp.status_code in (200, 201):
        logger.info("Created data view: %s", title)
    else:
        logger.warning("Data view %s: %s %s", title, resp.status_code, resp.text[:200])


# ---------------------------------------------------------------------------
# Saved objects builder
# ---------------------------------------------------------------------------

def _search_source(ip_id: str, kuery: str = "") -> tuple[str, list]:
    src = {
        "query": {"query": kuery, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }
    refs = [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": ip_id}]
    return json.dumps(src), refs


def _count(label: str = None) -> dict:
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric",
            "params": {"customLabel": label} if label else {}}


def _terms(agg_id: str, field: str, schema: str, size: int = 10, label: str = None) -> dict:
    p = {"field": field, "size": size, "order": "desc", "orderBy": "1"}
    if label:
        p["customLabel"] = label
    return {"id": agg_id, "enabled": True, "type": "terms", "schema": schema, "params": p}


def _date_histogram(agg_id: str) -> dict:
    return {"id": agg_id, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}}}


def _axes(position_cat: str = "bottom", label_y: str = "Count") -> dict:
    return {
        "grid": {"categoryLines": False},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": position_cat,
                           "show": True, "style": {}, "scale": {"type": "linear"},
                           "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                        "position": "left" if position_cat == "bottom" else "bottom",
                        "show": True, "style": {}, "scale": {"type": "linear", "mode": "normal"},
                        "labels": {"show": True, "rotate": 75 if position_cat != "bottom" else 0,
                                   "filter": True, "truncate": 100}, "title": {"text": label_y}}],
        "addTooltip": True, "addLegend": True, "legendPosition": "right",
        "times": [], "addTimeMarker": False,
    }


def _series(chart_type: str, mode: str = "normal") -> list:
    return [{"show": True, "type": chart_type, "mode": mode, "data": {"label": "Count", "id": "1"},
             "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "lineWidth": 2,
             "interpolate": "linear", "showCircles": True}]


def build_saved_objects() -> list[dict]:
    objs = []

    # Index patterns
    for ip_id, title in [("soc-ip-logs", "soc-logs-*"), ("soc-ip-alerts", "soc-alerts"), ("soc-ip-blocked", "soc-blocked-ips")]:
        objs.append({"id": ip_id, "type": "index-pattern",
                     "attributes": {"title": title, "timeFieldName": "@timestamp"}, "references": []})

    # Viz 1 — Attack Timeline (line, soc-logs-*)
    src, refs = _search_source("soc-ip-logs")
    objs.append({
        "id": "soc-viz-timeline", "type": "visualization",
        "attributes": {
            "title": "Attack Timeline",
            "visState": json.dumps({
                "title": "Attack Timeline", "type": "line",
                "params": {**_axes(), "seriesParams": _series("line")},
                "aggs": [_count(), _date_histogram("2"), _terms("3", "scenario", "group", 6, "Attack Type")],
            }),
            "uiStateJSON": "{}", "description": "Events over time split by attack scenario",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Viz 2 — Failed SSH Logins by IP (horizontal bar, soc-logs-*)
    src, refs = _search_source("soc-ip-logs", "status:failure AND action:ssh_login")
    objs.append({
        "id": "soc-viz-failed-logins", "type": "visualization",
        "attributes": {
            "title": "Failed SSH Logins by IP",
            "visState": json.dumps({
                "title": "Failed SSH Logins by IP", "type": "horizontal_bar",
                "params": {**_axes(position_cat="left", label_y="Count"), "seriesParams": _series("histogram", "stacked")},
                "aggs": [_count(), _terms("2", "source_ip", "segment", 15, "Attacking IP")],
            }),
            "uiStateJSON": "{}", "description": "Top source IPs by failed SSH login count",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Viz 3 — Top Attacking IPs (data table, soc-logs-*)
    src, refs = _search_source("soc-ip-logs")
    objs.append({
        "id": "soc-viz-top-ips", "type": "visualization",
        "attributes": {
            "title": "Top Attacking IPs",
            "visState": json.dumps({
                "title": "Top Attacking IPs", "type": "table",
                "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                            "sort": {"columnIndex": None, "direction": None}, "showTotal": False, "totalFunc": "sum"},
                "aggs": [_count("Events"), _terms("2", "source_ip", "bucket", 20, "Source IP")],
            }),
            "uiStateJSON": "{}", "description": "Top attacking IPs by total event count",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Viz 4 — Alerts Over Time (area, soc-alerts)
    src, refs = _search_source("soc-ip-alerts")
    area_params = {**_axes(label_y="Alerts"), "seriesParams": _series("area", "stacked")}
    area_params["seriesParams"][0]["type"] = "area"
    objs.append({
        "id": "soc-viz-alerts-timeline", "type": "visualization",
        "attributes": {
            "title": "Alerts Over Time",
            "visState": json.dumps({
                "title": "Alerts Over Time", "type": "area",
                "params": area_params,
                "aggs": [_count(), _date_histogram("2"), _terms("3", "rule_name", "group", 3, "Rule")],
            }),
            "uiStateJSON": "{}", "description": "Alert volume over time by detection rule",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Viz 5 — Alerts by Severity (pie, soc-alerts)
    src, refs = _search_source("soc-ip-alerts")
    objs.append({
        "id": "soc-viz-severity", "type": "visualization",
        "attributes": {
            "title": "Alerts by Severity",
            "visState": json.dumps({
                "title": "Alerts by Severity", "type": "pie",
                "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                            "isDonut": True, "labels": {"show": False, "values": True, "last_level": True, "truncate": 100}},
                "aggs": [_count(), _terms("2", "severity", "segment", 4, "Severity")],
            }),
            "uiStateJSON": "{}", "description": "Distribution of alerts by severity",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Viz 6 — Blocked IPs Count (metric, soc-blocked-ips)
    src, refs = _search_source("soc-ip-blocked")
    objs.append({
        "id": "soc-viz-blocked-count", "type": "visualization",
        "attributes": {
            "title": "Blocked IPs",
            "visState": json.dumps({
                "title": "Blocked IPs", "type": "metric",
                "params": {
                    "addTooltip": True, "addLegend": False, "type": "metric",
                    "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                                "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                                "labels": {"show": True}, "invertColors": False,
                                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False,
                                           "subText": "", "fontSize": 60}},
                },
                "aggs": [_count("Blocked IPs")],
            }),
            "uiStateJSON": "{}", "description": "Total blocked IPs",
            "kibanaSavedObjectMeta": {"searchSourceJSON": src},
        },
        "references": refs,
    })

    # Dashboard — SOC Overview
    # Grid: 48 cols. Row heights: 15 units.
    # Row 0: Timeline full width
    # Row 1: Failed Logins (left) | Top IPs (right)
    # Row 2: Alerts Timeline | Severity Pie | Blocked Count
    panels = [
        {"panelIndex": "1", "gridData": {"x": 0,  "y": 0,  "w": 48, "h": 15, "i": "1"}, "panelRefName": "panel_0", "embeddableConfig": {"enhancements": {}}},
        {"panelIndex": "2", "gridData": {"x": 0,  "y": 15, "w": 24, "h": 15, "i": "2"}, "panelRefName": "panel_1", "embeddableConfig": {"enhancements": {}}},
        {"panelIndex": "3", "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "3"}, "panelRefName": "panel_2", "embeddableConfig": {"enhancements": {}}},
        {"panelIndex": "4", "gridData": {"x": 0,  "y": 30, "w": 32, "h": 15, "i": "4"}, "panelRefName": "panel_3", "embeddableConfig": {"enhancements": {}}},
        {"panelIndex": "5", "gridData": {"x": 32, "y": 30, "w": 10, "h": 15, "i": "5"}, "panelRefName": "panel_4", "embeddableConfig": {"enhancements": {}}},
        {"panelIndex": "6", "gridData": {"x": 42, "y": 30, "w": 6,  "h": 15, "i": "6"}, "panelRefName": "panel_5", "embeddableConfig": {"enhancements": {}}},
    ]

    objs.append({
        "id": "soc-overview-dashboard", "type": "dashboard",
        "attributes": {
            "title": "SOC Overview",
            "description": "Mini SOC — Attack detection, alerting, and automated response monitoring",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True, "syncColors": False}),
            "version": 1,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-1h",
            "refreshInterval": {"pause": False, "value": 30000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": [
            {"name": "panel_0", "type": "visualization", "id": "soc-viz-timeline"},
            {"name": "panel_1", "type": "visualization", "id": "soc-viz-failed-logins"},
            {"name": "panel_2", "type": "visualization", "id": "soc-viz-top-ips"},
            {"name": "panel_3", "type": "visualization", "id": "soc-viz-alerts-timeline"},
            {"name": "panel_4", "type": "visualization", "id": "soc-viz-severity"},
            {"name": "panel_5", "type": "visualization", "id": "soc-viz-blocked-count"},
        ],
    })

    return objs


def import_saved_objects(objs: list[dict]) -> None:
    ndjson = "\n".join(json.dumps(o) for o in objs)
    resp = requests.post(
        f"{KIBANA_HOST}/api/saved_objects/_import?overwrite=true",
        headers={"kbn-xsrf": "true"},
        files={"file": ("soc.ndjson", ndjson.encode(), "application/ndjson")},
        timeout=30,
    )
    if resp.status_code == 200:
        result = resp.json()
        logger.info("Saved objects imported: %d ok, %d errors",
                    result.get("successCount", 0), len(result.get("errors", [])))
        for err in result.get("errors", []):
            logger.warning("  Import error [%s]: %s", err.get("id"), err.get("error", {}).get("message", ""))
    else:
        logger.error("Import failed: %s %s", resp.status_code, resp.text[:500])


# ---------------------------------------------------------------------------
# Kibana Stack Alerting rules
# ---------------------------------------------------------------------------

_ALERTING_RULES = [
    {
        "name": "SOC: SSH Brute Force Detected",
        "tags": ["soc", "brute-force", "ssh"],
        "rule_type_id": ".es-query",
        "consumer": "stackAlerts",
        "schedule": {"interval": "1m"},
        "params": {
            "searchType": "esQuery",
            "timeWindowSize": 1, "timeWindowUnit": "m",
            "threshold": [5], "thresholdComparator": ">",
            "index": ["soc-logs-*"], "timeField": "@timestamp",
            "esQuery": json.dumps({"query": {"bool": {"must": [
                {"term": {"status": "failure"}},
                {"term": {"action": "ssh_login"}},
            ]}}}),
            "excludeHitsFromPreviousRun": False,
            "aggType": "count", "groupBy": "all", "size": 100,
        },
        "actions": [],
        "notify_when": "onActionGroupChange",
    },
    {
        "name": "SOC: Dangerous Command Executed",
        "tags": ["soc", "command-exec", "lateral-movement"],
        "rule_type_id": ".es-query",
        "consumer": "stackAlerts",
        "schedule": {"interval": "1m"},
        "params": {
            "searchType": "esQuery",
            "timeWindowSize": 1, "timeWindowUnit": "m",
            "threshold": [0], "thresholdComparator": ">",
            "index": ["soc-logs-*"], "timeField": "@timestamp",
            "esQuery": json.dumps({"query": {"bool": {"must": [
                {"term": {"log_type": "command"}},
                {"bool": {"minimum_should_match": 1, "should": [
                    {"match_phrase": {"command": p}}
                    for p in ["wget", "nc ", "curl ", "chmod 777", "/tmp/.", "base64 -d"]
                ]}},
            ]}}}),
            "excludeHitsFromPreviousRun": False,
            "aggType": "count", "groupBy": "all", "size": 100,
        },
        "actions": [],
        "notify_when": "onActionGroupChange",
    },
    {
        "name": "SOC: Anomalous Login After Brute Force",
        "tags": ["soc", "anomaly", "credential-compromise"],
        "rule_type_id": ".es-query",
        "consumer": "stackAlerts",
        "schedule": {"interval": "1m"},
        "params": {
            "searchType": "esQuery",
            "timeWindowSize": 5, "timeWindowUnit": "m",
            "threshold": [0], "thresholdComparator": ">",
            "index": ["soc-logs-*"], "timeField": "@timestamp",
            "esQuery": json.dumps({"query": {"bool": {"must": [
                {"term": {"action": "ssh_login"}},
                {"term": {"status": "success"}},
                {"term": {"scenario": "brute_force_success"}},
            ]}}}),
            "excludeHitsFromPreviousRun": False,
            "aggType": "count", "groupBy": "all", "size": 100,
        },
        "actions": [],
        "notify_when": "onActionGroupChange",
    },
]


def setup_alerting_rules() -> None:
    for rule in _ALERTING_RULES:
        try:
            resp = requests.post(
                f"{KIBANA_HOST}/api/alerting/rule",
                headers=HEADERS,
                json=rule,
                timeout=15,
            )
            if resp.status_code in (200, 201):
                logger.info("Alerting rule created: %s", rule["name"])
            else:
                # Alerting requires xpack.security or encryptionKey — log but don't fail
                logger.warning("Alerting rule skipped (%s): %s", resp.status_code, resp.text[:200])
        except Exception as exc:
            logger.warning("Alerting rule %s unavailable: %s", rule["name"], exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    wait_for_kibana()

    logger.info("Creating data views...")
    create_data_view("soc-logs-*",      "soc-ip-logs")
    create_data_view("soc-alerts",      "soc-ip-alerts")
    create_data_view("soc-blocked-ips", "soc-ip-blocked")

    logger.info("Building and importing saved objects (dashboard + 6 visualizations)...")
    objs = build_saved_objects()
    import_saved_objects(objs)

    logger.info("Setting up Kibana Stack Alerting rules...")
    setup_alerting_rules()

    logger.info("=" * 60)
    logger.info("Setup complete. Open Kibana:")
    logger.info("  Dashboard  → http://localhost:5601/app/dashboards")
    logger.info("  Alerts     → http://localhost:5601/app/management/insightsAndAlerting/triggersActions/rules")
    logger.info("  Discover   → http://localhost:5601/app/discover")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
