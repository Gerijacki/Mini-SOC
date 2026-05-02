# Deployment Guide

This guide covers deploying Mini-SOC in production and connecting it to real system logs.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Dev deployment (quick start)](#dev-deployment)
3. [Production deployment](#production-deployment)
4. [Real log ingestion](#real-log-ingestion)
5. [Cloud log ingestion](#cloud-log-ingestion)
6. [Enabling enforce mode](#enabling-enforce-mode)
7. [Verification checklist](#verification-checklist)

---

## Prerequisites

| Requirement | Dev | Production |
|---|---|---|
| Docker Engine | 24+ | 24+ |
| Docker Compose | v2.20+ | v2.20+ |
| RAM | 4 GB | 8 GB |
| Disk | 10 GB free | 40 GB free (ES data) |
| OS | Any | Linux (for iptables enforce mode) |

**Ports that must be available:** `9200` (ES), `5601` (Kibana), `8000` (detection-api), `8001` (response-system), `8003` (rag-enricher).

---

## Dev Deployment

```bash
git clone https://github.com/Gerijacki/soc.git && cd soc
cp .env.example .env
docker compose up --build
```

**Startup timeline:**
- ~60s — Elasticsearch ready
- ~90s — Kibana ready
- ~120s — RAG enricher ready (model load + ChromaDB seeding)
- ~130s — Kibana setup completes (dashboard + alerting rules created)

Access points once healthy:
- Kibana SOC Dashboard: http://localhost:5601
- 3D Attack Graph: http://localhost:8003/viz
- Detection API docs: http://localhost:8000/docs

---

## Production Deployment

### Step 1 — Prepare environment file

```bash
cp .env.prod.example .env.prod
# Edit .env.prod — fill in ALL passwords before proceeding
```

Generate a secure Kibana encryption key (must be ≥ 32 characters):
```bash
openssl rand -hex 32
```

### Step 2 — First boot: initialize Elasticsearch security

Start only Elasticsearch to set up the built-in users:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env.prod up -d elasticsearch
```

Wait for it to be healthy (check with `docker compose ps`), then set the built-in user passwords:
```bash
# Set kibana_system password (matches KIBANA_SYSTEM_PASSWORD in .env.prod)
docker compose exec elasticsearch \
  elasticsearch-reset-password -u kibana_system --interactive

# Set elastic superuser password if not already set via ELASTIC_PASSWORD
docker compose exec elasticsearch \
  elasticsearch-reset-password -u elastic --interactive
```

### Step 3 — Create service users

Each Python service connects with minimal privileges. Run these once after ES is healthy:

```bash
ES_ADDR="http://localhost:9200"
ES_CREDS="elastic:${ELASTIC_PASSWORD}"   # from .env.prod

# filebeat_writer — indexes into soc-logs-*
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/role/filebeat_writer_role" \
  -H "Content-Type: application/json" -d '{
    "cluster": ["monitor"],
    "indices": [{"names": ["soc-logs-*"], "privileges": ["create_index", "index", "create"]}]
  }'
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/user/filebeat_writer" \
  -H "Content-Type: application/json" -d "{
    \"password\": \"${FILEBEAT_WRITER_PASSWORD}\",
    \"roles\": [\"filebeat_writer_role\"]
  }"

# detection_reader — reads soc-logs-*, writes soc-alerts, soc-blocked-ips
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/role/detection_reader_role" \
  -H "Content-Type: application/json" -d '{
    "cluster": ["monitor"],
    "indices": [
      {"names": ["soc-logs-*"], "privileges": ["read"]},
      {"names": ["soc-alerts", "soc-blocked-ips"], "privileges": ["create_index", "index", "read", "create"]}
    ]
  }'
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/user/detection_reader" \
  -H "Content-Type: application/json" -d "{
    \"password\": \"${DETECTION_READER_PASSWORD}\",
    \"roles\": [\"detection_reader_role\"]
  }"

# response_writer — writes to soc-blocked-ips only
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/role/response_writer_role" \
  -H "Content-Type: application/json" -d '{
    "cluster": [],
    "indices": [
      {"names": ["soc-blocked-ips"], "privileges": ["create_index", "index", "read", "create"]},
      {"names": ["soc-alerts"], "privileges": ["read"]}
    ]
  }'
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/user/response_writer" \
  -H "Content-Type: application/json" -d "{
    \"password\": \"${RESPONSE_WRITER_PASSWORD}\",
    \"roles\": [\"response_writer_role\"]
  }"

# kibana_setup — creates data views, dashboards, alerting rules
curl -u "$ES_CREDS" -X POST "$ES_ADDR/_security/user/kibana_setup" \
  -H "Content-Type: application/json" -d "{
    \"password\": \"${KIBANA_SETUP_PASSWORD}\",
    \"roles\": [\"kibana_admin\", \"superuser\"]
  }"
```

### Step 4 — Pull images and launch

```bash
# Pull pre-built images from GHCR
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env.prod pull

# Launch the full stack
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  --env-file .env.prod up -d

# Monitor startup
docker compose logs -f
```

### Step 5 — Kibana login

Navigate to http://localhost:5601 and log in with username `elastic` and your `ELASTIC_PASSWORD`.

---

## Real Log Ingestion

### Linux — `/var/log/auth.log` (Ubuntu/Debian/RHEL)

The production Filebeat config (`filebeat/filebeat.prod.yml`) normalizes raw syslog into the schema the detection rules query.

**On the host running SSH (not inside Docker):**

```bash
# Install Filebeat (same version as the stack)
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.0-amd64.deb
sudo dpkg -i filebeat-8.13.0-amd64.deb

# Copy the production config
sudo cp filebeat/filebeat.prod.yml /etc/filebeat/filebeat.yml

# Set credentials (adjust the SOC host IP)
sudo tee /etc/filebeat/env <<EOF
ES_HOST=http://<soc-host-ip>:9200
ELASTIC_USERNAME=filebeat_writer
ELASTIC_PASSWORD=<FILEBEAT_WRITER_PASSWORD>
EOF
sudo chmod 600 /etc/filebeat/env

sudo systemctl enable --now filebeat
sudo systemctl status filebeat
```

**Verify field parsing** (run against the SOC host):
```bash
curl -s "http://localhost:9200/soc-logs-*/_search?size=1&pretty" \
  -u elastic:${ELASTIC_PASSWORD} | \
  jq '.hits.hits[0]._source | {log_type, action, status, source_ip, username}'
```

Expected output for a failed SSH login:
```json
{
  "log_type": "auth",
  "action": "ssh_login",
  "status": "failure",
  "source_ip": "185.220.101.45",
  "username": "root"
}
```

### Linux — systemd journald

On hosts running systemd (Ubuntu 20.04+, Debian 10+, RHEL 8+), journald provides cleaner structured data:

```bash
# Grant Filebeat access to the journal
sudo usermod -aG systemd-journal filebeat
sudo systemctl restart filebeat
```

In `filebeat.prod.yml`, set `enabled: false` on the `log` input and `enabled: true` on the `journald` input, then restart Filebeat.

### Windows — Event Log

Run on the Windows machine being monitored. Filebeat must be installed as a Windows service:

```powershell
# Run as Administrator
cd "C:\Program Files\Filebeat"
.\install-service-filebeat.ps1

# Copy config
Copy-Item .\filebeat.windows.yml .\filebeat.yml

# Set environment variables (PowerShell)
[System.Environment]::SetEnvironmentVariable("ES_HOST", "http://<soc-host-ip>:9200", "Machine")
[System.Environment]::SetEnvironmentVariable("ELASTIC_USERNAME", "filebeat_writer", "Machine")
[System.Environment]::SetEnvironmentVariable("ELASTIC_PASSWORD", "<password>", "Machine")

Start-Service filebeat
```

**Enable required audit policies** (required for event IDs 4624, 4625, 4688):
```
secpol.msc → Local Policies → Audit Policy
  - Audit logon events: Success, Failure
  - Audit process tracking: Success
```

**Field mapping — what detection rules see:**

| Windows Event | Event ID | ES `status` | ES `action` | ES `log_type` |
|---|---|---|---|---|
| Successful logon | 4624 | `success` | `ssh_login` | `auth` |
| Failed logon | 4625 | `failure` | `ssh_login` | `auth` |
| Process creation | 4688 | `executed` | `command_execution` | `command` |

> `action: "ssh_login"` is used for Windows logon events to maintain compatibility
> with existing detection rules without requiring rule modifications.

---

## Cloud Log Ingestion

### AWS CloudWatch Logs

Filebeat has a native CloudWatch Logs input. VPC Flow Logs and CloudTrail both produce structured JSON, so `json.keys_under_root: true` works (same as the dev config).

```yaml
filebeat.inputs:
  - type: aws-cloudwatch
    log_group_arn: arn:aws:logs:us-east-1:123456789:log-group:sshd-logs
    scan_frequency: 1m
    start_position: beginning
    # CloudTrail sourceIPAddress → source_ip, eventName → action
    processors:
      - rename:
          fields:
            - from: sourceIPAddress
              to: source_ip
            - from: userIdentity.userName
              to: username
          ignore_missing: true
      - add_fields:
          target: ''
          fields:
            log_type: auth
            action: ssh_login
            status: success
```

Full reference: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-cloudwatch.html

### GCP Cloud Logging (Pub/Sub)

```yaml
filebeat.inputs:
  - type: gcp-pubsub
    project_id: my-project
    topic: projects/my-project/topics/sshd-logs
    subscription:
      name: projects/my-project/subscriptions/sshd-logs-filebeat
      create: true
    credentials_file: /etc/filebeat/gcp-service-account.json
```

Full reference: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-gcp-pubsub.html

---

## Enabling Enforce Mode

By default, the response-system runs in `simulate` mode — it logs what *would* happen but does not modify iptables. The `docker-compose.prod.yml` override sets `RESPONSE_MODE=enforce`.

**What enforce mode does:**

When an alert triggers, the response-system executes:
```bash
iptables -A INPUT -s <source_ip> -j DROP
```

This requires the `NET_ADMIN` Linux capability, already granted in `docker-compose.yml`:
```yaml
cap_add:
  - NET_ADMIN
```

**Inspect active blocks:**
```bash
# On the Docker host
sudo iptables -L INPUT -n --line-numbers | grep DROP
```

**Remove a specific block manually:**
```bash
sudo iptables -D INPUT -s 185.220.101.45 -j DROP
```

**Flush all blocks** (use with caution):
```bash
sudo iptables -F INPUT
```

**Block duration:** Blocks are recorded with an `expires_at` timestamp in `soc-blocked-ips`. The response-system will not issue duplicate blocks for the same IP within `BLOCK_DURATION` seconds (default: 3600). However, iptables rules are not automatically removed at expiry — use a cron job or `ipset` with TTLs for automatic cleanup in production.

---

## Verification Checklist

After deployment, run through these checks:

```bash
# 1. All containers healthy
docker compose ps

# 2. ES indices exist with data
curl -s "http://localhost:9200/_cat/indices/soc-*?v" -u elastic:${ELASTIC_PASSWORD}

# 3. Detection rules are loaded
curl -s "http://localhost:8000/rules" | jq '.[].name'

# 4. Trigger a detection cycle and check for alerts
curl -s -X POST "http://localhost:8000/trigger" | jq .
sleep 5
curl -s "http://localhost:8000/alerts?size=5" | jq '.[].rule_name'

# 5. Check response-system health
curl -s "http://localhost:8001/health" | jq .

# 6. Verify RAG enricher has MITRE techniques indexed
curl -s "http://localhost:8003/health" | jq '.collection_count'
# Expected: 20+

# 7. Confirm field schema is correct for real logs
curl -s "http://localhost:9200/soc-logs-*/_mapping" -u elastic:${ELASTIC_PASSWORD} | \
  jq '.[] | .mappings.properties | keys'
# Expected fields: source_ip, status, action, log_type, command, username, hostname
```
