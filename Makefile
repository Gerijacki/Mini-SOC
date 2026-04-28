.PHONY: up down build logs status test test-detection test-generator test-response \
        trigger alerts blocked reset-kibana demo

# ─── Stack ────────────────────────────────────────────────────────────────────

up:
	docker compose up --build -d
	@echo "Waiting for Kibana..."
	@sleep 5
	@echo "Kibana → http://localhost:5601  |  Detection API → http://localhost:8000"

down:
	docker compose down -v

build:
	docker compose build --no-cache

logs:
	docker compose logs -f

status:
	@echo "=== Containers ==="
	@docker compose ps
	@echo ""
	@echo "=== Log count ==="
	@curl -s http://localhost:9200/soc-logs-*/_count 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  soc-logs:        {d[\"count\"]:>6} docs')" || echo "  ES not ready"
	@curl -s http://localhost:9200/soc-alerts/_count 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  soc-alerts:      {d[\"count\"]:>6} docs')" || echo "  soc-alerts not ready"
	@curl -s http://localhost:9200/soc-blocked-ips/_count 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  soc-blocked-ips: {d[\"count\"]:>6} docs')" || echo "  soc-blocked-ips not ready"

# ─── SOC Operations ──────────────────────────────────────────────────────────

trigger:
	@echo "Triggering detection cycle..."
	@curl -s -X POST http://localhost:8000/trigger | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin), indent=2))"

alerts:
	@curl -s http://localhost:8000/alerts | python3 -c "import sys,json; data=json.load(sys.stdin); [print(f'[{a[\"severity\"].upper():8}] {a[\"rule_name\"]:30} {a[\"source_ip\"]:20} {a[\"@timestamp\"]}') for a in data]"

blocked:
	@curl -s http://localhost:8001/blocked | python3 -c "import sys,json; data=json.load(sys.stdin); [print(f'  {b[\"source_ip\"]:20} {b[\"reason\"]:30} {b[\"action_taken\"][:50]}') for b in data] if data else print('  No blocked IPs')"

reset-kibana:
	@echo "Re-running Kibana setup..."
	@docker compose run --rm kibana-setup

# ─── Tests ────────────────────────────────────────────────────────────────────

test: test-detection test-generator test-response
	@echo ""
	@echo "All tests complete."

test-detection:
	@echo "=== Detection API tests ==="
	cd detection-api && pip install -q -r requirements.txt && pytest tests/ -v

test-generator:
	@echo "=== Log Generator tests ==="
	cd log-generator && pip install -q -r requirements.txt && pytest tests/ -v

test-response:
	@echo "=== Response System tests ==="
	cd response-system && pip install -q -r requirements.txt && pytest tests/ -v

# ─── Demo helper ──────────────────────────────────────────────────────────────

demo:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  Mini SOC — Live Status"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@$(MAKE) status
	@echo ""
	@echo "Recent alerts:"
	@$(MAKE) alerts
	@echo ""
	@echo "Blocked IPs:"
	@$(MAKE) blocked
	@echo ""
	@echo "Detection API health:"
	@curl -s http://localhost:8000/health | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'  status={d[\"status\"]}  rules={d[\"rules_loaded\"]}  alerts_generated={d[\"alerts_generated\"]}  last_poll={d[\"last_poll\"]}')"
