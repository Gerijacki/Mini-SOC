import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Set defaults before any import so get_es_client() uses these
os.environ.setdefault("ES_HOST", "http://localhost:9200")
os.environ.setdefault("RESPONSE_MODE", "simulate")
os.environ.setdefault("INDEX_BLOCKED", "soc-blocked-ips")
os.environ.setdefault("BLOCK_DURATION", "3600")
