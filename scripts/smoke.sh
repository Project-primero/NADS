#!/usr/bin/env bash
# One-shot smoke check against a running backend. Usage: bash scripts/smoke.sh [host:port]
set -euo pipefail
BASE="${1:-127.0.0.1:8000}"
check() { curl -sf -m 5 "http://$BASE$1" > /dev/null && echo "OK  $1" || { echo "FAIL $1"; exit 1; }; }
check /api/health
check /api/stats
check "/api/alerts?limit=5"
check /api/catalog
check /api/analytics/traffic
check /api/analytics/top-talkers
echo "smoke: all endpoints OK"
