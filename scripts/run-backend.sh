#!/usr/bin/env bash
# Start backend API. Usage: bash scripts/run-backend.sh [host] [port]
set -euo pipefail
HOST="${1:-127.0.0.1}"; PORT="${2:-8000}"
/tmp/nadvenv/bin/python -m uvicorn backend.main:app --host "$HOST" --port "$PORT"
