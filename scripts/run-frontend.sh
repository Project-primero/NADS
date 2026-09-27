#!/usr/bin/env bash
# Start dashboard dev server. Usage: bash scripts/run-frontend.sh
set -euo pipefail
cd "$(dirname "$0")/../frontend"
npm run dev
