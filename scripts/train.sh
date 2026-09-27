#!/usr/bin/env bash
# Train anomaly model. Usage: bash scripts/train.sh [dataset.csv]
set -euo pipefail
if [ $# -gt 0 ]; then
  /tmp/nadvenv/bin/python train_model.py --model hybrid --dataset "$1"
else
  /tmp/nadvenv/bin/python train_model.py --model hybrid
fi
