#!/usr/bin/env bash
# One-command entrypoint: fetch data -> detect -> triage -> metrics
set -euo pipefail

echo "[1/4] Fetching dataset..."
bash data/fetch.sh

echo "[2/4] Running detection..."
python src/detect.py

echo "[3/4] Running triage..."
python src/triage.py

echo "[4/4] Computing metrics..."
python src/metrics.py

echo "Done. Results in docs/results.md"
