#!/usr/bin/env bash
# One-command entrypoint: fetch data -> detect -> triage -> metrics.
#
# Triage backend/model are configurable via env (defaults to local Ollama):
#   LLM_BACKEND=local_ollama LLM_MODEL=gemma4:12b-it-q8_0 LLM_NUM_CTX=32768 ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

DATASET="${DATASET:-apt3}"
export LLM_BACKEND="${LLM_BACKEND:-local_ollama}"
export LLM_MODEL="${LLM_MODEL:-gemma4:12b-it-q8_0}"
export LLM_MODE="${LLM_MODE:-evidence}"
export LLM_NUM_CTX="${LLM_NUM_CTX:-32768}"

echo "[1/4] Fetching dataset..."
bash data/fetch.sh

echo "[2/4] Running detection (Sigma rules -> matches)..."
uv run python -m src.detect --dataset "$DATASET"

echo "[3/4] Running triage ($LLM_MODEL via $LLM_BACKEND)..."
uv run python -m src.triage --dataset "$DATASET" --mode "$LLM_MODE"

echo "[4/4] Scoring..."
uv run python -m src.metrics --triage "data/triage_${DATASET}.json" --label "$LLM_MODEL"

echo "Done. Detection metrics in docs/results.md; per-model corpus in data/runs/."
