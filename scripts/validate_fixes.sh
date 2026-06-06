#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LLM_MODE=evidence LLM_NUM_CTX=32768 LLM_BACKEND=local_ollama
for M in "gemma4:e4b-it-q8_0" "gemma4:26b-a4b-it-q8_0"; do
  SAFE=$(echo "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo "================ VALIDATE: $M ================"
  START=$(date +%s)
  LLM_MODEL="$M" uv run python -m src.triage --dataset apt3 --mode evidence --limit 3 \
    2>&1 | tee "data/runs/${SAFE}__apt3.log"
  echo "ELAPSED ${M}: $(( $(date +%s) - START ))s"
done
