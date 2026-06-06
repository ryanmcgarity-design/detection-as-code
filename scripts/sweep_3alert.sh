#!/usr/bin/env bash
# 3-alert triage sweep across the four gemma4 models that fit a 32K KV cache.
# Each run: evidence mode (analyst + SQL-writer + adversarial grounding), 32K
# context, first 3 alerts. Writes a durable per-model corpus to data/runs/ and
# a per-model scorecard to data/runs/<model>__scorecard.txt.
set -euo pipefail
cd "$(dirname "$0")/.."

export LLM_MODE=evidence
export LLM_NUM_CTX=32768
export LLM_BACKEND=local_ollama

MODELS=(
  "gemma4:e4b-it-q8_0"
  "gemma4:12b-it-q8_0"
  "gemma4:26b-a4b-it-q8_0"
  "gemma4:31b-it-q4_K_M"
)

for M in "${MODELS[@]}"; do
  SAFE=$(echo "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo "================================================================"
  echo "MODEL: $M   (32K ctx, 3 alerts, evidence mode)"
  echo "================================================================"
  START=$(date +%s)
  LLM_MODEL="$M" uv run python -m src.triage --dataset apt3 --mode evidence --limit 3 \
    2>&1 | tee "data/runs/${SAFE}__apt3.log"
  END=$(date +%s)
  echo "ELAPSED ${M}: $((END-START))s"
  # Score this model's run before the next one overwrites the back-compat file.
  uv run python -m src.metrics --triage data/triage_apt3.json --label "$M" \
    2>&1 | tee "data/runs/${SAFE}__scorecard.txt"
done

echo "================================================================"
echo "CROSS-MODEL COMPARISON"
echo "================================================================"
uv run python -m src.metrics --compare
