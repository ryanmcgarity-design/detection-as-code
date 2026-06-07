#!/usr/bin/env bash
# Single-alert (A1) cost comparison across big open-source models on 1min.ai.
# Same pipeline, same alert — isolates per-model credit cost. Sequential to avoid
# rate limits. Each run logs "1min.ai run cost: ... credits" at the end.
set -uo pipefail
cd "$(dirname "$0")/.."
export LLM_BACKEND=1min_ai LLM_MODE=evidence

MODELS=(
  "deepseek-reasoner"
  "meta/meta-llama-3.1-405b-instruct"
)

for M in "${MODELS[@]}"; do
  SAFE=$(echo "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo "================ COST RUN: $M (1 alert) ================"
  START=$(date +%s)
  LLM_MODEL="$M" uv run python -m src.triage --dataset apt3 --mode evidence --limit 1 \
    2>&1 | tee "data/runs/_1min_cost_${SAFE}.log"
  echo "WALLCLOCK ${M}: $(( $(date +%s) - START ))s"
  echo
done

echo "================ COST SUMMARY ================"
echo "gpt-oss-120b (prior run): 40079 credits / 16 calls"
for M in "${MODELS[@]}"; do
  SAFE=$(echo "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo -n "$M: "
  grep "run cost:" "data/runs/_1min_cost_${SAFE}.log" | tail -1 || echo "(no cost line — check log)"
done
