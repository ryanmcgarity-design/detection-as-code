#!/usr/bin/env bash
# Single-alert (A1) cost on the Llama 4 MoE models — replacing the retired 405B.
set -uo pipefail
cd "$(dirname "$0")/.."
export LLM_BACKEND=1min_ai LLM_MODE=evidence

for M in "meta/llama-4-maverick-instruct" "meta/llama-4-scout-instruct"; do
  SAFE=$(printf '%s' "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo "================ COST RUN: $M (1 alert) ================"
  START=$(date +%s)
  LLM_MODEL="$M" uv run python -m src.triage --dataset apt3 --mode evidence --limit 1 \
    2>&1 | tee "data/runs/_1min_cost_${SAFE}.log"
  echo "WALLCLOCK ${M}: $(( $(date +%s) - START ))s"
  echo
done
