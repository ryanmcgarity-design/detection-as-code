#!/usr/bin/env bash
# A1 retest WITH ledger shrink — gpt-oss-120b, Opus, deepseek-chat.
# Compares per-model credits vs the untrimmed baseline (gpt-oss = 40,079).
set -uo pipefail
cd "$(dirname "$0")/.."
export LLM_BACKEND=1min_ai LLM_MODE=evidence

for M in "openai/gpt-oss-120b" "claude-opus-4-7" "deepseek-chat"; do
  SAFE=$(printf '%s' "$M" | tr -c 'A-Za-z0-9._-' '_')
  echo "================ TRIM RETEST: $M (1 alert) ================"
  START=$(date +%s)
  LLM_MODEL="$M" uv run python -m src.triage --dataset apt3 --mode evidence --limit 1 \
    2>&1 | tee "data/runs/_1min_trim_${SAFE}.log"
  echo "WALLCLOCK ${M}: $(( $(date +%s) - START ))s"
  echo
done
