#!/usr/bin/env bash
# Role-split end-to-end test: hold the 12B-dense ANALYST fixed, sweep the SQL-WRITER
# across the model ladder, and score TRIAGE accuracy on the first N alerts. Answers the
# decisive question the recall-vs-reference floor study could not: does triage accuracy
# SURVIVE a small SQL-writer, or does mis-grounded evidence poison the verdict?
#
# Requires OLLAMA_MAX_LOADED_MODELS>=2 so the 12B analyst + the SQL-writer stay co-resident
# (no per-turn swap). Control (12b-SQL = solo baseline reproduction) runs first.
#
# Usage: ./scripts/rolesplit_sweep.sh [N_ALERTS]   (default 5)
set -u
ANALYST="gemma4:12b-it-q8_0"
SQLWRITERS=(
  "gemma4:12b-it-q8_0"                 # control: reproduces the solo baseline
  "qwen2.5-coder:7b-instruct-q8_0"
  "gemma4:e4b-it-q8_0"
  "gemma4:e2b-it-q8_0"
  "qwen2.5-coder:3b-instruct-q8_0"
  "qwen2.5-coder:1.5b-instruct-q8_0"
)
N="${1:-5}"
OUT="data/runs"
mkdir -p "$OUT"
SUMMARY="$OUT/_rolesplit_sweep_summary.txt"
: > "$SUMMARY"
echo "Role-split sweep: analyst=$ANALYST, N=$N alerts, $(date)" | tee -a "$SUMMARY"
echo "baseline (12b solo, first $N): all malicious_true_positive — see baseline_solo12b__scorecard.txt" | tee -a "$SUMMARY"
echo "" | tee -a "$SUMMARY"

for sqlw in "${SQLWRITERS[@]}"; do
  safe=$(printf '%s' "$sqlw" | tr -c 'A-Za-z0-9._-' '_')   # printf, not echo: no trailing-newline underscore
  tag="analyst=12b  sqlwriter=$sqlw"
  echo "================ $tag (n=$N) ================" | tee -a "$SUMMARY"
  LLM_BACKEND=local_ollama LLM_MODE=evidence LLM_NUM_CTX=32768 \
  LLM_MODEL="$ANALYST" SQLWRITER_MODEL="$sqlw" \
    uv run python -m src.triage --dataset apt3 --mode evidence --limit "$N" \
    > "$OUT/_rolesplit_${safe}.log" 2>&1
  # preserve this config's triage output before the next run overwrites it
  cp data/triage_apt3.json "$OUT/rolesplit_n${N}__sqlw_${safe}__triage.json"
  # full scorecard to disk, summary line to the combined file
  uv run python -m src.metrics --triage data/triage_apt3.json --label "12b+SQLw:$sqlw" \
    > "$OUT/rolesplit_n${N}__sqlw_${safe}__scorecard.txt" 2>&1
  grep -E "verdict_accuracy|TP recall|fallback_rate|uncertain" \
    "$OUT/rolesplit_n${N}__sqlw_${safe}__scorecard.txt" | tee -a "$SUMMARY"
  # count disposition flips vs the all-TP expectation on this slice
  echo "  per-alert: $(grep -cE '✓' "$OUT/rolesplit_n${N}__sqlw_${safe}__scorecard.txt" 2>/dev/null) correct / $(grep -cE '✗' "$OUT/rolesplit_n${N}__sqlw_${safe}__scorecard.txt" 2>/dev/null) wrong" | tee -a "$SUMMARY"
  echo "" | tee -a "$SUMMARY"
done

echo "Done. Summary: $SUMMARY ; per-config: $OUT/rolesplit_n${N}__*" | tee -a "$SUMMARY"
