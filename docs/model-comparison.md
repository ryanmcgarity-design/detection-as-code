# Model Comparison — 3-Alert Triage Sweep

Evaluation of four local Gemma 4 variants on the LLM triage layer, scored against
the authoritative MITRE/OTRF APT3 emulation playbook (`src/ground_truth.py`).

## Setup

- **Task:** initial triage of the first 3 detection alerts — the `net.exe` domain
  reconnaissance trio. All three are documented APT3 operator steps, so ground truth
  for every one is **bad occurred** (a true positive):

  | Alert | Command | Playbook technique |
  |-------|---------|--------------------|
  | A1 | `net group "Domain Admins" /domain` | T1069 Permission Groups Discovery |
  | A2 | `net localgroup Administrators` | T1069 Permission Groups Discovery |
  | A3 | `net user /domain` | T1087 Account Discovery |

- **Pipeline:** evidence mode — Analyst (asks for evidence in plain English) +
  SQL-writer (schema-pinned translator) + adversarial grounding reviewer. The initial
  sweep used native tool-calling for the analyst's questions; it was later flattened to
  a text protocol (below). See [lessons-learned.md](lessons-learned.md).
- **Context:** 32K KV cache (`num_ctx=32768`), native Ollama `/api/chat`.
- **Scoring:** the disposition is collapsed to the one bit triage must answer —
  *did bad occur?* `malicious_true_positive` → bad; `benign_true_positive` /
  `false_positive` → no_bad; `uncertain` / fallback → undecided (counted wrong).

## Results (initial sweep)

| Model | Accuracy | Time | Notes |
|-------|----------|------|-------|
| **gemma4:12b-it-q8_0** (dense) | **3/3 (100%)** | 1334s (~22m) | thorough, clean — best value |
| **gemma4:31b-it-q4_K_M** (dense, Q4) | **3/3 (100%)** | 1732s (~29m) | most thorough (9 rounds/alert), slowest |
| gemma4:26b-a4b-it-q8_0 (MoE A4B) | 2/3 (67%) | 915s (~15m) | A2 lost to a harness bug (fixed — see below) |
| gemma4:e4b-it-q8_0 (dense, small) | 1/3 (33%) | 164s (~3m) | fast/shallow; A3 was a zero-evidence hallucination |

### Per-alert

| Alert | GT | E4B | 12B | 26B-A4B | 31B-Q4 |
|-------|----|-----|-----|---------|--------|
| A1 | bad | ✅ malicious | ✅ malicious | ✅ malicious | ✅ malicious |
| A2 | bad | ❌ uncertain | ✅ malicious | ❌ uncertain *(fallback)* | ✅ malicious |
| A3 | bad | ❌ benign | ✅ malicious | ✅ malicious | ✅ malicious |

### Cross-model agreement

- **agree + correct: 1** (A1 — every model nailed it)
- **agree + WRONG (shared blind spot): 0** ← the reassuring result: no alert where all
  models confidently agreed on a wrong answer. Errors concentrated in the weak models.
- **disagree: 2** (A2, A3 — where the strong models separated from the weak ones)

## Findings

1. **Dense beat sparse-MoE on both accuracy and robustness.** The dense 12B matched
   the 31B for accuracy at ~75% of the wall-clock and a quarter of the total params,
   and never tripped the token-budget runaway that cost the 26B-A4B its A2.
2. **Q4 quantization of the 31B was fully viable** — 100% accuracy, fit in 32K KV,
   no runaway. Its only cost was wall-clock.
3. **Investigation depth tracked accuracy.** The two 3/3 models did 7–9 evidence
   rounds per alert; E4B did 0–3 and was the only model to hallucinate. Depth is a
   usable quality signal.
4. **Two of the three wrong answers were harness bugs, not reasoning failures**
   (see below) — diagnosable only because of per-alert capture (evidence trail,
   grounding rounds, failure dumps).

## Fixes applied after the sweep

Both failures below were root-caused (see lessons-learned.md §9–§11) and fixed in
`src/triage.py`:

- **26B-A4B A2 → fallback** was *not* a reasoning failure. A stale `thinking`
  scratchpad carried forward in the message history corrupted the `think=False`
  recovery turn into empty output → fallback. Fix: strip `thinking` when appending
  assistant messages. Replay of the captured failure with the fix yields a correct
  `malicious_true_positive` — i.e. **2/3 → 3/3**.
- **E4B A3 → confident hallucinated `benign` with zero evidence queries** slipped
  past the grounding reviewer (which can only refute claims *against* retrieved
  records). Fix: a zero-evidence guard forces a decisive no-evidence verdict back to
  investigate before it's accepted.

### Post-fix validation (re-run on the tool-call architecture)

A third fix surfaced *during* validation: `think=False` over a history with many
empty-content tool-call turns *also* empties this model (independent of the stale
`thinking` field). Recovery is now a **clean closing call** (rebuild a minimal
system+alert+evidence prompt, ask only for the JSON). See lessons-learned.md §9.

| Model | Before | After fixes | Change |
|-------|--------|-------------|--------|
| gemma4:26b-a4b-it-q8_0 | 2/3 (A2 fallback) | **3/3 (100%)**, 0 fallback | A1+A2 runaways now recovered → correct `malicious_true_positive` |
| gemma4:e4b-it-q8_0 | 1/3 (A3 confident-benign, 0 queries) | 1/3 strict, but **A3 failure mode fixed** | zero-evidence guard forced investigation; A3 went confident-`benign` → `uncertain` + escalate (safe) |

E4B's score is unchanged by strict accuracy (it's a weak model), but the *dangerous*
failure mode is gone: it no longer confidently dismisses a real attack with zero
evidence — it now escalates as uncertain. That's the intended effect of the guard.

## Flattened text-protocol sweep (no tool-calling)

The analyst's native tool-calling transport was then replaced with a flattened text
protocol (ReAct-style `QUESTION:` / final-JSON, fresh-restate-each-turn — see
lessons-learned.md §12). Same models, same 3 alerts, same 32K KV.

| Model | Tool-call (orig → post-fix) | **Flattened** | Time (tool-call → flattened) |
|-------|-----------------------------|---------------|------------------------------|
| gemma4:12b-it-q8_0      | 3/3 | **3/3 (100%)** | 1334s → 2311s |
| gemma4:31b-it-q4_K_M    | 3/3 | **3/3 (100%)** | 1732s → 1705s |
| gemma4:26b-a4b-it-q8_0  | 2/3 → 3/3 | **3/3 (100%)** | 915s → 1786s |
| gemma4:e4b-it-q8_0      | 1/3 | **2/3 (67%)** | 164s → 536s |

Per-alert (flattened): A1 ✅ all four · A2 ✅ all four · A3 — only E4B wrong
(`false_positive` on a real attack); 12B/26B/31B all ✅. Cross-model:
agree+correct 2, **agree+WRONG (shared blind spot) 0**, disagree 1 (A3).

### What the flattened sweep showed

1. **Flattening removed the bug class — it didn't just patch it.** 26B-A4B needed all
   three fixes (stale-`thinking`, zero-evidence, closing-call) to reach 3/3 on
   tool-calling. On the flattened loop it hits **3/3 with none of that machinery** —
   the empty-output triggers came *from* the tool-call history, which no longer
   exists. Fixes #1 (thinking-strip) and #3 (closing-call) were reverted; the
   zero-evidence guard, runaway cap, SQL guards, and grounding stayed (they're logic,
   not protocol patches).
2. **Accuracy matched or beat tool-calling on every model** — E4B 1/3→2/3, the rest
   held at 3/3. The lone miss (E4B A3) is a weak-model reasoning miss, not an
   architecture failure.
3. **Bonus: no tool-calling anywhere → any instruction-following model works**,
   including non-tool-calling and remote models (1min.ai).
4. **Cost is wall-clock, and uneven.** The smaller/mid models slowed most (E4B 3.3×,
   12B 1.7×, 26B-A4B ~2×); the 31B was ~unchanged (it was already re-eval-bound from
   deep multi-round investigation). Source: fresh-restate re-sends the growing
   evidence ledger every turn, losing the tool-call path's prefix caching. Optimization
   lever when wanted: trim/summarize the echoed ledger.

**Bottom line:** the no-tool-calling redesign is same-or-better on accuracy across all
four models, removed two fixes' worth of complexity, and unlocks remote models — at a
wall-clock cost that's recoverable.
