# How small can the SQL-writer model go?

Even under the schema-bounded-playbook future state (which pre-vets SQL), the generative
long-tail and an always-on local SQL component still need on-the-fly SQL. So: what is the
smallest model that produces *reasonable* SQL for the SQL-writer role?

Run with `scripts/sqlwriter_isolation.py` over 258 real analyst questions mined from the
APT3 corpus (all 8 rule types), driving the **real** SQL-writer path (`triage._get_evidence`:
same prompt, schema grounding with sample values, extraction, execution). Each candidate
query is scored against the query a **strong model** wrote for that same question
(opus / 31B / deepseek / gpt-oss), q8 throughout to hold quantization constant.

## Metrics
- **valid** — executes without error.
- **recall** — fraction of the *reference* rows the candidate returned (the "needle-in-set"
  measure; a correct-but-broader query still scores well). The load-bearing metric.
- **has_ref** — candidate is a full superset of the reference rows.
- **over_fetch** — candidate rows ÷ reference rows (guards against "win recall by dumping
  the table").
- **match** — exact result-set equality (strict).

## Results (degradation curve, true param size)

| model | size | valid | recall | has_ref | over_fetch | match | sec/call |
|-------|:----:|:-----:|:------:|:-------:|:----------:|:-----:|:--------:|
| qwen2.5-coder 1.5b | 1.5B | 95% | 0.31 | 30% | 1.0 | 26% | 1.3 |
| qwen2.5-coder 3b | 3.1B | 93% | 0.41 | 40% | 1.0 | 34% | 2.1 |
| gemma4 e2b | 5.1B | 98% | 0.48 | 45% | 1.0 | 30% | 12.4 |
| qwen2.5-coder 7b | 7.6B | 98% | 0.39 | 38% | 1.0 | 30% | 2.9 |
| gemma4 e4b | 8.0B | 99% | 0.47 | 45% | 1.0 | 39% | 11.8 |
| **gemma4 12b** | 11.9B | 99% | **0.67** | **66%** | 1.0 | 58% | 75.8 |
| gemma4 26b-a4b (MoE) | 25.8B | 99% | 0.59 | 55% | 1.0 | 42% | 57.4 |

## Findings

1. **Validity is solved at every size (93–99%).** The bottleneck is never syntax — it is
   *grounding*: small models write executable SQL that retrieves the wrong rows. This is
   the "silent wrong-evidence" risk, quantified.
2. **A knee at 12B, not a slope.** Everything ≤8B sits at 0.31–0.48 recall with no size
   gradient (2B beats 7B). 12B jumps to 0.67. The floor is between 8B and 12B; nothing
   below it approaches the known-good anchor.
3. **Code-tuning is the wrong lever.** General-instruct gemma beats every qwen-coder at
   equal/larger size — the task is schema-grounding, not code syntax. (Code tuning *did*
   buy speed: coder 1.3–2.9 s/call vs gemma 12–76 s.)
4. **Dense beats MoE.** 12B-dense (0.67) > 26B-a4b-MoE (0.59) — the MoE's ~4B active
   params behave like a small model, echoing the earlier triage sweep.
5. **Per-rule, small models break worst on PowerShell-encoded** (0.16–0.43, the
   decode/scriptblock queries) and hold up best on simple projections. Even 12B is only
   0.56 on net-recon (highest-variety) but 0.89–1.0 on wscript/vbscript/lateral.

## The metric's limit (read recall as *relative*, not pass/fail)

The 12B anchor — the model that scored 88% on the triage run — lands at **0.67, not ~1.0**,
because **correct SQL is non-unique**: two valid queries for the same question return
different row sets (projection / LIMIT / window differ). So recall-vs-reference *ranks*
models reliably (12B clearly separates) but **understates absolute correctness**, and a
"≥0.9" bar is unreachable even for a good model.

## Conclusion + the decisive next test

No cheap model does grounded SQL adequately — not for lack of SQL ability (95%+ valid) but
for lack of reliable *grounding*. The floor is ~12B-dense; code-tuning and MoE do not help.
This reinforces the methodology doc's §3: on-the-fly SQL is the fragile component, which
argues for either a 12B+ SQL-writer **or** pre-vetted/cached queries (the question bank).

Because recall-vs-reference deflates absolutes, the **decisive** test is end-to-end: a
**role-split** run (small SQL-writer feeding the 12B analyst) scored on triage accuracy.

## End-to-end validation (role-split triage) — the decisive result

Run with `scripts/rolesplit_sweep.sh` (per-role `SQLWRITER_MODEL` wiring; 12B analyst held
fixed, SQL-writer swept; both models co-resident via `OLLAMA_MAX_LOADED_MODELS=2`). 5
alerts (the first-5, all net-recon TPs; 12B-solo baseline = 5/5).

| SQL-writer | size | recall-vs-ref | end-to-end triage |
|---|:--:|:--:|:--:|
| gemma4 12b (control) | 12B | 0.67 | **100%** (5/5) |
| qwen2.5-coder 7b | 7.6B | 0.39 | **100%** |
| gemma4 e4b | 8B | 0.47 | **100%** |
| gemma4 e2b | 5.1B | 0.48 | **100%** |
| qwen2.5-coder 3b | 3.1B | 0.41 | **100%** |
| qwen2.5-coder 1.5b | 1.5B | 0.31 | **80%** (4/5) |

**1. Recall-vs-reference was too harsh — confirmed.** Every SQL-writer from **3B up**
held triage at **100%** despite ~0.4 recall against the reference query. Those queries
were *different but correct enough* for the analyst's verdict. So a **3B SQL-writer + 12B
analyst is viable** — a ~12× smaller, ~25× faster SQL component (3B ≈ 2 s/call vs 12B ≈
53 s/call) with **no triage-accuracy loss** on this slice. The recall study alone would
have wrongly rejected it; **the end-to-end test is what settles it.**

**2. The 1.5B floor failure is graceful, not dangerous.** It dropped to 80%, but the one
miss went to **`uncertain` + fallback** (conf 0.5) — *not* a confident wrong verdict. TP
precision stayed 1.0 (no false positives); the grounding/fallback guards caught the weak
evidence and degraded to "can't conclude." So even past the floor, the system fails safe.

**Practical floor: ~3B** (not the ~12B the recall metric implied), and below it the failure
is safe rather than silent.

**Caveats:** n=5, all easy net-recon TPs — tests the *common* case, not the hard
benign-closure alerts (the lone TN / wscript FNs) where SQL grounding may matter more, so
the floor could be higher there. 80% = 4/5, directional not robust. Natural next step: a
harder, mixed sample (and on the P40 box, a stronger 31B-dense analyst).
