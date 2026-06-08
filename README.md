# detection-as-code

A reproducible **detection-as-code** pipeline that compiles Sigma rules to SQL,
runs them over Windows endpoint telemetry, and adds an **LLM triage layer** that
investigates each alert and produces a structured disposition — evaluated against
authoritative MITRE/OTRF APT3 emulation ground truth.

The detection decision is **deterministic**. The LLM is **advisory only** — it
investigates and explains, it never decides whether something is a detection, and
it is never the source of ground truth.

---

## What it does

```
Windows event logs (Sysmon / Security / PowerShell, JSON)
        │
        ▼
  [L1] Sigma rules ──(pySigma → SQLite)──►  alerts (deterministic match)
        │
        ▼
  LLM triage  ──(analyst + SQL-writer + adversarial reviewer)──►  disposition
        │                                                          (advisory)
        ▼
  metrics  ──(scored vs APT3 playbook ground truth)──►  precision / recall /
                                                         disposition accuracy
```

1. **Detection (L1).** Eight Sigma rules (discovery, execution, lateral movement)
   are compiled with pySigma and run against the logs loaded into an in-memory
   SQLite table. Matches are deterministic — that's the detection decision.
2. **Triage.** For each alert, an LLM investigates the surrounding telemetry and
   returns a structured `TriageResult`: a **disposition** (did bad occur?), scope,
   escalation call, and a responder handoff — all grounded in retrieved evidence.
3. **Scoring.** Results are scored against ground truth derived from the published
   APT3 operator playbook, never from the LLM.

### Detection rules

| Rule | ATT&CK | Severity |
|------|--------|----------|
| Net.exe Domain Reconnaissance | T1069.002 / T1087.002 | medium |
| Network Configuration Discovery via Ipconfig | T1016 | low |
| Whoami Reconnaissance | T1033 | low |
| VBScript Execution via CMD | T1059.005 | medium |
| WScript VBScript Execution | T1059.005 | medium |
| Remote Service Creation via SC.EXE | T1021.002 | high |
| PowerShell Encoded Command Execution | T1059.001 | medium |
| PowerShell Suspicious Launch Flags | T1059.001 | high |

---

## The LLM triage layer

The interesting part. Rather than ask one model to both reason *and* write SQL
(it does neither well), triage is a **two-role decomposition over a flattened
text protocol** — no native tool-calling, so any instruction-following model works:

- **Analyst** — reasons about the alert in plain language and asks for evidence in
  English (`QUESTION: the parent process and user of the net.exe run on HR001`).
  Never writes SQL, never sees the 250-column schema. Each turn it emits either a
  `QUESTION:` or its final JSON verdict.
- **SQL-writer** — a narrow, schema-pinned translator that turns one English
  question into one read-only `SELECT`, runs it, and returns shaped facts (≤20
  rows, ≤4 KB, explicit "0 rows", projected columns).

Wrapped around that:

- **Adversarial grounding** — a skeptic checks that every concrete claim in the
  verdict (users, hosts, processes, timestamps) is backed by a retrieved record;
  unsupported claims are challenged back to the analyst.
- **Zero-evidence guard** — a decisive verdict reached without retrieving *any*
  evidence is forced back to investigate (it's unsupported by construction).
- **Deterministic fallback** — if the LLM times out or returns unparseable output,
  a rule-metadata-only fallback produces a usable (dumber) result. The LLM is never
  load-bearing for the system staying up.

### Trust boundary

- Detection is deterministic (Sigma match); the LLM never makes it.
- Ground-truth labels come from `src/ground_truth.py` (the APT3 playbook), never
  the LLM.
- LLM output is schema-validated (Pydantic); malformed output is caught and routed
  to fallback.
- Every SQL query from the LLM is validated read-only before execution.

### Backends

The same pipeline runs on three backends via `LLM_BACKEND`:

| Backend | Transport | Notes |
|---------|-----------|-------|
| `local_ollama` | native `/api/chat` | honors `num_ctx`/`think`; default |
| `remote_ollama` | OpenAI-compatible | second machine / GPU box |
| `1min_ai` | `OneminClient` (custom REST) | hosted models; per-call credit metering |

See [docs/model-comparison.md](docs/model-comparison.md) for a cross-model and
cost comparison, and [docs/lessons-learned.md](docs/lessons-learned.md) for the
hard-won notes on building reliable LLM agents.

---

## Quickstart

Requires [uv](https://github.com/astral-sh/uv) and a local
[Ollama](https://ollama.com) (for the default backend).

```bash
# 1. Fetch the pinned OTRF APT3 dataset
bash data/fetch.sh

# 2. Run detection (Sigma rules → matches)
uv run python -m src.detect --dataset apt3

# 3. Triage the matches (local Ollama, 32K context)
LLM_BACKEND=local_ollama LLM_MODEL=gemma4:12b-it-q8_0 LLM_NUM_CTX=32768 \
  uv run python -m src.triage --dataset apt3 --mode evidence

# 4. Score
uv run python -m src.metrics --triage data/triage_apt3.json --label gemma4:12b
```

Tests and lint:

```bash
uv run pytest tests/
uv run ruff check src tests
```

---

## Results

> Detection-layer metrics are generated into [docs/results.md](docs/results.md).
> Triage-layer numbers below are from the headline run (`gemma4:12b-it-q8_0`,
> 32K context, full 25-alert APT3 set).

<!-- RESULTS:25-ALERT -->
| Metric | Value |
|--------|-------|
| Verdict accuracy (did-bad-occur vs playbook) | **88.0%** (22/25) |
| True-positive recall | **0.917** |
| True-positive precision | **0.957** |
| Uncertain rate | 0% |
| Fallback rate | 0% |
| Mean confidence — correct vs wrong | 0.955 vs 0.90 |

All 23 unambiguous malicious steps — `net.exe` domain recon, `sc.exe` remote service
creation, encoded/abusive PowerShell — were dispositioned correctly. **All three
errors fall on the benign-vs-malicious boundary**, the hardest call:

- `whoami /groups` → called malicious @ 1.0 (it is the lone true-negative): a confident **false positive** (the model over-calls the one benign case).
- two `WScript` executions → called `benign_true_positive` @ 0.85 (both are real attack steps): **false negatives**.

The model confirms obvious malice reliably; every miss clusters on **benign-closure** —
and with a single true-negative in an all-TP set, that axis is barely testable here
(see Limitations). Run on the 225 W-capped 3090 at 32K context; no fallbacks fired.
<!-- /RESULTS -->

**Ground truth:** scored against the OTRF/MITRE APT3 operator playbook
(`data/ground_truth/apt3_attack_steps.json`, built from the published Mordor
playbook). Of the 25 matched alerts (the triage eval set), **24 are true positives
and 1 is a false positive** (`whoami /groups` — the rule over-fires versus the
documented `/all` step).

> Two scoring lenses, deliberately kept distinct: the **detection layer**
> ([docs/results.md](docs/results.md)) scores *events* against the playbook with a
> conservative known-benign-images set (precision 100%, recall 22.1% — our 8 rules
> target a focused slice of the campaign, not full coverage; the `whoami /groups`
> case is *excluded* there as ambiguous rather than counted as a benign FP). The
> **triage layer** below scores *per-alert dispositions* across the 25 matches,
> where that same case is the lone negative — which is exactly why this set can't
> measure specificity (see Limitations).

---

## Honest limitations

This is a portfolio project, and the limitations are part of the point — knowing
what a number *can't* tell you is the job.

- **Ground-truth circularity.** The rules and the ground-truth labels both derive
  from the same observed APT3 procedure. Scores reflect performance on a known
  campaign, not generalization to unseen attacks.
- **The eval set is ~all true positives** (24 TP / 1 FP). With almost no negatives,
  the set **cannot measure specificity or risk-score calibration** — a model that
  labels *everything* malicious scores ~96%. Disposition accuracy here mostly
  measures "does it correctly refuse to dismiss a real attack," not discrimination.
- **Training contamination.** The Mordor APT3 dataset is public and widely written
  up (distinctive `shire\` host/user names). Models may *recognize* the scenario
  rather than reason from the logs, so accuracy partly measures recall, not
  analysis. **Grounding** is the contamination-resistant signal — whether a verdict
  is tied to retrieved evidence holds regardless of what the model memorized.
- **Telemetry scope.** Only Sysmon EID 1 (process creation) is scored. Roughly a
  dozen in-memory APT3 techniques (the Empire `winenum` module, keylogging) run
  in-agent and spawn no process — they exist in the PowerShell logs but are outside
  the scored subset by construction.
- **Static replay.** No MTTD / time-to-detect is reported; this is replay data, not
  a live stream.

## Future work

A rigorous evaluation — and a more realistic detection architecture — would add:

- **A contamination-resistant, class-balanced eval** by mixing multiple labeled
  sources (e.g. `splunk/attack_data`, our APT3/APT29) onto a shared timeline, with
  ground truth by provenance, plus a small **synthetic slice of benign IT-admin
  activity that trips the rules** (the hard negatives no public dataset provides).
- **Risk-score calibration** as the primary triage metric — does the per-alert
  score rank-order reality so a downstream rule can threshold on it?
- **An L2 "meta-detection" layer** — a deterministic rule over *alerts keyed by
  entity over time* (risk-based alerting): accumulation across alerts is detection
  logic, not LLM memory.
- Scaling to APT29 and the full APT3 set, plus scope-accuracy scoring.
- **A schema-bounded evidence-assembly playbook** — replacing the generative per-turn
  analyst loop with *ask-every-data-bound-question → assemble all available evidence →
  confine a cheap local LLM to the gestalt did-bad judgment*, with a grounding gate for
  soundness and explicit reporting of absent telemetry. Rides on a mature
  detection/meta-detection layer; validating its benign-closure path is gated on the
  class-balanced eval above. Design note, supporting measurements, and a recorded
  adversarial critique in [docs/triage-methodology.md](docs/triage-methodology.md).

---

## Repo layout

```
rules/              Sigma detection rules (YAML)
src/
  detect.py         compile rules → run over logs → matches
  triage.py         LLM triage layer (analyst + SQL-writer + grounding)
  schema.py         Pydantic schemas (Disposition, TriageResult, query sandbox)
  ground_truth.py   playbook-backed labels (authoritative, never the LLM)
  build_ground_truth.py   Mordor playbook xlsx → attack-steps JSON
  metrics.py        detection + triage scoring, cross-model comparison
  triage_fallback.py      deterministic fallback path
  backends/onemin.py      1min.ai REST adapter + credit metering
data/               datasets (gitignored) + committed ground truth
docs/               results, model comparison, lessons learned
tests/              pytest suite (lint + tests run in CI)
```
