# Triage Methodology — toward a schema-bounded evidence-assembly playbook

> **Status: design note / future work. Nothing here is implemented.** It captures a
> design discussion (2026-06-07) that was deliberately stress-tested point-by-point in
> an adversarial pass; what survived is recorded honestly in §9. The supporting scripts
> in `scripts/` are real and runnable; the architecture is not built. This is
> acknowledged scope creep relative to the original portfolio goal — kept because the
> cost finding, the needle-handling measurements, and the resulting (humbler) thesis are
> independently useful.

## 0. Thesis (one paragraph)

For a **defined dataset + ruleset**, the space of meaningful investigative questions is
finite — bounded by the **telemetry schema** (data types and fields), *not* by the
attack space. So replace the generative, per-turn analyst loop with a **deterministic
evidence-assembly playbook**: ask every data-bound question whose telemetry component is
present, assemble all available evidence, and confine a **cheap local LLM to the gestalt
"did bad occur?" judgment** over that evidence — with a grounding gate for soundness and
explicit reporting of any telemetry that was absent. The bank is grown **offline by a
more expensive model** and versioned like a detection rule. This is strong on
true-positive confirmation by construction; its one real runtime exposure is the judge
overlooking present-but-buried evidence (§9, R1).

## 1. Foundation: questions are schema-bound, not attack-bound

The load-bearing claim. You can only ask what the telemetry can express, and a novel
attack still has to land as artifacts in the **same finite set of fields**. A network
event is a 5-tuple + content; a process event is image/cmdline/parent/user/integrity;
etc. The question set therefore grows with **data source/type**, not with attacks or
data volume — and is enumerable **top-down from the schema**.

This is a stronger foundation than the earlier (discarded) framing of "cluster the
questions models have asked and watch the curve saturate." Saturation of *mined*
questions measures **model convergence**, not coverage of the question space, and models
share priors so it converges fast and means little. **Enumerate from the schema instead
of mining from the corpus** — that covers fields no past attack happened to make salient.
(Corpus mining is still useful, but for *ranking* which questions decide bad, not for
*discovering* the set.)

## 2. An observation about cost (not the justification)

Per-role token accounting across four metered models (`scripts/role_token_split.py` over
`data/runs/_1min_cost_*.log`): the **analyst/reasoning role is ~85% of cost**, the
SQL-writer 5–21%. The driver is the flattened protocol re-feeding the whole evidence
ledger each turn (≈ O(turns²); see `triage._render_analyst_state`).

| model | analyst | sql-writer | closing/other |
|---|:--:|:--:|:--:|
| deepseek-reasoner | 67% | 15% | 18% |
| gpt-oss-120b | 67% | 21% | 12% |
| llama4-scout | 76% | 7% | 17% |
| llama4-maverick | 78% | 5% | 17% |

Cost is **not** the real reason to do this — determinism, auditability, and reproducibility
are. But the number kills one tempting idea: *role-splitting* (SQL local, analyst remote)
relocates only the cheap 15% and leaves the expensive, latency-dominating analyst remote.
The real levers are (a) avoiding the analyst on easy alerts and (b) **removing the
generative loop itself**, which is what §3 does.

## 3. Architecture: exhaustive assembly + a judge (no selection problem)

The earlier open question was "which subset of questions to ask per alert?" — the
**selection function**. It is removed, not solved:

> **Ask all the questions whose data component is present; assemble everything; let the
> LLM judge over the full assembled evidence in a single pass.**

Deterministic SQL is cheap, so exhaustiveness is affordable. This simultaneously
eliminates (a) the selection function, (b) the multi-turn re-feed cost (one judgment
pass, not N growing turns), and (c) the need for build-time *attribution* ("which
question was load-bearing?") — you never prune to a minimal subset, so you never need to
know. It is the logical extreme of the coarse-granularity dial (fewer-fatter beats
more-leaner, given the O(turns²) re-feed).

Two qualifiers:
- **Gating is on what the alert indicates, and only for the did-bad phase.** If nothing
  in the alert implies a network component, the network questions aren't asked *up front*.
  This is a triage-efficiency gate, **not** a security boundary and **not** "absence of
  telemetry = benign": confirming bad has many paths, and once bad is affirmed you pivot
  to IR where everything is on the table. (It can't be weaponised by suppressing a
  telemetry source, because the triggering alert isn't in the suppressed branch and IR
  reopens everything.)
- **Bounded by context + enrichment budget.** "Assemble everything" is capped by the
  judge's context window and by external-enrichment rate limits. Within the cap this is
  fine; the residual at high cardinality is §9/R1 and §6.

## 4. Question categories — an explanation layer, not a router

The four categories describe *why* a question is asked; they are **not** an orthogonal
routing table (parent-chain is both context and scope — that's fine, because nothing
dispatches on them). The operative rule is "ask what's needed to decide bad."

| category | answers | from the telemetry? |
|---|---|---|
| **Context** (parent chain, normal-for-host, signed/path) | did bad | ✅ |
| **Scope** (blast radius, lateral, timeline) | how bad | ✅ mostly |
| **Internal intel** (privilege, asset criticality, history) | how bad | ⚠️ partial |
| **External intel** (IP/hash/domain rep, TTP attribution) | did bad | ❌ via enrichment |

External intel is **not** a design hole — enrichment (TI feeds, reputation) is standard
SOC plumbing, trivially integrated; its absence here is a *testbed* limitation. (It does
make the bank externally dependent and non-deterministic for that one class — name it.)

## 5. Evidence controls (corrected from the first draft)

`scripts/needle_probe.py` measured these on the APT3 data; the prescriptions below fix
errors in the original write-up.

- **Inclusion, not flagging.** The query's job is to ensure the bad artifact is *in* the
  returned set; deciding it's bad is the judge + enrichment. So a low-cardinality
  dimension → **return the full distinct set** (it's small: 918 connections → 47 IPs) and
  enrich — *not* "collapse to a count," which would bury a singleton C2. (Original draft
  had this backwards.)
- **Disjunctive sufficiency.** You only need **one** grounded malicious link to declare an
  incident, not every step. So a single high-cardinality blind spot (a busy server with
  thousands of distinct destinations you can't fully enrich) doesn't sink the call — a
  cleaner link elsewhere in the chain resolves it.
- **Correlation: keys over clocks.** Prefer `ProcessGuid`/`ParentProcessGuid` intra-host
  (needle-proof regardless of clock). Measured within-row skew: `UtcTime` vs
  `TimeCreated` median 18 ms but **p95 54 s** (+ semantic divergence per event-type;
  `@timestamp` is a redundant copy of `TimeCreated`). Cross-host correlation (lateral
  movement) is where GUIDs fail and you fall back to time+padding — but cross-host
  blast-radius is an **IR / meta-detection** concern, not a per-alert triage question.
- **Entropy/profile → context structuring, not truncation avoidance.** The cardinality
  profile's best use is shaping the judge's input (lead with profiles; place
  anomaly-ranked items where attention is strongest) to mitigate R1 — not deciding what
  to drop.

## 6. Complexity is conserved — this targets a mature SOC

Many of the clean answers above work by pushing the hard part into the **detection /
meta-detection layer**: recon-burst = a count-threshold rule (≥5 recon commands/hour);
rare parent→child = a detection; per-entity risk accumulation = risk-based alerting
(RBA) over alerts-keyed-by-entity-over-time. That is architecturally *right* — detection
is deterministic and testable, which is where you want the complexity — but be honest:
**this rides on a far richer detection layer than the 8 Sigma rules here today.** It
therefore assumes a **mature SOC** (or a bundled vendor stack — EDR/SIEM). For the
portfolio demo, "mature with outside help" concretely means **importing a real detection
corpus** (full Sigma / Elastic / Splunk ESCU), not hand-writing it.

## 7. What is actually novel (vs SOAR/SIEM)

This is substantially **RBA + a SOAR playbook with an LLM judge** — and saying so is what
keeps it credible. The defensible, narrow contribution is *where the LLM goes and how
cheaply*:

- **Not novel:** the question bank, gating, enrichment, deterministic retrieval (decades of SOAR/SIEM).
- **Defensible-novel:** a **cheap, local LLM as the gestalt judge** over deterministically
  *exhaustively-assembled* evidence, **confined to the did-bad decision**, **graded
  against playbook-derived ground truth**, with the bank **grown offline by an expensive
  model**. The contribution is the placement, the cost point, and that it can be scored
  honestly — not the playbook.

## 8. Sufficiency: "did we look hard enough?"

Answered by construction under §3. If you ask every data-bound question and assemble all
available evidence, sufficiency-over-available-data holds. The remaining failure modes
are **non-silent**:
- **Data not collected** → a *coverage* gap, surfaced by the per-entity telemetry profile,
  so a benign-closure reads "benign given available telemetry, with these declared blind
  spots." Honest, not falsely confident.
- **Data present but judge missed it** → R1.

This converts the old unfalsifiable runtime doubt ("were we thorough this time?") into a
**build-time invariant**: *is the bank complete over the schema?* — verifiable once,
offline, and checkable by a human. The **grounding/confidence gate** (already implemented:
the adversarial reviewer that tests the verdict against the gathered evidence) provides
**soundness** (verdict ⊨ evidence); sufficiency comes from exhaustiveness + absence
reporting. It does **not** require knowing which specific evidence "called bad."

## 8b. Operational context — the benign-closure enabler

Two non-telemetry sources answer what telemetry structurally cannot — *was this supposed
to happen?* — and so they are what actually closes alerts benign:
- **Prior alert resolution** (case-management system): has this entity/technique fired and
  been dispositioned before? A human-confirmed benign closure on the same
  host/user/pattern is strong evidence for `benign_true_positive`.
- **Current engineering / change tickets** (ITSM): is there an authorized change,
  maintenance, or pentest that *binds to this host/user/action/window*?

These are simply more schema-bound data sources (§1/§4, internal-intel class), assembled
into the evidence dump (§3) like any other. They are the affirmative evidence *for* benign
that directly arms R2 — the one axis the telemetry-only design could not decide.

**Risk treatment (these sources are attacker-influenceable; telemetry is less so):**
- *Outsider* — can't forge tickets (no ITSM access). The slow baseline-training attack
  (repeated benign-looking recon to earn auto-close) still **accumulates entity risk in
  the meta-detection layer**; the moment they expand or pivot, the accumulated count plus
  the new activity crosses threshold. Training-to-benign buys cover for the trained
  pattern only, while building a risk debt against the entity.
- *Insider* — can fully launder (real ticket + manager sign-off + avoid DLP and every
  other alarm). Possible, but by disjunctive sufficiency (§5) the defender needs **one**
  link to surface while the attacker must defeat **every** one; any single slip declares
  the incident, and the laundered ticket becomes evidence of premeditation. Long-tail,
  perfection-required.

**Why baseline-training fails (structural, not a fragile invariant):** detection
triggering operates on the **raw alert/event stream** and never consumes triage
disposition — X alerts over a window is X alerts regardless of how each was closed. And
dispositions are **provisional and reopenable**: when an outlier surfaces and elevates the
entity's visibility, the previously-auto-closed history is re-examined *in light of it*, so
the trained-benign pattern becomes **evidence**, not laundering. The one *legitimate* path from
resolution back to detection is **tuning**: persistent, frequent noise warrants turning
off that specific noisy detection for that specific case. That is safe and good hygiene —
because it is gated by **detection-engineering rigor** (deliberate, investigated, narrowly
scoped, time-boxed / periodically re-justified, documented), **not** automatic disposition
propagation; the malicious version still surfaces via other detections / the
meta-detection layer (defense-in-depth); and the tuning investigation is required
regardless. Done this way, a tuning exception is the **most trustworthy** form of
prior-resolution evidence for §8b's benign-closure — it carries rigor raw auto-closes
lack. The failure mode to avoid is the opposite: **broad, permanent, unreviewed exceptions
that rot into coverage gaps ("tuning debt")** — rigor is required at *creation and at
review*. What never to do: wire automatic *suppression* from dispositions so closed alerts
silently stop being counted; keep detection counting on the raw stream, and make every
suppression a reviewed, expiring, scoped tuning artifact.

**Operational rule:** these sources *inform* the judge, never *auto-resolve*. Trust only
**human-validated** prior resolutions (never the system's own unreviewed dispositions — an
echo chamber). Require **precise binding** of ticket/prior to host/user/action/window
(loose matching launders anything). Any benign verdict leaning on them is still subject to
the grounding gate (it must actually be supported by a ticket/prior that *binds*).

## 9. Risks / open problems (what survived the adversarial pass)

- **R1 — the needle moves from retrieval to judgment.** With "assemble everything," a
  present needle can be lost in a long context (lost-in-the-middle). This is the **one
  genuine runtime residual**. It is *measurable* (inject a known needle into a large
  assembled dump; measure judge recall) and *mitigable* (structure the context per §5:
  profiles first, anomaly-ranked items in high-attention positions; cap assembled size to
  the judge's reliable window).
- **Build-time invariant — schema-completeness of the bank.** "Ask all the questions"
  means *provably complete enumeration over the schema*, not "all the questions we
  happened to bank." Atomic-question completeness is tractable (§1/§4); relational/temporal
  completeness rides on the detection layer (§6). Verify it offline; it is not a runtime
  uncertainty.
- **R3 — legitimate-access abuse (narrowed).** Authorized *access* ≠ authorized *pattern*:
  abuse of legitimate capability usually surfaces not as an unauthorized action but as an
  anomalous **aggregate** — volume / destination / frequency — caught at the **DLP /
  data-movement** and **behavioral (UEBA)** layers ("$20k/week to your own account" flags
  despite full permission). So R3 reduces to a **mature-SOC detection-coverage dependency**
  (§6: the detection layer must include DLP + UEBA), not "undetectable." The **irreducible
  tail** is harm that leaves *no anomalous trace at any layer* — read-only misuse, a single
  in-pattern fraudulent/destructive action, out-of-band exfil (screen photos),
  tuned-below-threshold low-and-slow. That is the universal limit of telemetry-based
  detection ("can't detect what leaves no trace"), not specific to this design; accumulating
  variants are still caught *eventually* by risk surfacing (§8b), if not timely.
- **Validation dependency — benign-closure needs hard negatives.** APT3 is **all-TP**, so
  a checklist always looks good and benign-closure is untestable on it. The
  class-balanced eval in the README's Future Work (mixed labeled sources + a **synthetic
  benign-IT-admin slice that trips the rules**) is a **blocking prerequisite**: build the
  eval first, then the bank is falsifiable. The highest-leverage next step is a small
  hard-negative slice — it tests the one axis the architecture is weakest on and the one
  APT3 cannot exercise.

## 10. Supporting scripts (built this session, runnable)

| script | what it does |
|---|---|
| `scripts/role_token_split.py` | per-role token/credit split from 1min.ai cost logs (the §2 table) |
| `scripts/needle_probe.py` | clock-skew + entropy/cardinality probe on the dataset (the §5 numbers) |
| `scripts/sqlwriter_isolation.py` | tests whether a small model can do the SQL-writer role: generated/valid/nonempty + exact-match/overlap vs a trusted reference query. Run AFTER a sweep (loads models → GPU). Note: under the §3 "ask everything" design the SQL-writer largely becomes pre-vetted/cached queries, so this harness now mainly informs *whether on-the-fly SQL is even needed* for the long tail. |

## 11. Provenance

This document is the residue of a structured adversarial debate: every component (finite
set, categorization, the controls, the discovery method, the cost argument) was attacked,
and most objections were either conceded, scoped to a mature-SOC assumption, or collapsed
into R1 + the two §9 items. The idea is not "a finite question set"; it is the humbler,
sturdier claim in §0.
