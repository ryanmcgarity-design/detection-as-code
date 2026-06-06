# Lessons Learned — Building Reliable LLM Agents

Hard-won notes from building the LLM triage layer of this project (local Gemma 4
MoE over detection alerts). The symptoms showed up on Gemma 4, but **none of these
are Gemma-specific** — they recur across reasoning models (Qwen3, DeepSeek-R1,
o1-style, etc.) and any agent that calls tools. Captured here so the next project
starts from the conclusion, not the three-day debug.

---

## 1. Split reasoning from structured generation (the "model split")

**The biggest single win.** One model asked to *both* reason about a problem *and*
emit precise structured output (SQL, JSON, an API call) does neither well. It
writes plausible-but-wrong queries, drowns its own context, and confabulates.

Decompose into roles, even if it's the **same model** with two prompts:

- **Analyst** — reasons in plain language, decides what to find out, asks for it in
  natural language ("the parent process and user of X"). Never sees SQL or the schema.
  (We carry the ask as a plain-text `QUESTION:` line, not a native tool call — see §12
  for why that's more robust.)
- **Specialist** — a narrow, mechanical translator (natural language → one SELECT),
  pinned to the schema, deterministic, returns shaped results.

Why it works: each role is tuned independently (temperature, thinking on/off,
prompt, token budget), failures are isolated to one role, and each role's context
stays small. The analyst reasons; the specialist translates. Neither juggles both.

This is the generic **orchestrator + worker/tool** pattern. Reach for it whenever a
task mixes open-ended reasoning with precise structured output. The split is free
(same model, two system prompts) — you don't need a second model to get the benefit.

## 2. A model confabulates about data it cannot see the shape of

Our analyst invented usernames (`jdoe`, `sally.jones`) and parent processes
(`cmd.exe`) that did not exist in the data. Root cause: it was writing filters
against columns it had only seen *names* for — never values. So it guessed, got
empty results, and filled the narrative from training priors.

**Fix: ground the generator with real example values.** We inject 2–3 real distinct
values per key column into the specialist's prompt (so it learns users look like
`SHIRE\nmartha`, timestamps are ISO-8601, image paths are full `C:\...` paths). The
moment it saw real values, it wrote correct filters *and* the analyst stopped
inventing — because it was handed facts instead of guessing.

Generalizes to any text-to-SQL / text-to-API over a schema the model can't observe:
**blind generation is confabulation.** Show it the data's shape.

## 3. Reasoning models spend their token budget *before* they answer

Modern models do hidden chain-of-thought. If `max_tokens` is too small, the model
burns the entire budget thinking and returns **empty content** with
`finish_reason: "length"`. We saw a SQL-writer return `''` at 512 tokens and a
perfect query at 2048 — same prompt, the only difference was room to finish thinking.

Tells: empty `content`, `finish_reason == "length"`, large `completion_tokens` with
nothing usable in `content`.

Two levers:
- **Mechanical sub-tasks** (SQL gen, JSON formatting) don't need to think — disable
  it (`think: false` / `/no_think` / `reasoning_effort: minimal`, model-dependent).
  Faster and removes the empty-output failure mode.
- **Reasoning tasks** need a *generous* budget. Don't cap them at a number sized for
  the answer alone — size it for thinking + answer.

And add a **retry on empty/unparseable final output** (re-prompt for just the answer
with thinking off) before giving up. Stochastic empties happen even with budget;
recover them instead of falling back. (Ours fired on ~2/3 of verdicts and recovered
every one.)

## 4. The model owns no state — you do

Chat-completion APIs are **stateless per request**. The server-side KV cache is a
*performance* optimization (it skips recomputing seen prefixes), not conversation
memory, and it can be evicted anytime. The canonical conversation is the `messages`
array *you* send.

Consequences:
- Role handoffs are clean by construction: the specialist runs as a separate
  throwaway `messages` array; the analyst's array sits untouched in your code and you
  append the shaped result back as the tool reply. Nothing is "lost."
- The only cost of interleaving two roles on one resident model is **KV-cache
  re-eval** (the analyst's prompt gets recomputed after the specialist's call
  overwrites the cache) — that's *latency*, not lost context. Separate
  models/GPUs avoid it; smaller contexts make it cheap.
- **Don't build "unload/reload the model between items to clear state"** — there is no
  cross-item state to clear (each item already starts from a fresh `messages` array).
  It just adds model-load latency for zero benefit. We chased a "KV contamination"
  theory for hours; it never existed.

## 5. Shape tool results — never hand an agent raw output

A single `SELECT *` on a 250-column table returned ~37k tokens **in one tool
result** — larger than the whole context window. The model lost the system prompt
and alert, then derailed ("please provide the alert details"). Crucially: **a bigger
context window only delays this** — the agent fills whatever you give it and
overflows anyway.

Make the tool boundary do the shaping:
- **Cap by bytes, not just rows.** Row caps don't bound wide tables.
- **Project columns** — never `SELECT *`. (Best enforced in the *specialist*, which
  is told to always name columns.)
- **Make "0 rows" explicit and distinct from "query failed."** If the agent can't
  tell an empty result from a broken query, it loops rewording the same request. This
  "flailing on empty" was half our failures.
- **No silent truncation.** Say "showing 20 of N; narrow the query" so the agent
  knows there's more.

## 6. A plumbing bug masquerades as a model problem

For most of the debug, the model "couldn't write good queries and kept reworking
them." The real cause was a **substring keyword filter**: our read-only SQL guard
rejected any query containing `CREATE`, and `CREATE` is a substring of the column
name `TimeCreated`. So *every time-windowed query was silently rejected* — and time
windows are the most natural investigative move. The model wasn't flailing; our
validator was lying to it.

Lessons: word-boundary match keyword filters (`\bCREATE\b`, not `"CREATE" in sql`).
And when an agent "behaves badly," **instrument the tool boundary and read exactly
what the tool received and returned before blaming the model.**

## 7. Instrument before theorizing

Every wrong root-cause theory this project died the moment we added a number:
- "It's KV-cache contamination" → disproved by switching models (failure persisted).
- "Context slowly accumulates to overflow" → disproved by per-call token logging
  (the success case used 7× *more* tokens than the failure case).
- "The model can't write queries" → disproved by dumping the tool inputs (it could;
  the validator was rejecting them).

Minimum instrumentation for any agent loop: **per-call token usage**
(prompt/completion/total + `finish_reason`), and a **failure dump** of the full
`messages` array + raw model output when parsing fails. Cheap to add, and they turn
"the model loses context" hand-waving into a measured fact. Don't theorize past the
data.

## 8. Quantization and packaging are part of the model's behavior

The *same* architecture behaved very differently across artifacts. A HuggingFace
GGUF run through llama.cpp wouldn't load at all (engine didn't know the arch); forced
onto the native engine with hand-copied chat-template directives, it leaked raw
control tokens (`<|tool_response>`, `<channel|>`) into output *and* ran away
generating until it filled the context. The vendor-packaged build of the same model
and quant was clean. Root cause was buried in GGUF metadata: a different embedded
chat template, tokenizer model, and EOS token.

Lesson: **a re-quant or re-package is not behavior-equivalent.** Validate the exact
artifact end-to-end (loads, stops cleanly, output parses) before trusting it — don't
assume "same model, smaller quant" behaves the same.

## 9. Never carry the model's `thinking` scratchpad forward in history

A native assistant response can include a `thinking` field (the hidden
chain-of-thought) alongside `content` and `tool_calls`. When the analyst made a
tool call, we appended the **raw** native message back into the conversation —
dragging that ~1.3k-char thinking block forward with it.

The damage showed up a turn later. On a `think=False` recovery turn (forcing the
final JSON verdict), the presence of a *historical* thinking block corrupted
generation: the model emitted ~68 tokens that vanished and returned
**empty `content`** (`done_reason: stop`, not `length` — so it looked like a clean
empty, not a truncation). That empty fell through to the deterministic fallback.
The correct verdict was reachable the whole time; the history was poisoning the
model with its own discarded scratchpad.

Proven by replaying the exact dumped `messages` array two ways: with the stale
`thinking` field → empty; with it stripped → a clean, parseable, **correct**
verdict. One model's fallback flipped to a correct `malicious_true_positive` from
this single change.

Lesson: **the `thinking` field is the model's private scratchpad for one turn, not
conversation.** When you append an assistant message to history, keep only
`role`, `content`, and `tool_calls` — drop `thinking`. Carrying it forward bloats
context at best and silently corrupts later turns at worst. (Corollary, learned the
hard way here: `think:false` was *not* broken on the endpoint — a probe with a clean
history answered fine. **Reproduce the failure with a minimal input before blaming
the model or the API.** The bug was ours.)

**Second, independent trigger — and the robust remedy.** Stripping `thinking` fixed
the short-history case but a longer one (4 tool-call rounds, two ~4 KB tool results)
*still* emptied on the recovery turn. Dump replay isolated it: `think=False` over a
history containing **multiple empty-content assistant tool-call turns** empties this
model — even with no `thinking` field present and a large token budget. The same
history with thinking left **on** produced the verdict fine. So `think=False` is
fragile in proportion to how many tool-call turns precede it.

Don't try to make the polluted history work. **Recover with a clean closing call:**
rebuild a minimal conversation — system prompt + the original task + all gathered
evidence rendered as plain text — and ask only for the final structured answer. It
has zero tool-call turns, so it sidesteps *both* empty-output triggers and recovered
reliably in every replay (and in both think modes). General principle: **when an
agent's live history won't yield the final answer, don't keep poking the history —
collapse what you learned into a fresh, minimal prompt and ask once more.**

> Epilogue: this whole section is a patch for failures that only exist because of the
> tool-call message history. We later made *every* turn a fresh, minimal restate (§12),
> which removed the failure modes by construction — and retired both patches above.

## 10. Absence of evidence is its own failure mode

We built an adversarial reviewer to catch hallucination: it checks every concrete
claim in the verdict against the records the analyst actually retrieved. It works —
*when there are records*. Its blind spot: it can only **refute claims against
evidence**, so "no evidence retrieved" reads as "no claims to dispute," and the
verdict sails through.

A small model exploited this exactly: it returned a confident (0.95) `benign`
disposition on a real attack having run **zero** evidence queries — pure
confabulation from training priors — and the grounding pass waved it through
because there was nothing to check against.

Lesson: **a decisive conclusion reached with no evidence is unsupported by
construction** — it's the *most* dangerous output (confident and ungrounded), not
the safest. Check for it separately from claim-level grounding: if the agent reaches
a decisive verdict (anything but "uncertain") with an empty evidence log, force it
back to investigate before accepting the answer. Don't let "nothing to refute" mean
"nothing wrong."

## 11. Separate process failures from reasoning failures before blaming the model

Three wrong answers in our model sweep looked like three dumb models. Two were
**harness bugs**, fixable in code with the model untouched:
- a token-budget runaway whose recovery was sabotaged by the stale `thinking` field
  (§9) — *not* the model failing to reason;
- a zero-evidence confabulation that grounding was blind to (§10) — a missing guard,
  *not* the model being incapable.

Only one was a genuine reasoning miss. Without per-alert capture (the evidence trail,
grounding rounds, and a full failure dump) you can't tell these apart — and you'll
"fix" the wrong thing (swap models, raise temperature) while the real bug persists.
**Triage your agent's failures the way you'd triage an alert: get the evidence first,
then attribute cause.**

## 12. Prefer a flattened text protocol over native tool-calling for agent loops

§9 and §10 were patches for failures that *originated in the native tool-call
representation* — the accumulating empty-content assistant tool-call turns that the
chat template chokes on. The structural fix was to stop using that representation at
all.

Because the client owns the conversation (§4), an agent loop doesn't need to grow a
tool-call message history. Each turn can be a **fresh, flattened restate**: one call
of `[system, user]` where the user message is the task + the running evidence ledger
as plain text, and the model replies with either `QUESTION: <plain english>` (the
worker answers, you append the result to the ledger) or its final structured answer.
ReAct, essentially — but the point here is what it *removes*:

- **The tool-call empty-output failure modes vanish by construction** — there are no
  empty-content assistant turns and no `thinking` field to carry forward (§9). On our
  worst-affected model, this took it from "needs three fixes to reach 3/3" to "3/3
  with none of them." We then deleted those two patches.
- **Any instruction-following model works** — no native tool-calling required. This is
  what lets the same loop run on small local models *and* remote / non-tool-calling
  endpoints (we point it at a custom REST API by swapping one backend dispatch).
- **You control the exact bytes the model sees each turn**, so thinking on/off,
  ledger trimming, and reviewer directives are all just text you compose.

The cost: re-sending the ledger every turn loses the tool-call path's server-side
prefix caching, so wall-clock rises with investigation depth (we saw 1.7–3.3× on
smaller models; ~1× on the model that was already re-eval-bound). The lever when you
need the speed back is to **trim or summarize the echoed ledger** — keep the latest
evidence verbatim and compress older turns. Accuracy was same-or-better across every
model in our sweep, so the trade bought robustness and model-portability for latency.

Reach for native tool-calling when you need its structured-call guarantees or the
model is specifically tuned for it; reach for the flattened protocol when you want
robustness, debuggability, and the freedom to run any model.

---

## Appendix — the config that worked (for reference, not gospel)

| Role | temp | thinking | notes |
|------|------|----------|-------|
| Analyst (reasoner) | 0.5 | on | flattened text loop — emits `QUESTION:` or final JSON; fresh restate each turn |
| SQL-writer (specialist) | 0.0 | **off** | schema-pinned w/ real sample values; never `SELECT *` |

- Loop: fresh-restate each turn (no accumulating tool-call history); bound rounds, then
  force a final verdict (§12).
- Result shaping: ≤20 rows **and** ≤4000 chars; explicit "0 rows"; no silent truncation.
- SQL guard: read-only, word-boundary keyword filter, single statement.
- Keep the model resident (no unload/reload); the client owns context.
- **Zero-evidence guard:** a decisive verdict with an empty evidence log is forced
  back to investigate before it's accepted (§10) — kept; representation-independent.
- Backend-agnostic chat dispatch: local native API / remote OpenAI-compatible / custom
  REST, selected by one env var — the flattened loop runs on all three.
- *Retired with the flatten (§12):* the stale-`thinking` strip and the clean-closing-
  call recovery (§9) — both were tool-call-history artifacts that no longer exist.
