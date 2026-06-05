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
  natural language (`get_evidence("the parent process and user of X")`). Never sees
  SQL or the schema.
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

---

## Appendix — the config that worked (for reference, not gospel)

| Role | temp | thinking | max_tokens | notes |
|------|------|----------|-----------|-------|
| Analyst (reasoner) | 0.5 | on | 8192 | calls `get_evidence`; retry verdict w/ thinking off on empty |
| SQL-writer (specialist) | 0.0 | **off** | 2048 | schema-pinned w/ real sample values; never `SELECT *` |

- Result shaping: ≤20 rows **and** ≤4000 chars; explicit "0 rows"; no silent truncation.
- SQL guard: read-only, word-boundary keyword filter, single statement.
- Final-answer retry: ×2 with thinking off before deterministic fallback.
- Keep the model resident (no unload/reload); the client owns context.
