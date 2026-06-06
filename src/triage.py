"""
LLM triage layer.

For each detection match the LLM is given:
  - The alert record
  - The logs table schema
  - A query_logs tool it can call freely

The LLM drives its own investigation — it decides what queries to run,
what context to gather, and how to interpret the evidence. After the
investigation loop the LLM returns a structured TriageResult.

Trust boundary (explicit):
  - The DETECTION DECISION is deterministic (Sigma match). The LLM never
    decides whether something is a detection.
  - Ground truth labels for scoring come from src/ground_truth.py, never
    from the LLM.
  - LLM output is ADVISORY TRIAGE METADATA only.
  - All LLM output is schema-validated (Pydantic). Malformed or hallucinated
    output is caught, logged, and routed to the deterministic fallback.
  - SQL queries from the LLM are validated read-only before execution.
  - The LLM never sees credentials, secrets, or data outside the logs table.

Invocation modes (LLM_MODE env var or per-model config):
  tools  — OpenAI function calling API (model must support it)
  react  — text-based Thought/Action/Observation loop (any model)
  auto   — try tools first; on "does not support tools" error, retry as react
"""

import json
import logging
import os
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import httpx
from openai import OpenAI
from pydantic import ValidationError

from src.detect import DATASETS, build_db, compile_rules, load_events, output_path
from src.ground_truth import is_malicious_process_creation
from src.schema import Disposition, QueryTool, TriageRecord, TriageResult
from src.triage_fallback import fallback_triage

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"

LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
# Native Ollama base (no /v1). The evidence pipeline uses /api/chat directly so
# that think:false and options (num_ctx, etc.) are actually honored — the
# OpenAI-compat /v1 endpoint silently drops them (Ollama issues #14820/#15288).
LLM_NATIVE_URL = os.environ.get("LLM_NATIVE_URL", "http://localhost:11434")
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma4:26b-a4b-it-q8_0")
LLM_MODE = os.environ.get("LLM_MODE", "evidence")   # evidence | tools | react | auto
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.5"))
# SQL-writer role runs deterministic (temp 0) — we want repeatable, correct SQL.
SQL_WRITER_TEMPERATURE = float(os.environ.get("SQL_WRITER_TEMPERATURE", "0.0"))
# Hard cap on tokens per turn. Bounds runaway generation (a model that never
# emits a stop token would otherwise generate until it fills the whole context
# window). Largest legitimate turn observed was ~4.5k (reasoning + 8 tool calls).
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "8192"))
# Context-window size (KV-cache). Sets num_ctx on every native call so VRAM is
# pinned regardless of the server's OLLAMA_CONTEXT_LENGTH default. Empty = leave
# to the server default. The model sweep sets this to 32768 (32K).
LLM_NUM_CTX = int(os.environ["LLM_NUM_CTX"]) if os.environ.get("LLM_NUM_CTX") else None
LLM_TIMEOUT = None  # no timeout — let the model run to completion
MAX_RESULT_ROWS = 20

# Remote Ollama (second machine / VPS)
LLM_REMOTE_URL = os.environ.get("LLM_REMOTE_URL", "")
LLM_REMOTE_KEY = os.environ.get("LLM_REMOTE_KEY", "ollama")

# TODO: 1min.ai backend — not implemented yet.
# When ready, set LLM_BACKEND=1min_ai and implement src/backends/onemin.py.
# Expected: OpenAI-compatible wrapper that maps their API to the standard interface.
LLM_BACKEND = os.environ.get("LLM_BACKEND", "local_ollama")  # local_ollama | remote_ollama | 1min_ai

SYSTEM_PROMPT_TOOLS = """\
You are a SOC analyst investigating Windows endpoint alerts. You have access to
a SQL database containing Windows event logs (Sysmon, Security, PowerShell).

For each alert you will:
1. Query the logs to gather context — parent process, user, host activity,
   surrounding events. You decide what to look for.
2. Return a JSON object with your findings.

The logs table has many columns. Useful ones include:
  Channel, EventID, TimeCreated, Computer, Image, CommandLine,
  ParentImage, ParentCommandLine, User, TargetImage, TargetProcessId,
  GrantedAccess, SourceImage, CallTrace

Use the query_logs tool to run SELECT queries. You may run multiple queries.
Limit results where possible (e.g. LIMIT 20).

When done, respond with ONLY a JSON object (no markdown, no explanation) in
this exact format:
{
  "summary": "<what happened in plain English, citing evidence>",
  "technique": "<ATT&CK technique ID e.g. T1059.001, or 'unknown'>",
  "technique_name": "<technique name>",
  "confidence": <0.0-1.0 float>,
  "priority": "<high|medium|low>",
  "verdict": "<true_positive|likely_false_positive|uncertain>",
  "reasoning": "<explanation citing specific evidence from your queries>",
  "queries_run": ["<sql1>", "<sql2>"]
}
"""

SYSTEM_PROMPT_REACT = """\
You are a SOC analyst investigating Windows endpoint alerts. You have access to
a SQL database containing Windows event logs (Sysmon, Security, PowerShell).

Investigate the alert by querying the database. Use this EXACT format for each step:

Thought: <what you want to find out>
Action: query_logs
Action Input: <a valid SQL SELECT query against the logs table>
Observation: <result will be filled in for you>

You may repeat Thought/Action/Action Input as many times as needed (up to 6 queries).
When you have enough evidence, end with:

Thought: <final reasoning>
Final Answer:
{
  "summary": "<what happened in plain English, citing evidence>",
  "technique": "<ATT&CK technique ID e.g. T1059.001, or 'unknown'>",
  "technique_name": "<technique name>",
  "confidence": <0.0-1.0 float>,
  "priority": "<high|medium|low>",
  "verdict": "<true_positive|likely_false_positive|uncertain>",
  "reasoning": "<explanation citing specific evidence from your queries>",
  "queries_run": ["<sql1>", "<sql2>"]
}

The logs table has many columns. Useful ones:
  Channel, EventID, TimeCreated, Computer, Image, CommandLine,
  ParentImage, ParentCommandLine, User, TargetImage, TargetProcessId,
  GrantedAccess, SourceImage, CallTrace

Always use SELECT queries. LIMIT results (e.g. LIMIT 20).
"""

QUERY_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "query_logs",
        "description": (
            "Run a read-only SQL SELECT query against the Windows event log database. "
            "Returns up to 20 rows as a JSON array."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "A SELECT query against the logs table.",
                }
            },
            "required": ["sql"],
        },
    },
}


# ── Dual-role decomposition (mode="evidence") ───────────────────────────────
# The ANALYST reasons about the alert and asks for evidence in plain English via a
# text protocol — each turn it emits either `QUESTION: <english>` or its final JSON
# verdict (no native tool-calling, so any instruction-following model works). A
# separate SQL-WRITER role (same model, temp 0, schema-pinned) translates each
# question into one projected, capped SELECT, runs it, and returns shaped facts.
# The analyst never writes SQL and never sees the 250-column schema. The loop is
# fresh-restate-each-turn: the client owns the conversation, so there is no
# accumulating tool-call history (which previously caused empty-output failures).

SYSTEM_PROMPT_ANALYST = """\
You are a SOC analyst performing initial triage of a Windows endpoint alert. A
separate data analyst has direct access to the host telemetry — you investigate by
asking for evidence in plain English. You do NOT write SQL or see the schema.

YOUR JOB — answer one question first, then scope only if needed:
1. DID BAD OCCUR?  Conclude exactly one disposition:
   - malicious_true_positive : the activity is real AND malicious — bad occurred
   - benign_true_positive    : the activity is real but benign/authorized — no bad
   - false_positive          : the detection misfired; the flagged activity didn't really happen — no bad
   - uncertain               : the evidence does not let you decide
   If bad did NOT occur, you are done — do not scope.

2. IF malicious_true_positive, scope the blast radius:
   - SYSTEMS involved (hostnames), USERS involved (accounts),
   - DATA/assets touched, and the TIME FRAME of the activity.

Then decide whether this warrants ESCALATION to an incident, and write the handoff
for the responders: your analysis, conclusion, and recommended next steps.

HOW TO INVESTIGATE — you respond with EXACTLY ONE of two things each turn:
  (a) To gather evidence, output a single line:
        QUESTION: <one plain-English evidence request>
      The data analyst runs it and the result is added to "EVIDENCE GATHERED SO FAR"
      on your next turn. Ask ONE question at a time.
  (b) When you can conclude, output ONLY your final JSON verdict (the object below).
Never output both a QUESTION and a verdict in the same turn.

- Be decisive and efficient. Gather what you need in a handful of TARGETED questions
  (aim for 6 or fewer), then conclude. Don't re-ask the same thing different ways.
- Ground EVERY statement ONLY in the evidence gathered. Never invent usernames,
  processes, hosts, or timestamps. If the evidence doesn't show it, say so.
- Use the telemetry available (listed below). For example: for a PowerShell alert,
  pull the script-block logs to see what actually executed in memory; for an
  execution alert, build the process tree and check the user's surrounding activity;
  for lateral movement, check authentication/logon events.
- Do NOT conclude a disposition before gathering at least some evidence.

The final JSON verdict format (output ONLY this object, no markdown, no other text):
{
  "disposition": "<malicious_true_positive|benign_true_positive|false_positive|uncertain>",
  "confidence": <0.0-1.0 float>,
  "technique": "<ATT&CK technique ID e.g. T1059.001, or 'unknown'>",
  "technique_name": "<technique name>",
  "summary": "<what happened, plain English, citing the evidence you gathered>",
  "reasoning": "<why this disposition — cite specific records>",
  "scope": {"systems": [], "users": [], "data": "", "timeframe": ""},
  "escalate": <true|false>,
  "escalation_rationale": "<why escalate or not>",
  "recommended_actions": ["<next step for the responders>"]
}
Fill scope only when the disposition is malicious_true_positive; otherwise leave it empty.
"""

SYSTEM_PROMPT_SQL_WRITER = """\
You are a database query specialist. Translate the SOC analyst's plain-English
request into ONE read-only SQLite SELECT against the `logs` table. The system
runs your query and returns the rows to the analyst.

Rules:
- SELECT only. Never modify data.
- NEVER use SELECT *. Always name the specific columns relevant to the request,
  and always include identifying columns when relevant: TimeCreated, Computer,
  User, Image, CommandLine, ParentImage, ParentCommandLine.
- Always end with LIMIT 20 (or fewer).
- Text matching: use LIKE with % wildcards on substrings, e.g.
  Image LIKE '%net.exe%' (matching is case-insensitive). Do NOT match full paths
  with '='.
- TimeCreated is ISO-8601 text (e.g. '2019-05-14T22:43:10.226Z'); filter time
  windows with BETWEEN '<start>' AND '<end>' on the string value.
- Use the exact value formats shown in the schema below.

Return ONLY the SQL query — no markdown fences, no explanation, no commentary.
"""

SYSTEM_PROMPT_REVIEWER = """\
You are a skeptical SOC reviewer auditing another analyst's triage conclusion for
hallucination. You are given (a) the analyst's verdict and (b) the COMPLETE set of
evidence records they actually retrieved — nothing else exists.

Your job: check that every CONCRETE factual claim in the verdict — usernames,
hostnames, process/image names, parent processes, command lines, timestamps — is
directly supported by a record in the evidence. Assume the analyst may have invented
or misremembered specifics. A claim is "unsupported" if no retrieved record backs it.
Do NOT flag general reasoning or ATT&CK technique opinions — only concrete factual
claims that the evidence does not show.

Respond with ONLY this JSON (no other text):
{
  "grounded": <true if every concrete claim is supported, else false>,
  "unsupported_claims": ["<specific claim not backed by any evidence record>", ...]
}
If everything checks out, return grounded=true with an empty list.
"""



def _make_client() -> OpenAI:
    """Build an OpenAI client for the configured backend."""
    if LLM_BACKEND == "remote_ollama":
        if not LLM_REMOTE_URL:
            raise ValueError("LLM_REMOTE_URL must be set for remote_ollama backend")
        return OpenAI(base_url=LLM_REMOTE_URL, api_key=LLM_REMOTE_KEY)

    if LLM_BACKEND == "1min_ai":
        from src.backends.onemin import make_client as onemin_make_client
        return onemin_make_client()  # type: ignore[return-value]

    # Default: local_ollama
    return OpenAI(
        base_url=LLM_BASE_URL or "http://localhost:11434/v1",
        api_key=os.environ.get("OPENAI_API_KEY", "ollama"),
    )


def _get_schema_hint(conn: sqlite3.Connection) -> str:
    cols = [row[1] for row in conn.execute("PRAGMA table_info(logs)").fetchall()]
    useful = [c for c in cols if c in {
        "Channel", "EventID", "TimeCreated", "Computer", "Image", "CommandLine",
        "ParentImage", "ParentCommandLine", "User", "TargetImage", "TargetProcessId",
        "GrantedAccess", "SourceImage", "CallTrace", "SourceProcessId",
        "LogonType", "SubjectUserName", "TargetUserName", "IpAddress",
    }]
    return f"Table: logs\nColumns (subset): {', '.join(useful)}\nTotal columns: {len(cols)}"


def _get_schema_for_writer(conn: sqlite3.Connection) -> str:
    """Rich schema for the SQL-writer role: key columns + real example values so
    it writes correct filters (right user format, time format, path style) the
    first time instead of guessing and looping on empty results."""
    cols = [row[1] for row in conn.execute("PRAGMA table_info(logs)").fetchall()]
    key = ["TimeCreated", "Computer", "Channel", "EventID", "Image", "CommandLine",
           "ParentImage", "ParentCommandLine", "User", "TargetImage", "GrantedAccess",
           "SourceImage", "LogonType", "SubjectUserName", "TargetUserName", "IpAddress"]
    key = [c for c in key if c in cols]
    lines = [
        "Table: logs — Windows Sysmon/Security/PowerShell event logs.",
        f"{len(cols)} columns total. Query ONLY these key columns "
        "(example values shown so you match the exact format):",
    ]
    for c in key:
        try:
            vals = [r[0] for r in conn.execute(
                f'SELECT DISTINCT "{c}" FROM logs '
                f"WHERE \"{c}\" IS NOT NULL AND \"{c}\" != '' LIMIT 3"
            ).fetchall()]
            sample = " | ".join(str(v)[:70] for v in vals)
        except Exception:
            sample = ""
        lines.append(f"  {c}" + (f" — e.g. {sample}" if sample else ""))
    return "\n".join(lines)


# Channel -> one-line description, so the analyst KNOWS what telemetry exists and
# can ask for it. Only channels actually present in the dataset are surfaced.
_TELEMETRY_DESCRIPTIONS = {
    "Microsoft-Windows-Sysmon/Operational":
        "Process execution, network connections, file & registry activity, image loads "
        "(what ran, parent process, command line, user, hashes).",
    "Microsoft-Windows-PowerShell/Operational":
        "PowerShell script-block & module logging — the actual code/cmdlets executed INSIDE "
        "PowerShell, including in-memory activity that spawns no process.",
    "Windows PowerShell":
        "PowerShell pipeline/engine execution details.",
    "Security":
        "Authentication & account events — logons (who/where/how, logon type), privilege use, "
        "account and group changes.",
    "Microsoft-Windows-WMI-Activity/Operational":
        "WMI activity — often lateral movement or persistence.",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall":
        "Host firewall events.",
    "Microsoft-Windows-Bits-Client/Operational":
        "BITS transfers — often used to download payloads.",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":
        "RDP / remote session events.",
    "System": "Windows system events (service installs, driver loads, etc.).",
}


def _get_telemetry_inventory(conn: sqlite3.Connection) -> str:
    """Top-level list of the telemetry types present in this dataset, so the analyst
    has awareness of what it can investigate (it can't ask for what it doesn't know
    exists). Derived from the data — generalizes to any dataset."""
    rows = conn.execute(
        "SELECT Channel, COUNT(*) FROM logs WHERE Channel IS NOT NULL "
        "GROUP BY Channel ORDER BY COUNT(*) DESC"
    ).fetchall()
    lines = ["TELEMETRY AVAILABLE for this environment (ask get_evidence about any of it):"]
    for ch, n in rows:
        desc = _TELEMETRY_DESCRIPTIONS.get(ch, "")
        lines.append(f"  - {ch} ({n:,} events)" + (f": {desc}" if desc else ""))
    return "\n".join(lines)


def _execute_query(conn: sqlite3.Connection, sql: str) -> str:
    try:
        validated = QueryTool(sql=sql)
    except ValidationError as e:
        return json.dumps({"error": f"Query rejected: {e}"})
    try:
        rows = conn.execute(validated.sql).fetchmany(MAX_RESULT_ROWS)
        if not rows:
            return json.dumps([])
        keys = rows[0].keys()
        return json.dumps([dict(zip(keys, row)) for row in rows], default=str)
    except Exception as e:
        return json.dumps({"error": f"Query failed: {e}"})


def _parse_triage_result(content: str, queries_run: list[str]) -> Optional[TriageResult]:
    try:
        text = content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        # Extract the first JSON object, ignoring any leading prose or model
        # control tokens (e.g. Gemma's <|tool_response> / <channel|> markers).
        # raw_decode parses one value from `start` and ignores trailing noise.
        start = text.find("{")
        if start == -1:
            raise ValueError("no JSON object found in model output")
        data, _ = json.JSONDecoder().raw_decode(text[start:])
        data["queries_run"] = queries_run
        return TriageResult(**data)
    except (json.JSONDecodeError, ValidationError, Exception) as e:
        log.warning("Failed to parse LLM output: %s | content: %.200s", e, content)
        return None


def _chat(client, messages: list[dict]) -> str:
    """Unified single-turn call supporting OpenAI client and OneminClient."""
    from src.backends.onemin import OneminClient
    if isinstance(client, OneminClient):
        return client.chat(LLM_MODEL, messages)
    response = client.chat.completions.create(
        model=LLM_MODEL,
        messages=messages,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
        timeout=LLM_TIMEOUT,
    )
    return response.choices[0].message.content or ""


LOOP_REPEAT_THRESHOLD = 3

def _dump_failure(messages: list[dict], raw_content: str, queries_run: list[str]) -> None:
    """Write the full conversation state + raw model output when parsing fails."""
    try:
        import time
        path = Path("/tmp") / f"triage_fail_{int(time.time())}.json"
        serializable = []
        for m in messages:
            if isinstance(m, dict):
                serializable.append(m)
            else:  # openai message object
                serializable.append({
                    "role": getattr(m, "role", "?"),
                    "content": getattr(m, "content", None),
                    "tool_calls": [
                        {"id": tc.id, "sql": json.loads(tc.function.arguments).get("sql", "")}
                        for tc in (getattr(m, "tool_calls", None) or [])
                    ],
                })
        path.write_text(json.dumps({
            "raw_content": raw_content,
            "n_messages": len(messages),
            "n_queries": len(queries_run),
            "messages": serializable,
        }, indent=2, default=str))
        log.warning("Failure context dumped to %s (%d messages)", path, len(messages))
    except Exception as e:
        log.warning("Could not dump failure context: %s", e)


def _triage_tools_loop(
    client: OpenAI,
    messages: list[dict],
    conn: sqlite3.Connection,
    queries_run: list[str],
) -> tuple[Optional[TriageResult], Optional[str]]:
    """Native function-calling loop. Returns (result, fallback_reason)."""
    query_counts: dict[str, int] = {}
    call_n = 0
    while True:
        call_n += 1
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            tools=[QUERY_TOOL_DEF],
            tool_choice="auto",
            temperature=LLM_TEMPERATURE,
            max_tokens=LLM_MAX_TOKENS,
            timeout=LLM_TIMEOUT,
        )
        usage = getattr(response, "usage", None)
        if usage:
            log.info(
                "call #%d tokens: prompt=%s completion=%s total=%s",
                call_n,
                getattr(usage, "prompt_tokens", "?"),
                getattr(usage, "completion_tokens", "?"),
                getattr(usage, "total_tokens", "?"),
            )
        msg = response.choices[0].message

        if msg.tool_calls:
            messages.append(msg)
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                sql = args.get("sql", "")
                queries_run.append(sql)
                query_counts[sql] = query_counts.get(sql, 0) + 1
                if query_counts[sql] >= LOOP_REPEAT_THRESHOLD:
                    log.warning("Loop detected: query repeated %d times — injecting challenge", query_counts[sql])
                    content = (
                        "You have run this exact query multiple times and already have these results. "
                        "What specific evidence are you still looking for? "
                        "Either run a more targeted query with a specific WHERE clause, "
                        "or provide your final verdict based on the evidence gathered so far."
                    )
                else:
                    result = _execute_query(conn, sql)
                    log.info("Tool call sql=%s", sql)
                    content = result
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })
            continue

        result = _parse_triage_result(msg.content or "", queries_run)
        if result is None:
            _dump_failure(messages, msg.content or "", queries_run)
            return None, "LLM returned unparseable or invalid output"
        return result, None


EVIDENCE_MAX_CHARS = 4000  # hard cap on evidence returned to the analyst per question
GROUNDING_ROUNDS = 2       # adversarial review -> challenge-back-to-analyst rounds
ZERO_EVIDENCE_RETRIES = 2  # times we force investigation on a decisive no-evidence verdict


def _zero_evidence_challenge() -> str:
    return (
        "You reached a decisive conclusion WITHOUT retrieving any evidence — you "
        "did not call get_evidence even once. You cannot know whether bad occurred "
        "without looking at the telemetry. Investigate now: call get_evidence to pull "
        "the actual records (the process tree, the user, surrounding activity, and the "
        "relevant logs for this alert), THEN give your verdict grounded in what you find."
    )


def _extract_sql(raw: str) -> str:
    """Pull a single SELECT statement out of the writer's reply (tolerates
    markdown fences, leading prose, and trailing commentary)."""
    text = raw.strip()
    if text.startswith("```"):
        parts = text.split("```")
        text = parts[1] if len(parts) >= 2 else text
        if text.lstrip().lower().startswith("sql"):
            text = text.lstrip()[3:]
    m = re.search(r"\b(SELECT|WITH)\b", text, re.IGNORECASE)
    if m:
        text = text[m.start():]
    if ";" in text:
        text = text[: text.index(";") + 1]
    return text.strip()


def _shape_evidence(question: str, result_json: str) -> str:
    """Turn raw query output into compact, factual evidence for the analyst —
    explicit empties, no silent truncation, hard size cap."""
    try:
        data = json.loads(result_json)
    except Exception:
        return result_json
    if isinstance(data, dict) and "error" in data:
        return (f"Query error ({data['error']}). The request may be ambiguous — "
                f"try rephrasing or asking something more specific.")
    if not data:
        return f"No matching records found for: {question}"
    note = ""
    if len(data) >= MAX_RESULT_ROWS:
        note = (f"\n(Showing the first {MAX_RESULT_ROWS} records; there may be more — "
                f"ask a more specific question to narrow it down.)")
    body = json.dumps(data, default=str)
    if len(body) > EVIDENCE_MAX_CHARS:
        body = body[:EVIDENCE_MAX_CHARS] + " …[truncated — ask for fewer columns or rows]"
    return f"{len(data)} record(s):\n{body}{note}"


def _ollama_chat(
    messages: list,
    *,
    tools: Optional[list] = None,
    think: Optional[bool] = None,
    temperature: Optional[float] = None,
    num_predict: Optional[int] = None,
) -> dict:
    """Call Ollama's native /api/chat. Stateless like /v1: the full `messages`
    array is sent each call. Returns the parsed response dict; response["message"]
    has `content` and optional `tool_calls`. `think` is only sent if explicitly
    set — by default we let the model do whatever it does."""
    options: dict = {}
    if temperature is not None:
        options["temperature"] = temperature
    # Runaway guard: cap generation per call. 8192 let the analyst ramble into a
    # 3-min thinking runaway; 4096 bounds it. Empty *verdicts* are a thinking
    # artifact fixed by the think=False verdict retry, not by a bigger budget.
    options["num_predict"] = num_predict if num_predict is not None else 4096
    if LLM_NUM_CTX is not None:
        options["num_ctx"] = LLM_NUM_CTX
    payload: dict = {
        "model": LLM_MODEL,
        "messages": messages,
        "stream": False,
    }
    if think is not None:
        payload["think"] = think
    if options:
        payload["options"] = options
    if tools:
        payload["tools"] = tools
    resp = httpx.post(f"{LLM_NATIVE_URL}/api/chat", json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    # Empty-result guard: a non-tool call (writer/reviewer) that comes back with no
    # content means the model thought itself out of answering. Re-issue once with
    # think=False so it actually responds. (Tool/analyst turns handle this in-loop.)
    msg = data.get("message") or {}
    if not tools and think is None and not (msg.get("content") or "").strip():
        log.info("empty result — re-issuing with think=False")
        payload["think"] = False
        resp = httpx.post(f"{LLM_NATIVE_URL}/api/chat", json=payload, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    return data


def _llm_chat(
    messages: list,
    client=None,
    *,
    think: Optional[bool] = None,
    temperature: Optional[float] = None,
    num_predict: Optional[int] = None,
) -> str:
    """Backend-agnostic single-turn chat — returns the assistant's text content.

    The flattened evidence loop uses plain text (no tool-calling), so any
    instruction-following model works:
      - local_ollama   -> native /api/chat (honors num_ctx / think)
      - remote_ollama  -> OpenAI-compatible client (think/num_ctx N/A)
      - 1min_ai        -> OneminClient, a CUSTOM REST API (NOT OpenAI-compatible:
                          /api/chat-with-ai, API-KEY header, promptObject.prompt);
                          no temperature/think knobs and no token-usage in the reply.

    Flip LLM_BACKEND to run the same loop locally or against a remote model.
    """
    if LLM_BACKEND == "local_ollama":
        data = _ollama_chat(messages, think=think, temperature=temperature,
                            num_predict=num_predict)
        return (data.get("message") or {}).get("content") or ""
    # Remote / OpenAI-compatible backends (remote_ollama, 1min_ai).
    return _chat(client, messages)


def _get_evidence(
    question: str,
    conn: sqlite3.Connection,
    schema_block: str,
    queries_run: list[str],
) -> str:
    """SQL-writer role: translate one English question -> SELECT, run it, shape it.
    Runs as an isolated conversation; logs the SQL for audit (queries_run)."""
    writer_messages = [
        {"role": "system", "content": SYSTEM_PROMPT_SQL_WRITER + "\n\nSCHEMA:\n" + schema_block},
        {"role": "user", "content": f"Analyst request: {question}"},
    ]
    try:
        data = _ollama_chat(writer_messages, temperature=SQL_WRITER_TEMPERATURE)
        raw = (data.get("message") or {}).get("content") or ""
    except Exception as e:
        return f"Could not generate a query ({type(e).__name__}). Rephrase the request."
    sql = _extract_sql(raw)
    if not sql:
        return f"No query could be generated for: {question}"
    queries_run.append(sql)  # audit trail — NOT shown to the analyst
    log.info("  evidence sql=%s", sql)
    result = _execute_query(conn, sql)
    return _shape_evidence(question, result)


MAX_EVIDENCE_ROUNDS = 8  # analyst question turns before we force a final verdict
_QUESTION_RE = re.compile(r"QUESTION:\s*(.+?)(?:\n\s*\n|\Z)", re.IGNORECASE | re.DOTALL)


def _extract_question(text: str) -> Optional[str]:
    """Pull the analyst's `QUESTION: <text>` request out of a turn, or None if the
    turn isn't a question (i.e. it's the final verdict). The contract is one-or-the-
    other, so we check the QUESTION marker first."""
    m = _QUESTION_RE.search(text or "")
    if not m:
        return None
    q = m.group(1).strip().strip("`").strip()
    if q.startswith("{"):  # a JSON verdict, not a question
        return None
    return q or None


def _render_analyst_state(
    alert_core: str,
    evidence_log: list[tuple[str, str]],
    directives: Optional[list[str]] = None,
) -> str:
    """Build the analyst's full per-turn state as plain text: the alert + the running
    evidence ledger + any reviewer directives. Re-sent fresh each turn (no
    accumulating assistant/tool messages), so there's no tool-call history to corrupt
    later turns and no model state to manage — the client owns the conversation."""
    parts = [alert_core, "", "=== EVIDENCE GATHERED SO FAR ==="]
    if evidence_log:
        for i, (q, ev) in enumerate(evidence_log, 1):
            parts.append(f"[Q{i}] {q}\n→ {ev}")
    else:
        parts.append("(none yet — you have not gathered any evidence)")
    for d in (directives or []):
        parts.append("\n=== REVIEWER NOTE ===\n" + d)
    parts.append(
        "\nRespond with EXACTLY ONE of:\n"
        "  QUESTION: <one plain-English evidence request>   — to investigate further\n"
        "  or your final JSON verdict object                — when you can conclude.\n"
        "Do not output both."
    )
    return "\n".join(parts)


def _force_verdict(
    analyst_system: str,
    alert_core: str,
    evidence_log: list[tuple[str, str]],
    queries_run: list[str],
    client=None,
) -> Optional[TriageResult]:
    """Stall recovery: a clean call with all evidence asking ONLY for the final JSON
    (thinking off for a direct answer). Used when the analyst returns neither a
    question nor a parseable verdict, or when the round budget is exhausted."""
    if evidence_log:
        ev = "\n\n".join(f"[Q{i}] {q}\n→ {e}" for i, (q, e) in enumerate(evidence_log, 1))
        ev_block = f"=== EVIDENCE GATHERED ===\n{ev}"
    else:
        ev_block = "(You gathered no evidence.)"
    closing = [
        {"role": "system", "content": analyst_system},
        {"role": "user", "content": (
            f"{alert_core}\n\n{ev_block}\n\n"
            "Output ONLY your final JSON verdict now, grounded in the evidence above "
            "— no QUESTION, no preamble, no other text."
        )},
    ]
    try:
        content = _llm_chat(closing, client, think=False, temperature=LLM_TEMPERATURE)
    except Exception as e:
        log.warning("forced verdict call failed: %s", e)
        return None
    return _parse_triage_result(content, queries_run)


def _triage_evidence_loop(
    analyst_system: str,
    alert_core: str,
    conn: sqlite3.Connection,
    schema_block: str,
    queries_run: list[str],
    evidence_log: list[tuple[str, str]],
    client=None,
    directives: Optional[list[str]] = None,
) -> tuple[Optional[TriageResult], Optional[str]]:
    """Flattened analyst loop (no tool-calling). Each turn is a fresh 2-message call
    (system + the restated alert/evidence state). The analyst replies with either a
    `QUESTION:` (translated to SQL by the writer role, result appended to the ledger)
    or the final JSON verdict. Any instruction-following model works, and the
    tool-call protocol's empty-output failure modes are gone by construction.
    Records each (question, evidence) into evidence_log for grounding review."""
    for rnd in range(MAX_EVIDENCE_ROUNDS):
        state = _render_analyst_state(alert_core, evidence_log, directives)
        messages = [
            {"role": "system", "content": analyst_system},
            {"role": "user", "content": state},
        ]
        content = _llm_chat(messages, client, temperature=LLM_TEMPERATURE)
        log.info("analyst turn #%d content_len=%d", rnd + 1, len(content or ""))

        question = _extract_question(content)
        if question:
            log.info("Evidence q=%r", question[:100])
            ev = _get_evidence(question, conn, schema_block, queries_run)
            evidence_log.append((question, ev))
            directives = None  # a reviewer directive is consumed once acted on
            continue

        result = _parse_triage_result(content, queries_run)
        if result is not None:
            return result, None

        # Neither a question nor a parseable verdict — force the verdict directly.
        forced = _force_verdict(analyst_system, alert_core, evidence_log, queries_run, client)
        if forced is not None:
            return forced, None
        log.info("analyst turn #%d: no question, no verdict — restating", rnd + 1)

    # Round budget exhausted — one last forced verdict before giving up.
    forced = _force_verdict(analyst_system, alert_core, evidence_log, queries_run, client)
    if forced is not None:
        return forced, None
    _dump_failure(
        [{"role": "system", "content": analyst_system},
         {"role": "user", "content": _render_analyst_state(alert_core, evidence_log, directives)}],
        "", queries_run,
    )
    return None, "analyst did not produce a verdict within the round budget"


def _grounding_challenge(unsupported: list[str]) -> str:
    bullets = "\n".join(f"- {c}" for c in unsupported[:8])
    return (
        "A reviewer audited your verdict against ONLY the evidence you actually "
        "retrieved and flagged these claims as unsupported by any record:\n"
        f"{bullets}\n\n"
        "Either call get_evidence to retrieve records that support these claims, or "
        "revise your verdict to remove/correct anything the evidence does not show. "
        "Then respond with ONLY your final JSON verdict."
    )


def _adversarial_review(
    alert_core: str,
    result: TriageResult,
    evidence_log: list[tuple[str, str]],
) -> Optional[dict]:
    """Skeptic pass: are the verdict's concrete claims actually supported by the
    evidence the analyst retrieved? Returns {'grounded', 'unsupported_claims'} or
    None on error/no-evidence (treated as 'cannot challenge')."""
    if not evidence_log:
        return None
    transcript = "\n\n".join(f"Q: {q}\nEVIDENCE: {ev}" for q, ev in evidence_log)
    verdict_text = (
        f"VERDICT\nsummary: {result.summary}\n"
        f"technique: {result.technique} ({result.technique_name})\n"
        f"disposition: {result.disposition} | escalate: {result.escalate} | confidence: {result.confidence}\n"
        f"reasoning: {result.reasoning}"
    )
    user = (
        f"{alert_core}\n\n{verdict_text}\n\n"
        f"=== EVIDENCE THE ANALYST RETRIEVED (the only data that exists) ===\n{transcript}"
    )
    try:
        data = _ollama_chat(
            [
                {"role": "system", "content": SYSTEM_PROMPT_REVIEWER},
                {"role": "user", "content": user},
            ],
            temperature=LLM_TEMPERATURE,
        )
        raw = (data.get("message") or {}).get("content") or ""
    except Exception as e:
        log.warning("Adversarial review failed: %s", e)
        return None
    start = raw.find("{")
    if start == -1:
        return None
    try:
        data, _ = json.JSONDecoder().raw_decode(raw[start:])
    except Exception:
        return None
    return {
        "grounded": bool(data.get("grounded", True)),
        "unsupported_claims": [str(c) for c in (data.get("unsupported_claims") or [])],
    }


def _triage_react_loop(
    client: OpenAI,
    messages: list[dict],
    conn: sqlite3.Connection,
    queries_run: list[str],
) -> tuple[Optional[TriageResult], Optional[str]]:
    """
    ReAct text loop. Parses Thought/Action/Action Input/Final Answer from plain text.
    Works with any instruction-following model, no tool calling required.
    """
    while True:
        text = _chat(client, messages).strip()
        messages.append({"role": "assistant", "content": text})

        # Check for Final Answer
        fa_match = re.search(r"Final Answer:\s*(\{.*\})", text, re.DOTALL | re.IGNORECASE)
        if fa_match:
            result = _parse_triage_result(fa_match.group(1), queries_run)
            if result is None:
                return None, "LLM Final Answer failed schema validation"
            return result, None

        # Parse Action / Action Input
        action_match = re.search(
            r"Action:\s*query_logs\s*\nAction Input:\s*(.+?)(?:\nObservation:|$)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if action_match:
            sql = action_match.group(1).strip().strip("`")
            queries_run.append(sql)
            observation = _execute_query(conn, sql)
            log.info("ReAct sql=%s", sql)
            messages.append({
                "role": "user",
                "content": f"Observation: {observation}",
            })
            continue

        # No action and no final answer — prompt for continuation
        messages.append({
            "role": "user",
            "content": (
                "Continue your investigation. Use the Thought/Action/Action Input format "
                "to query the database, or provide your Final Answer if ready."
            ),
        })


def triage_match(
    match: dict,
    conn: sqlite3.Connection,
    client: OpenAI,
    schema_hint: str,
    mode: str = LLM_MODE,
    schema_writer: str = "",
    capture: Optional[dict] = None,
    telemetry: str = "",
) -> TriageRecord:
    """Run the agentic investigation loop for a single match."""
    queries_run: list[str] = []
    triage_result: Optional[TriageResult] = None
    fallback_reason: Optional[str] = None

    alert_core = (
        f"ALERT\n"
        f"Rule: {match['title']} ({match['rule']})\n"
        f"Time: {match['timestamp']}\n"
        f"Host: {match['computer']}\n"
        f"Process: {match['image']}\n"
        f"Command: {match['command_line']}\n"
        f"EventID: {match['event_id']} | Channel: {match['channel']}"
    )
    alert_text = alert_core + f"\n\nDATABASE SCHEMA\n{schema_hint}"

    if not LLM_BASE_URL and LLM_BACKEND == "local_ollama":
        fallback_reason = "LLM_BASE_URL not configured"
    elif mode == "evidence":
        analyst_system = SYSTEM_PROMPT_ANALYST + ("\n\n" + telemetry if telemetry else "")
        evidence_log: list[tuple[str, str]] = []
        grounding_rounds = 0
        grounding_unsupported: list[str] = []
        zero_evidence_rounds = 0
        try:
            triage_result, fallback_reason = _triage_evidence_loop(
                analyst_system, alert_core, conn, schema_writer,
                queries_run, evidence_log, client,
            )
            # Zero-evidence guard: a DECISIVE verdict reached without gathering any
            # evidence is unsupported by construction — the adversarial reviewer can't
            # refute claims when there's no evidence to check against (it returns
            # "cannot challenge"). Force the analyst to actually investigate. The
            # challenge is passed as a reviewer directive into the restated state.
            # (Caught gemma4:e4b A3 — a confident 'benign' call with zero queries.)
            while (triage_result is not None and not evidence_log
                   and triage_result.disposition != Disposition.UNCERTAIN
                   and zero_evidence_rounds < ZERO_EVIDENCE_RETRIES):
                zero_evidence_rounds += 1
                log.warning("Decisive verdict with ZERO evidence — forcing investigation (round %d)",
                            zero_evidence_rounds)
                triage_result, fallback_reason = _triage_evidence_loop(
                    analyst_system, alert_core, conn, schema_writer,
                    queries_run, evidence_log, client,
                    directives=[_zero_evidence_challenge()],
                )
            # Adversarial grounding: a skeptic checks the verdict's concrete claims
            # against the gathered evidence; unsupported claims are challenged back
            # to the analyst (as a reviewer directive) to revise or gather support.
            for rnd in range(1, GROUNDING_ROUNDS + 1):
                if triage_result is None:
                    break
                review = _adversarial_review(alert_core, triage_result, evidence_log)
                if not review or review["grounded"] or not review["unsupported_claims"]:
                    break
                grounding_rounds = rnd
                grounding_unsupported = review["unsupported_claims"]
                log.warning("Grounding round %d — unsupported: %s", rnd, review["unsupported_claims"])
                triage_result, fallback_reason = _triage_evidence_loop(
                    analyst_system, alert_core, conn, schema_writer,
                    queries_run, evidence_log, client,
                    directives=[_grounding_challenge(review["unsupported_claims"])],
                )
        except Exception as e:
            fallback_reason = f"LLM error: {type(e).__name__}: {e}"
            log.warning("LLM call failed for rule=%s: %s", match.get("rule"), e)
        if capture is not None:
            capture["evidence_trail"] = [{"question": q, "evidence": ev} for q, ev in evidence_log]
            capture["grounding_rounds"] = grounding_rounds
            capture["grounding_unsupported"] = grounding_unsupported
            capture["zero_evidence_rounds"] = zero_evidence_rounds
    else:
        system_prompt = SYSTEM_PROMPT_REACT if mode == "react" else SYSTEM_PROMPT_TOOLS
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": alert_text},
        ]

        try:
            if mode == "react":
                triage_result, fallback_reason = _triage_react_loop(
                    client, messages, conn, queries_run
                )
            elif mode == "tools":
                triage_result, fallback_reason = _triage_tools_loop(
                    client, messages, conn, queries_run
                )
            else:  # auto
                try:
                    triage_result, fallback_reason = _triage_tools_loop(
                        client, messages, conn, queries_run
                    )
                except Exception as e:
                    err = str(e).lower()
                    if "does not support tools" in err or "tool" in err:
                        log.info("Model does not support tools, retrying with ReAct: %s", LLM_MODEL)
                        messages = [
                            {"role": "system", "content": SYSTEM_PROMPT_REACT},
                            {"role": "user", "content": alert_text},
                        ]
                        queries_run.clear()
                        triage_result, fallback_reason = _triage_react_loop(
                            client, messages, conn, queries_run
                        )
                    else:
                        raise

        except Exception as e:
            fallback_reason = f"LLM error: {type(e).__name__}: {e}"
            log.warning("LLM call failed for rule=%s: %s", match.get("rule"), e)

    if triage_result is None:
        reason = fallback_reason or "unknown"
        triage_result = fallback_triage(match, reason)
        return TriageRecord(
            **match,
            triage=triage_result,
            fallback_used=True,
            fallback_reason=reason,
        )

    return TriageRecord(**match, triage=triage_result, fallback_used=False)


def main(dataset_key: str = "apt3", limit: Optional[int] = None) -> list[TriageRecord]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    matches_file = output_path(dataset_key)
    if not matches_file.exists():
        raise FileNotFoundError(f"Matches not found: {matches_file} — run src/detect.py first")

    matches = json.loads(matches_file.read_text())
    if limit is not None:
        matches = matches[:limit]
    log.info("Triaging %d matches from %s", len(matches), matches_file.name)

    dataset_path = DATASETS[dataset_key]
    events = load_events(dataset_path)
    db0 = build_db(events)
    schema_hint = _get_schema_hint(db0)
    schema_writer = _get_schema_for_writer(db0)
    telemetry = _get_telemetry_inventory(db0)

    client = _make_client()
    n = len(matches)

    records: list[TriageRecord] = [None] * n
    cases: list[dict] = []
    for i, match in enumerate(matches):
        conn = build_db(events)
        log.info("[%d/%d] Triaging: %s — %s", i + 1, n, match["rule"], match["timestamp"])
        capture: dict = {}
        record = triage_match(match, conn, client, schema_hint,
                              schema_writer=schema_writer, capture=capture,
                              telemetry=telemetry)
        disposition = record.triage.disposition if record.triage else "?"
        fallback = " [fallback]" if record.fallback_used else ""
        log.info("  -> disposition=%s escalate=%s confidence=%.2f%s",
                 disposition,
                 record.triage.escalate if record.triage else "?",
                 record.triage.confidence if record.triage else 0,
                 fallback)
        records[i] = record
        # "Case" record — the durable, per-model capture for cross-model + quality
        # analysis: the full assessment + the evidence trail it used + the grounding
        # outcome + the ground-truth label (from ground_truth.py, never the LLM).
        gt_malicious = is_malicious_process_creation(match.get("image", ""), match.get("command_line", ""))
        cases.append({
            "model": LLM_MODEL,
            "dataset": dataset_key,
            **record.model_dump(),
            "ground_truth_verdict": "bad" if gt_malicious else "no_bad",
            "evidence_trail": capture.get("evidence_trail", []),
            "grounding_rounds": capture.get("grounding_rounds", 0),
            "grounding_unsupported": capture.get("grounding_unsupported", []),
            "zero_evidence_rounds": capture.get("zero_evidence_rounds", 0),
        })

    # Back-compat single-file output (latest run)
    out = DATA_DIR / f"triage_{dataset_key}.json"
    out.write_text(json.dumps([r.model_dump() for r in records], indent=2))
    # Durable per-model case corpus — does NOT overwrite other models' runs.
    runs_dir = DATA_DIR / "runs"
    runs_dir.mkdir(exist_ok=True)
    safe_model = re.sub(r"[^A-Za-z0-9._-]", "_", LLM_MODEL)
    case_file = runs_dir / f"{safe_model}__{dataset_key}.json"
    case_file.write_text(json.dumps(cases, indent=2, default=str))
    log.info("Triage results -> %s ; case corpus -> %s", out, case_file)
    return records


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=list(DATASETS), default="apt3")
    parser.add_argument(
        "--mode", choices=["evidence", "tools", "react", "auto"], default=None,
        help="Override LLM_MODE env var for this run",
    )
    parser.add_argument("--limit", type=int, default=None, help="Only triage the first N matches")
    args = parser.parse_args()
    if args.mode:
        LLM_MODE = args.mode
    main(args.dataset, limit=args.limit)
