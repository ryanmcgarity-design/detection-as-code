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

from openai import OpenAI
from pydantic import ValidationError

from src.detect import DATASETS, build_db, compile_rules, load_events, output_path
from src.schema import Priority, QueryTool, TriageRecord, TriageResult, Verdict
from src.triage_fallback import fallback_triage

log = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"

LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma4:26b-a4b-it-q8_0")
LLM_MODE = os.environ.get("LLM_MODE", "evidence")   # evidence | tools | react | auto
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.5"))
# SQL-writer role runs deterministic (temp 0) — we want repeatable, correct SQL.
SQL_WRITER_TEMPERATURE = float(os.environ.get("SQL_WRITER_TEMPERATURE", "0.0"))
# Hard cap on tokens per turn. Bounds runaway generation (a model that never
# emits a stop token would otherwise generate until it fills the whole context
# window). Largest legitimate turn observed was ~4.5k (reasoning + 8 tool calls).
LLM_MAX_TOKENS = int(os.environ.get("LLM_MAX_TOKENS", "8192"))
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
# The ANALYST reasons about the alert and asks for evidence in plain English.
# A separate SQL-WRITER role (same model, temp 0, schema-pinned) translates each
# question into one projected, capped SELECT, runs it, and returns shaped facts.
# The analyst never writes SQL and never sees the 250-column schema.

SYSTEM_PROMPT_ANALYST = """\
You are a SOC analyst investigating Windows endpoint alerts. A separate data
analyst has direct access to the Windows event-log database. You do NOT write
SQL and you do NOT see the schema.

To investigate, call get_evidence with a plain-English question describing exactly
what you want to know, for example:
  "the parent process, user, and timestamp of the net.exe execution on HR001 around 22:43"
  "every process this user ran on this host in the 5 minutes after the alert"
  "any access to lsass.exe or known credential-dumping tools on this host"
The data analyst runs the query and returns the matching records. Ask follow-up
questions until you have enough evidence to judge the alert.

Ground every statement ONLY in records returned by get_evidence. Never invent
usernames, process names, parent processes, or timestamps — if the evidence does
not show something, say so explicitly. If a question returns no records, try a
broader or differently-worded question before concluding.

When done, respond with ONLY a JSON object (no markdown, no explanation):
{
  "summary": "<what happened in plain English, citing evidence you retrieved>",
  "technique": "<ATT&CK technique ID e.g. T1059.001, or 'unknown'>",
  "technique_name": "<technique name>",
  "confidence": <0.0-1.0 float>,
  "priority": "<high|medium|low>",
  "verdict": "<true_positive|likely_false_positive|uncertain>",
  "reasoning": "<explanation citing specific records from get_evidence>"
}
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

EVIDENCE_TOOL_DEF = {
    "type": "function",
    "function": {
        "name": "get_evidence",
        "description": (
            "Ask the data analyst a plain-English question about the Windows event "
            "logs (e.g. 'the parent process and user of the net.exe run on HR001 at "
            "22:43'). Returns the matching log records. You never write SQL."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "A plain-English description of the evidence you want.",
                }
            },
            "required": ["question"],
        },
    },
}


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
FINAL_ANSWER_RETRIES = 2   # re-prompts for the JSON verdict before falling back


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


def _get_evidence(
    client: OpenAI,
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
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=writer_messages,
            temperature=SQL_WRITER_TEMPERATURE,
            # gemma4 reasons in a hidden (stripped) channel before answering, so
            # the budget must cover that pre-amble plus the SQL — 512 gets cut off
            # mid-think and returns empty. think=False trims it; 2048 ensures the
            # SQL actually lands.
            max_tokens=2048,
            extra_body={"think": False},
            timeout=LLM_TIMEOUT,
        )
        raw = response.choices[0].message.content or ""
    except Exception as e:
        return f"Could not generate a query ({type(e).__name__}). Rephrase the request."
    sql = _extract_sql(raw)
    if not sql:
        return f"No query could be generated for: {question}"
    queries_run.append(sql)  # audit trail — NOT shown to the analyst
    log.info("  evidence sql=%s", sql)
    result = _execute_query(conn, sql)
    return _shape_evidence(question, result)


def _triage_evidence_loop(
    client: OpenAI,
    messages: list[dict],
    conn: sqlite3.Connection,
    schema_block: str,
    queries_run: list[str],
) -> tuple[Optional[TriageResult], Optional[str]]:
    """Analyst loop: reasons in English, calls get_evidence; the SQL-writer role
    handles all SQL. Returns (result, fallback_reason)."""
    question_counts: dict[str, int] = {}
    call_n = 0
    final_retries = 0
    force_no_think = False
    while True:
        call_n += 1
        create_kwargs = dict(
            model=LLM_MODEL,
            messages=messages,
            tools=[EVIDENCE_TOOL_DEF],
            tool_choice="auto",
            temperature=LLM_TEMPERATURE,
            max_tokens=LLM_MAX_TOKENS,
            timeout=LLM_TIMEOUT,
        )
        if force_no_think:
            # gemma4 sometimes burns the whole turn on hidden thinking and emits
            # an empty final answer — force a direct response on the retry.
            create_kwargs["extra_body"] = {"think": False}
            force_no_think = False
        response = client.chat.completions.create(**create_kwargs)
        usage = getattr(response, "usage", None)
        if usage:
            log.info(
                "analyst call #%d tokens: prompt=%s completion=%s total=%s",
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
                question = args.get("question", "")
                question_counts[question] = question_counts.get(question, 0) + 1
                if question_counts[question] >= LOOP_REPEAT_THRESHOLD:
                    log.warning("Loop: question repeated %d times — injecting challenge", question_counts[question])
                    content = (
                        "You have already asked this exact question and have the results. "
                        "Either ask a more specific question, or give your final verdict now "
                        "based on the evidence gathered so far."
                    )
                else:
                    log.info("Evidence q=%r", question[:100])
                    content = _get_evidence(client, question, conn, schema_block, queries_run)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": content,
                })
            continue

        result = _parse_triage_result(msg.content or "", queries_run)
        if result is not None:
            return result, None
        # Empty / unparseable final answer (gemma4 thinking ate the turn, or a
        # stochastic empty). Re-prompt for the JSON verdict with thinking off,
        # a couple of times, before giving up to the deterministic fallback.
        if final_retries < FINAL_ANSWER_RETRIES:
            final_retries += 1
            log.warning("Empty/invalid final answer — retrying (%d/%d) with thinking off",
                        final_retries, FINAL_ANSWER_RETRIES)
            messages.append({
                "role": "user",
                "content": ("Respond NOW with ONLY the JSON verdict object described in your "
                            "instructions — no thinking, no preamble, no other text."),
            })
            force_no_think = True
            continue
        _dump_failure(messages, msg.content or "", queries_run)
        return None, "LLM returned unparseable or invalid output"


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
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_ANALYST},
            {"role": "user", "content": alert_core},
        ]
        try:
            triage_result, fallback_reason = _triage_evidence_loop(
                client, messages, conn, schema_writer, queries_run
            )
        except Exception as e:
            fallback_reason = f"LLM error: {type(e).__name__}: {e}"
            log.warning("LLM call failed for rule=%s: %s", match.get("rule"), e)
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

    client = _make_client()
    n = len(matches)

    records: list[TriageRecord] = [None] * n
    for i, match in enumerate(matches):
        conn = build_db(events)
        log.info("[%d/%d] Triaging: %s — %s", i + 1, n, match["rule"], match["timestamp"])
        record = triage_match(match, conn, client, schema_hint, schema_writer=schema_writer)
        verdict = record.triage.verdict if record.triage else "?"
        fallback = " [fallback]" if record.fallback_used else ""
        log.info("  -> verdict=%s priority=%s confidence=%.2f%s",
                 verdict,
                 record.triage.priority if record.triage else "?",
                 record.triage.confidence if record.triage else 0,
                 fallback)
        records[i] = record

    out = DATA_DIR / f"triage_{dataset_key}.json"
    out.write_text(json.dumps([r.model_dump() for r in records], indent=2))
    log.info("Triage results written to %s", out)
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
