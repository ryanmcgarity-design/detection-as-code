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
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma4:31b-it-q4_K_M")
LLM_MODE = os.environ.get("LLM_MODE", "auto")   # tools | react | auto
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
        data = json.loads(text)
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
        timeout=LLM_TIMEOUT,
    )
    return response.choices[0].message.content or ""


def _triage_tools_loop(
    client: OpenAI,
    messages: list[dict],
    conn: sqlite3.Connection,
    queries_run: list[str],
) -> tuple[Optional[TriageResult], Optional[str]]:
    """Native function-calling loop. Returns (result, fallback_reason)."""
    while True:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            tools=[QUERY_TOOL_DEF],
            tool_choice="auto",
            timeout=LLM_TIMEOUT,
        )
        msg = response.choices[0].message

        if msg.tool_calls:
            messages.append(msg)
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                sql = args.get("sql", "")
                queries_run.append(sql)
                result = _execute_query(conn, sql)
                log.debug("Tool call sql=%s", sql[:80])
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result,
                })
            continue

        result = _parse_triage_result(msg.content or "", queries_run)
        if result is None:
            return None, "LLM returned unparseable or invalid output"
        return result, None


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
            log.debug("ReAct sql=%s", sql[:80])
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
) -> TriageRecord:
    """Run the agentic investigation loop for a single match."""
    queries_run: list[str] = []
    triage_result: Optional[TriageResult] = None
    fallback_reason: Optional[str] = None

    alert_text = (
        f"ALERT\n"
        f"Rule: {match['title']} ({match['rule']})\n"
        f"Time: {match['timestamp']}\n"
        f"Host: {match['computer']}\n"
        f"Process: {match['image']}\n"
        f"Command: {match['command_line']}\n"
        f"EventID: {match['event_id']} | Channel: {match['channel']}\n\n"
        f"DATABASE SCHEMA\n{schema_hint}"
    )

    if not LLM_BASE_URL and LLM_BACKEND == "local_ollama":
        fallback_reason = "LLM_BASE_URL not configured"
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


def main(dataset_key: str = "apt3") -> list[TriageRecord]:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    matches_file = output_path(dataset_key)
    if not matches_file.exists():
        raise FileNotFoundError(f"Matches not found: {matches_file} — run src/detect.py first")

    matches = json.loads(matches_file.read_text())
    log.info("Triaging %d matches from %s", len(matches), matches_file.name)

    dataset_path = DATASETS[dataset_key]
    events = load_events(dataset_path)
    schema_hint = _get_schema_hint(build_db(events))

    client = _make_client()
    n = len(matches)

    def _worker(args):
        idx, match = args
        conn = build_db(events)  # each thread gets its own in-memory DB
        log.info("[%d/%d] Triaging: %s — %s", idx + 1, n, match["rule"], match["timestamp"])
        record = triage_match(match, conn, client, schema_hint)
        verdict = record.triage.verdict if record.triage else "?"
        fallback = " [fallback]" if record.fallback_used else ""
        log.info("  -> verdict=%s priority=%s confidence=%.2f%s",
                 verdict,
                 record.triage.priority if record.triage else "?",
                 record.triage.confidence if record.triage else 0,
                 fallback)
        return idx, record

    workers = int(os.environ.get("TRIAGE_WORKERS", "1"))
    records: list[TriageRecord] = [None] * n
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_worker, (i, m)): i for i, m in enumerate(matches)}
        for future in as_completed(futures):
            idx, record = future.result()
            records[idx] = record

    out = DATA_DIR / f"triage_{dataset_key}.json"
    out.write_text(json.dumps([r.model_dump() for r in records], indent=2))
    log.info("Triage results written to %s", out)
    return records


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=list(DATASETS), default="apt3")
    parser.add_argument(
        "--mode", choices=["tools", "react", "auto"], default=None,
        help="Override LLM_MODE env var for this run",
    )
    args = parser.parse_args()
    if args.mode:
        LLM_MODE = args.mode
    main(args.dataset)
