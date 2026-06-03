"""
Tests for the triage layer: schema validation, fallback path, query sandboxing.
No network calls — LLM_BASE_URL is unset in CI.
"""

import json

import pytest
from pydantic import ValidationError

from src.schema import Priority, QueryTool, TriageResult, Verdict
from src.triage_fallback import fallback_triage
from src.triage import _execute_query, _parse_triage_result, triage_match
from src.detect import build_db


# --- Schema validation ---

def test_triage_result_valid():
    result = TriageResult(
        summary="PowerShell ran encoded command",
        technique="T1059.001",
        technique_name="PowerShell",
        confidence=0.9,
        priority=Priority.HIGH,
        verdict=Verdict.TRUE_POSITIVE,
        reasoning="Encoded command with Empire flags",
        queries_run=["SELECT * FROM logs LIMIT 1"],
    )
    assert result.technique == "T1059.001"
    assert result.confidence == 0.9


def test_triage_result_technique_normalized():
    result = TriageResult(
        summary="x", technique="t1059.001", technique_name="PS",
        confidence=0.5, priority=Priority.LOW,
        verdict=Verdict.UNCERTAIN, reasoning="x",
    )
    assert result.technique == "T1059.001"


def test_triage_result_invalid_confidence():
    with pytest.raises(ValidationError):
        TriageResult(
            summary="x", technique="T1059.001", technique_name="PS",
            confidence=1.5,  # out of range
            priority=Priority.HIGH, verdict=Verdict.TRUE_POSITIVE, reasoning="x",
        )


def test_triage_result_invalid_technique():
    with pytest.raises(ValidationError):
        TriageResult(
            summary="x", technique="notATechnique", technique_name="PS",
            confidence=0.5, priority=Priority.MEDIUM,
            verdict=Verdict.UNCERTAIN, reasoning="x",
        )


def test_triage_result_unknown_technique_allowed():
    result = TriageResult(
        summary="x", technique="unknown", technique_name="unknown",
        confidence=0.3, priority=Priority.LOW,
        verdict=Verdict.UNCERTAIN, reasoning="x",
    )
    assert result.technique == "unknown"


# --- Query sandboxing ---

def test_query_tool_rejects_non_select():
    with pytest.raises(ValidationError):
        QueryTool(sql="DROP TABLE logs")


def test_query_tool_rejects_insert():
    with pytest.raises(ValidationError):
        QueryTool(sql="INSERT INTO logs VALUES (1)")


def test_query_tool_rejects_delete():
    with pytest.raises(ValidationError):
        QueryTool(sql="DELETE FROM logs WHERE 1=1")


def test_query_tool_accepts_select():
    q = QueryTool(sql="SELECT * FROM logs LIMIT 5")
    assert q.sql == "SELECT * FROM logs LIMIT 5"


def _make_conn():
    events = [{
        "@timestamp": "2024-01-01T10:00:00Z",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "computer_name": "TEST",
        "event_data": {
            "Image": r"C:\Windows\system32\whoami.exe",
            "CommandLine": "whoami.exe /all",
            "ParentImage": r"C:\Windows\system32\cmd.exe",
            "User": "TEST\\user",
        },
    }]
    return build_db(events)


def test_execute_query_select_works():
    conn = _make_conn()
    result = _execute_query(conn, "SELECT CommandLine FROM logs LIMIT 1")
    rows = json.loads(result)
    assert isinstance(rows, list)
    assert len(rows) == 1
    assert "whoami.exe" in rows[0].get("CommandLine", "")


def test_execute_query_rejects_drop():
    conn = _make_conn()
    result = _execute_query(conn, "DROP TABLE logs")
    data = json.loads(result)
    assert "error" in data
    assert "rejected" in data["error"]


def test_execute_query_bad_sql_returns_error():
    conn = _make_conn()
    result = _execute_query(conn, "SELECT * FROM nonexistent_table")
    data = json.loads(result)
    assert "error" in data


# --- Fallback path ---

SAMPLE_MATCH = {
    "rule": "powershell_encoded_command",
    "title": "PowerShell Encoded Command Execution",
    "timestamp": "2024-01-01T10:00:00Z",
    "computer": "TEST-PC",
    "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "command_line": "powershell.exe -enc SQBFAFgA",
    "event_id": "1",
    "channel": "Microsoft-Windows-Sysmon/Operational",
}


def test_fallback_returns_triage_result():
    result = fallback_triage(SAMPLE_MATCH, reason="test")
    assert isinstance(result, TriageResult)
    assert result.verdict == Verdict.UNCERTAIN
    assert result.priority in (Priority.HIGH, Priority.MEDIUM, Priority.LOW)


def test_fallback_high_priority_for_high_rule():
    match = {**SAMPLE_MATCH, "rule": "powershell_suspicious_launch_flags"}
    result = fallback_triage(match, reason="no llm")
    assert result.priority == Priority.HIGH


def test_no_llm_uses_fallback():
    """With empty LLM_BASE_URL triage must use fallback without network calls."""
    import src.triage as triage_mod
    original = triage_mod.LLM_BASE_URL
    triage_mod.LLM_BASE_URL = ""
    try:
        conn = _make_conn()
        from src.triage import _get_schema_hint
        schema = _get_schema_hint(conn)
        record = triage_match(SAMPLE_MATCH, conn, None, schema)
        assert record.fallback_used is True
        assert record.triage is not None
        assert record.triage.verdict == Verdict.UNCERTAIN
    finally:
        triage_mod.LLM_BASE_URL = original


# --- Output parsing ---

def test_parse_valid_json():
    content = json.dumps({
        "summary": "test", "technique": "T1059.001",
        "technique_name": "PowerShell", "confidence": 0.8,
        "priority": "high", "verdict": "true_positive",
        "reasoning": "evidence found", "queries_run": [],
    })
    result = _parse_triage_result(content, [])
    assert result is not None
    assert result.technique == "T1059.001"


def test_parse_strips_markdown_fences():
    content = "```json\n" + json.dumps({
        "summary": "test", "technique": "unknown",
        "technique_name": "unknown", "confidence": 0.3,
        "priority": "low", "verdict": "uncertain",
        "reasoning": "unclear", "queries_run": [],
    }) + "\n```"
    result = _parse_triage_result(content, [])
    assert result is not None


def test_parse_invalid_json_returns_none():
    result = _parse_triage_result("this is not json", [])
    assert result is None


def test_parse_invalid_schema_returns_none():
    content = json.dumps({"summary": "incomplete"})
    result = _parse_triage_result(content, [])
    assert result is None
