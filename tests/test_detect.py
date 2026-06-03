"""
Tests for the detection layer. Runs against a small in-memory fixture so CI
does not need the full 28MB dataset.
"""

import json
import sqlite3

import pytest

from src.detect import build_db, compile_rules, flatten_event, run_detections

# Minimal synthetic events that should trigger specific rules
FIXTURE_EVENTS = [
    {
        "@timestamp": "2024-01-01T10:00:00.000Z",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "computer_name": "TEST-PC",
        "event_data": {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -noP -sta -w 1 -enc SQBFAFgA",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe",
            "User": "TEST\\user",
        },
    },
    {
        "@timestamp": "2024-01-01T10:01:00.000Z",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "computer_name": "TEST-PC",
        "event_data": {
            "Image": "C:\\Windows\\system32\\whoami.exe",
            "CommandLine": "whoami.exe /all /fo list",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
            "ParentCommandLine": "cmd.exe",
            "User": "TEST\\user",
        },
    },
    {
        "@timestamp": "2024-01-01T10:02:00.000Z",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "event_id": 1,
        "computer_name": "TEST-PC",
        "event_data": {
            "Image": "C:\\Windows\\system32\\svchost.exe",
            "CommandLine": "svchost.exe -k netsvcs",
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "ParentCommandLine": "",
            "User": "NT AUTHORITY\\SYSTEM",
        },
    },
]


def test_flatten_event_sets_channel():
    event = {"log_name": "Microsoft-Windows-Sysmon/Operational", "event_id": 1, "event_data": {}}
    flat = flatten_event(event)
    assert flat["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert flat["EventID"] == 1


def test_flatten_event_promotes_event_data_fields():
    event = {
        "log_name": "test",
        "event_id": 1,
        "event_data": {"CommandLine": "cmd.exe /c foo", "Image": "C:\\cmd.exe"},
    }
    flat = flatten_event(event)
    assert flat["CommandLine"] == "cmd.exe /c foo"
    assert flat["Image"] == "C:\\cmd.exe"


def test_build_db_row_count():
    conn = build_db(FIXTURE_EVENTS)
    count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    assert count == len(FIXTURE_EVENTS)


def test_rules_compile():
    rules = compile_rules()
    assert len(rules) >= 6, f"Expected at least 6 compiled rules, got {len(rules)}"
    for rule_path, title, query in rules:
        assert "<TABLE_NAME>" not in query, f"Rule {rule_path} has unresolved TABLE_NAME"
        assert "SELECT" in query.upper()


def test_encoded_powershell_detected():
    conn = build_db(FIXTURE_EVENTS)
    rules = compile_rules()
    matches = run_detections(conn, rules)
    rule_names = [m["rule"] for m in matches]
    assert "powershell_encoded_command" in rule_names
    assert "powershell_suspicious_launch_flags" in rule_names


def test_whoami_detected():
    conn = build_db(FIXTURE_EVENTS)
    rules = compile_rules()
    matches = run_detections(conn, rules)
    rule_names = [m["rule"] for m in matches]
    assert "discovery_whoami_recon" in rule_names


def test_benign_svchost_not_flagged():
    conn = build_db(FIXTURE_EVENTS)
    rules = compile_rules()
    matches = run_detections(conn, rules)
    # svchost -k netsvcs should not trigger any rules
    svchost_matches = [m for m in matches if "svchost" in (m.get("image") or "").lower()
                       and "powershell" not in (m.get("rule") or "")]
    assert not svchost_matches, f"svchost incorrectly flagged: {svchost_matches}"


def test_match_schema():
    conn = build_db(FIXTURE_EVENTS)
    rules = compile_rules()
    matches = run_detections(conn, rules)
    assert matches
    required = {"rule", "title", "timestamp", "computer", "image", "command_line", "event_id"}
    for m in matches:
        assert required.issubset(m.keys()), f"Match missing fields: {required - m.keys()}"
