"""Audit log: append-only JSONL writes."""

from __future__ import annotations

import json

from govclaw import audit
from govclaw.intent import build
from govclaw.schemas import allow, deny


def _read(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def test_log_decision_writes_jsonl(govclaw_tmp_state):
    p = build(tool_name="write_file", args={"path": "/tmp/x"}, session_id="s1")
    d = allow("ok", source="reviewer")
    assert audit.log_decision(p, d) is True
    rows = _read(govclaw_tmp_state["audit_path"])
    assert len(rows) == 1
    row = rows[0]
    assert row["event_type"] == "decision"
    assert row["tool"] == "write_file"
    assert row["decision"] == "allow"
    assert row["trace_id"] == p.trace_id


def test_log_outcome_appends_event(govclaw_tmp_state):
    p = build(tool_name="write_file", args={"path": "/tmp/x"}, session_id="s1")
    audit.log_decision(p, allow("ok"))
    audit.log_outcome(
        trace_id=p.trace_id,
        tool_name="write_file",
        args={"path": "/tmp/x"},
        result='{"ok":true}',
        duration_ms=37,
        session_id="s1",
    )
    rows = _read(govclaw_tmp_state["audit_path"])
    assert [r["event_type"] for r in rows] == ["decision", "outcome"]
    assert rows[1]["duration_ms"] == 37


def test_log_approval_resolution(govclaw_tmp_state):
    audit.log_approval_resolution(
        approval_id="abc",
        trace_id="t1",
        status="approved",
        granted_by="user",
    )
    rows = _read(govclaw_tmp_state["audit_path"])
    assert rows[0]["event_type"] == "approval_resolved"
    assert rows[0]["status"] == "approved"


def test_audit_writes_are_strictly_appending(govclaw_tmp_state):
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    audit.log_decision(p, allow("first"))
    audit.log_decision(p, deny("second"))
    audit.log_decision(p, allow("third"))
    rows = _read(govclaw_tmp_state["audit_path"])
    assert [r["explanation"] for r in rows] == ["first", "second", "third"]


def test_outcome_summary_is_truncated(govclaw_tmp_state):
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    audit.log_decision(p, allow("ok"))
    huge = "x" * 5000
    audit.log_outcome(
        trace_id=p.trace_id,
        tool_name="write_file",
        args={},
        result=huge,
        duration_ms=1,
    )
    rows = _read(govclaw_tmp_state["audit_path"])
    assert len(rows[1]["result_summary"]) <= 512
