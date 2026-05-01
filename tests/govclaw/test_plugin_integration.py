"""End-to-end plugin: pre_tool_call -> decision -> approval -> retry."""

from __future__ import annotations

import json

from govclaw import plugin
from govclaw.approvals import store


def _audit_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def test_hardline_blocks_without_calling_reviewer(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"allow","risk_level":"low","explanation":"x"}'
    out = plugin.pre_tool_call(
        tool_name="terminal",
        args={"command": "rm -rf /"},
        task_id="t",
        session_id="s",
        tool_call_id="c1",
    )
    assert out == {"action": "block", "message": "Catastrophic system command refused by GovClaw."}
    # Reviewer must not have been consulted for hardline denials.
    assert fake_reviewer["calls"] == []
    rows = _audit_lines(govclaw_tmp_state["audit_path"])
    assert any(r["decision"] == "deny" for r in rows)


def test_idempotent_tool_passes_through_silently(govclaw_tmp_state, fake_reviewer):
    out = plugin.pre_tool_call(
        tool_name="read_file",
        args={"path": "/etc/hosts"},
        task_id="t",
        session_id="s",
        tool_call_id="c2",
    )
    assert out is None
    # No audit entry, no reviewer call.
    assert fake_reviewer["calls"] == []
    audit_path = govclaw_tmp_state["audit_path"]
    assert not audit_path.exists() or audit_path.stat().st_size == 0


def test_auto_allow_short_circuits(govclaw_tmp_state, fake_reviewer):
    out = plugin.pre_tool_call(
        tool_name="todo",
        args={"op": "add", "text": "x"},
        task_id="t",
        session_id="s",
        tool_call_id="c3",
    )
    assert out is None
    assert fake_reviewer["calls"] == []
    rows = _audit_lines(govclaw_tmp_state["audit_path"])
    assert rows[0]["source"] == "policy"
    assert rows[0]["decision"] == "allow"


def test_reviewer_allow_returns_none(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"allow","risk_level":"low","explanation":"safe write"}'
    out = plugin.pre_tool_call(
        tool_name="write_file",
        args={"path": "/tmp/x", "content": "x"},
        task_id="t",
        session_id="s",
        tool_call_id="c4",
    )
    assert out is None
    assert len(fake_reviewer["calls"]) == 1


def test_reviewer_deny_blocks(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"deny","risk_level":"high","explanation":"writes outside cwd"}'
    out = plugin.pre_tool_call(
        tool_name="write_file",
        args={"path": "/etc/shadow"},
        task_id="t",
        session_id="s",
        tool_call_id="c5",
    )
    assert out is not None
    assert out["action"] == "block"
    assert "writes outside cwd" in out["message"]


def test_send_message_queues_approval_in_noninteractive_mode(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"require_approval","risk_level":"high","explanation":"third party"}'
    out = plugin.pre_tool_call(
        tool_name="send_message",
        args={"to": "alice", "text": "hi"},
        task_id="t",
        session_id="s1",
        tool_call_id="c6",
    )
    assert out is not None
    assert out["action"] == "block"
    assert "approval" in out["message"].lower()
    pending = store.pending(session_id="s1")
    assert len(pending) == 1


def test_repeat_request_reuses_approval_id(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"require_approval","risk_level":"high","explanation":"x"}'
    args = {"to": "alice", "text": "hi"}
    plugin.pre_tool_call(
        tool_name="send_message", args=args,
        task_id="t", session_id="s1", tool_call_id="c1",
    )
    plugin.pre_tool_call(
        tool_name="send_message", args=args,
        task_id="t", session_id="s1", tool_call_id="c2",
    )
    pending = store.pending(session_id="s1")
    assert len(pending) == 1


def test_grant_unblocks_retry_via_cache(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"require_approval","risk_level":"high","explanation":"x"}'
    args = {"to": "alice", "text": "hi"}
    out = plugin.pre_tool_call(
        tool_name="send_message", args=args,
        task_id="t", session_id="s1", tool_call_id="c1",
    )
    assert out["action"] == "block"

    # Resolve out-of-band (as the CLI subcommand would).
    pending = store.pending(session_id="s1")
    rec = store.resolve(pending[0].approval_id, actor="user", grant=True)
    assert rec.status == "approved"

    # Retry: cache hit -> allow.
    out2 = plugin.pre_tool_call(
        tool_name="send_message", args=args,
        task_id="t", session_id="s1", tool_call_id="c2",
    )
    assert out2 is None


def test_post_tool_call_writes_outcome_for_allowed_action(govclaw_tmp_state, fake_reviewer):
    fake_reviewer["response"] = '{"decision":"allow","risk_level":"low","explanation":"ok"}'
    plugin.pre_tool_call(
        tool_name="write_file", args={"path": "/tmp/x"},
        task_id="t", session_id="s1", tool_call_id="c1",
    )
    plugin.post_tool_call(
        tool_name="write_file", args={"path": "/tmp/x"},
        result='{"ok":true}', duration_ms=12,
        task_id="t", session_id="s1", tool_call_id="c1",
    )
    rows = _audit_lines(govclaw_tmp_state["audit_path"])
    types = [r["event_type"] for r in rows]
    assert "decision" in types and "outcome" in types


def test_governance_failure_fails_closed(govclaw_tmp_state, fake_reviewer, monkeypatch):
    """If the inner pipeline raises, the hook returns a block message."""
    import govclaw.plugin as plugin_mod

    def boom(**_):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(plugin_mod, "_pre_tool_call_inner", boom)
    out = plugin.pre_tool_call(
        tool_name="write_file", args={"path": "/tmp/x"},
        task_id="t", session_id="s1", tool_call_id="c1",
    )
    assert out is not None and out["action"] == "block"
