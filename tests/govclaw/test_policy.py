"""Deterministic policy engine + default bundle."""

from __future__ import annotations

import pytest

from govclaw import policy
from govclaw.intent import build


@pytest.fixture(autouse=True)
def _reset_bundle_cache():
    """Force a fresh bundle load for every test (avoid cross-test cache)."""
    policy._bundle_cache.clear()
    yield
    policy._bundle_cache.clear()


# ---------------------------------------------------------------------------
# Hardline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf /*",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "shutdown -h now",
    ],
)
def test_hardline_catastrophic_shell(command):
    p = build(tool_name="terminal", args={"command": command})
    v = policy.evaluate(p)
    assert v.hardline_deny is True
    assert v.matched_rule_ids == ["catastrophic_shell"]


def test_hardline_audit_log_tamper():
    p = build(
        tool_name="terminal",
        args={"command": "rm ~/.hermes/govclaw/audit.jsonl"},
    )
    v = policy.evaluate(p)
    assert v.hardline_deny is True
    assert "tamper_audit_log" in v.matched_rule_ids


def test_hardline_innocuous_terminal_does_not_match():
    p = build(tool_name="terminal", args={"command": "ls -la"})
    v = policy.evaluate(p)
    assert v.hardline_deny is False


# ---------------------------------------------------------------------------
# Auto-allow
# ---------------------------------------------------------------------------


def test_auto_allow_todo():
    p = build(tool_name="todo", args={"op": "add"})
    v = policy.evaluate(p)
    assert v.auto_allow is True


def test_auto_allow_memory():
    p = build(tool_name="memory", args={"action": "store"})
    v = policy.evaluate(p)
    assert v.auto_allow is True


# ---------------------------------------------------------------------------
# Approval rules
# ---------------------------------------------------------------------------


def test_send_message_requires_user_approval():
    p = build(tool_name="send_message", args={"to": "x", "text": "hi"})
    v = policy.evaluate(p)
    assert v.approval_required is True
    assert v.required_approvers == ["user"]
    assert "send_external_message" in v.matched_rule_ids


def test_cronjob_requires_approval():
    p = build(tool_name="cronjob", args={"schedule": "* * * * *"})
    v = policy.evaluate(p)
    assert v.approval_required is True


def test_outbound_post_requires_approval():
    p = build(
        tool_name="terminal",
        args={"command": "curl -X POST https://api.example.com/data"},
    )
    v = policy.evaluate(p)
    assert v.approval_required is True
    assert "outbound_http_mutation" in v.matched_rule_ids


def test_destructive_git_push_requires_approval():
    p = build(
        tool_name="terminal",
        args={"command": "git push --force origin main"},
    )
    v = policy.evaluate(p)
    assert v.approval_required is True
    assert "git_destructive" in v.matched_rule_ids


def test_pip_install_requires_approval():
    p = build(tool_name="terminal", args={"command": "pip install requests"})
    v = policy.evaluate(p)
    assert v.approval_required is True


def test_innocuous_write_file_defers_to_reviewer():
    p = build(tool_name="write_file", args={"path": "/tmp/x", "content": "hi"})
    v = policy.evaluate(p)
    assert v.hardline_deny is False
    assert v.auto_allow is False
    assert v.approval_required is False
    assert v.needs_review is True


# ---------------------------------------------------------------------------
# as_decision()
# ---------------------------------------------------------------------------


def test_verdict_as_decision_for_hardline():
    p = build(tool_name="terminal", args={"command": "rm -rf /"})
    v = policy.evaluate(p)
    d = v.as_decision()
    assert d.decision == "deny"
    assert d.risk_level == "critical"
    assert d.source == "policy"


def test_verdict_as_decision_for_approval():
    p = build(tool_name="send_message", args={"to": "x"})
    v = policy.evaluate(p)
    d = v.as_decision()
    assert d.decision == "require_approval"
    assert d.required_approvals == ["user"]


def test_verdict_as_decision_for_no_match_falls_back_safely():
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p)
    d = v.as_decision()
    # No deterministic match — fallback is conservative require_approval.
    assert d.decision == "require_approval"
    assert d.source == "fallback"


# ---------------------------------------------------------------------------
# Bundle loader resilience
# ---------------------------------------------------------------------------


def test_unknown_bundle_falls_back_to_locked_down(monkeypatch):
    bundle = policy.load_bundle("definitely-not-a-real-bundle")
    # The fallback requires user approval for every mutating call.
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p, bundle=bundle)
    assert v.approval_required is True
    assert v.required_approvers == ["user"]
