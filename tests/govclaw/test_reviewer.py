"""LLM reviewer + invariants."""

from __future__ import annotations

import json

from govclaw import policy, reviewer
from govclaw.intent import build


def _cfg(client):
    return reviewer.ReviewerConfig(client=client)


def test_reviewer_allow_passes_through():
    def client(messages, **kw):
        return json.dumps({"decision": "allow", "risk_level": "low",
                           "explanation": "safe local write"})
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "allow"
    assert d.source == "reviewer"


def test_reviewer_cannot_weaken_policy_required_approval():
    """If policy required user approval, the LLM cannot downgrade to allow."""
    def client(messages, **kw):
        return json.dumps({"decision": "allow", "risk_level": "low",
                           "explanation": "looks fine"})
    p = build(tool_name="send_message", args={"to": "x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "require_approval"
    assert "user" in d.required_approvals
    assert any(h.startswith("enforced:") for h in d.policy_hits)


def test_reviewer_can_escalate_allow_to_require_approval():
    def client(messages, **kw):
        return json.dumps({"decision": "require_approval", "risk_level": "high",
                           "explanation": "external write target",
                           "required_approvals": ["user"]})
    p = build(tool_name="write_file", args={"path": "/etc/shadow"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "require_approval"
    assert d.required_approvals == ["user"]


def test_reviewer_unparseable_response_falls_back():
    def client(messages, **kw):
        return "I refuse to answer in JSON."
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "require_approval"
    assert d.source == "fallback"


def test_reviewer_extracts_json_from_prose():
    def client(messages, **kw):
        return ('Sure, here is my decision: '
                '{"decision":"deny","risk_level":"high","explanation":"nope"}')
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "deny"


def test_reviewer_unknown_decision_falls_back():
    def client(messages, **kw):
        return json.dumps({"decision": "transform", "risk_level": "low",
                           "explanation": "lets convert it"})
    p = build(tool_name="write_file", args={"path": "/tmp/x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "require_approval"
    assert d.source == "fallback"


def test_reviewer_exception_falls_back_to_policy_verdict():
    def client(messages, **kw):
        raise RuntimeError("network down")
    # Policy already required approval — fallback must preserve that.
    p = build(tool_name="send_message", args={"to": "x"})
    v = policy.evaluate(p)
    d = reviewer.review(p, v, _cfg(client))
    assert d.decision == "require_approval"
    assert "user" in d.required_approvals
    assert d.source == "fallback"


def test_reviewer_disabled_returns_policy_decision():
    def client(messages, **kw):
        raise AssertionError("client should not be called")
    p = build(tool_name="send_message", args={"to": "x"})
    v = policy.evaluate(p)
    cfg = reviewer.ReviewerConfig(enabled=False, client=client)
    d = reviewer.review(p, v, cfg)
    assert d.decision == "require_approval"
