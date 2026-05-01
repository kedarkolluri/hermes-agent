"""Approvals store: request, resolve, cache, multi-party quorum."""

from __future__ import annotations

import time

import pytest

from govclaw.approvals import store
from govclaw.intent import build
from govclaw.schemas import require_approval


def test_request_inserts_pending_record(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("test", ["user"])
    rec = store.request(p, d)
    assert rec.status == "pending"
    assert rec.required == ["user"]
    assert rec.session_id == "s1"


def test_request_is_idempotent_for_same_intent(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("test", ["user"])
    rec1 = store.request(p, d)
    rec2 = store.request(p, d)
    assert rec1.approval_id == rec2.approval_id


def test_different_args_get_different_records(govclaw_tmp_state):
    d = require_approval("t", ["user"])
    p1 = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    p2 = build(tool_name="send_message", args={"to": "y"}, session_id="s1")
    rec1 = store.request(p1, d)
    rec2 = store.request(p2, d)
    assert rec1.approval_id != rec2.approval_id


def test_resolve_grant_marks_approved_when_quorum_met(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user"])
    rec = store.request(p, d)
    updated = store.resolve(rec.approval_id, actor="user", grant=True)
    assert updated is not None
    assert updated.status == "approved"
    assert updated.granted == ["user"]


def test_multi_party_quorum_requires_all_approvers(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user", "accountant"])
    rec = store.request(p, d)

    after_one = store.resolve(rec.approval_id, actor="user", grant=True)
    assert after_one.status == "pending"  # only one approver so far

    after_both = store.resolve(rec.approval_id, actor="accountant", grant=True)
    assert after_both.status == "approved"


def test_any_denial_terminates_the_approval(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user", "accountant"])
    rec = store.request(p, d)
    store.resolve(rec.approval_id, actor="user", grant=True)
    final = store.resolve(rec.approval_id, actor="accountant", grant=False)
    assert final.status == "denied"


def test_resolve_unknown_id_returns_none(govclaw_tmp_state):
    assert store.resolve("does-not-exist", actor="user", grant=True) is None


def test_fetch_cached_grant_returns_approved_record(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user"])
    rec = store.request(p, d)
    store.resolve(rec.approval_id, actor="user", grant=True)
    cached = store.fetch_cached_grant(p)
    assert cached is not None
    assert cached.approval_id == rec.approval_id


def test_fetch_cached_grant_returns_none_for_pending(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user"])
    store.request(p, d)
    assert store.fetch_cached_grant(p) is None


def test_expired_grant_is_not_returned(govclaw_tmp_state):
    p = build(tool_name="send_message", args={"to": "x"}, session_id="s1")
    d = require_approval("t", ["user"])
    rec = store.request(p, d, ttl_secs=-1)  # immediately expired
    assert store.resolve(rec.approval_id, actor="user", grant=True).status == "expired"
    assert store.fetch_cached_grant(p) is None


def test_pending_filters_by_session(govclaw_tmp_state):
    d = require_approval("t", ["user"])
    p_a = build(tool_name="send_message", args={"to": "1"}, session_id="sA")
    p_b = build(tool_name="send_message", args={"to": "2"}, session_id="sB")
    store.request(p_a, d)
    store.request(p_b, d)
    only_a = store.pending(session_id="sA")
    assert len(only_a) == 1
    assert only_a[0].session_id == "sA"


def test_cache_key_is_session_scoped(govclaw_tmp_state):
    """Same args in different sessions must not share an approval."""
    d = require_approval("t", ["user"])
    p1 = build(tool_name="send_message", args={"to": "x"}, session_id="sA")
    p2 = build(tool_name="send_message", args={"to": "x"}, session_id="sB")
    rec1 = store.request(p1, d)
    rec2 = store.request(p2, d)
    assert rec1.approval_id != rec2.approval_id
