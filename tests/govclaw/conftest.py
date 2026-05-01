"""Shared fixtures for the govclaw test suite.

Each test gets its own temp dir for the audit log + approvals DB so tests
are isolated. We also force the plugin module to drop its cached config.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def govclaw_tmp_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point GovClaw's audit log + approvals DB at a per-test tmp dir."""
    audit_path = tmp_path / "audit.jsonl"
    approvals_db = tmp_path / "approvals.db"
    monkeypatch.setenv("GOVCLAW_AUDIT_PATH", str(audit_path))
    monkeypatch.setenv("GOVCLAW_APPROVALS_DB", str(approvals_db))
    monkeypatch.setenv("HERMES_NONINTERACTIVE", "1")  # block CLI prompts
    # Drop any cached plugin config from previous tests in this process.
    try:
        from govclaw import plugin
        plugin.reset_for_tests()
    except Exception:
        pass
    yield {
        "audit_path": audit_path,
        "approvals_db": approvals_db,
        "tmp_path": tmp_path,
    }


@pytest.fixture
def fake_reviewer(monkeypatch: pytest.MonkeyPatch):
    """Replace the reviewer's default LLM client with a fixture-controllable one.

    Yields a mutable dict whose ``response`` key the test sets to the JSON
    string the fake client should return on the next call.
    """
    state = {"response": '{"decision":"allow","risk_level":"low","explanation":"ok"}',
             "calls": []}

    def _client(messages, **kw):
        state["calls"].append({"messages": messages, "kw": kw})
        return state["response"]

    import govclaw.reviewer as reviewer_mod
    monkeypatch.setattr(reviewer_mod, "_default_client", _client)
    return state
