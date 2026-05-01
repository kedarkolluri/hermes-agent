"""govclaw CLI subcommand surface."""

from __future__ import annotations

from govclaw import cli as govclaw_cli
from govclaw.approvals import store
from govclaw.intent import build
from govclaw.schemas import require_approval


def _seed_pending(session_id="s1"):
    p = build(tool_name="send_message", args={"to": "x", "text": "hi"}, session_id=session_id)
    d = require_approval("test", ["user"])
    return store.request(p, d), p


def test_list_with_no_pending(govclaw_tmp_state, capsys):
    rc = govclaw_cli.main(["list"])
    assert rc == 0
    assert "No pending approvals." in capsys.readouterr().out


def test_list_shows_pending(govclaw_tmp_state, capsys):
    rec, _ = _seed_pending()
    rc = govclaw_cli.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert rec.approval_id in out
    assert "send_message" in out


def test_approve_marks_record_approved(govclaw_tmp_state, capsys):
    rec, _ = _seed_pending()
    rc = govclaw_cli.main(["approve", rec.approval_id])
    capsys.readouterr()  # drain
    assert rc == 0
    assert store.record(rec.approval_id).status == "approved"


def test_approve_unknown_id_returns_error(govclaw_tmp_state, capsys):
    rc = govclaw_cli.main(["approve", "does-not-exist"])
    assert rc == 1
    assert "Unknown approval id" in capsys.readouterr().err


def test_deny_marks_record_denied(govclaw_tmp_state, capsys):
    rec, _ = _seed_pending()
    rc = govclaw_cli.main(["deny", rec.approval_id])
    capsys.readouterr()
    assert rc == 0
    assert store.record(rec.approval_id).status == "denied"


def test_audit_handles_missing_log(govclaw_tmp_state, capsys):
    rc = govclaw_cli.main(["audit"])
    assert rc == 1
    assert "No audit log" in capsys.readouterr().err


def test_audit_tail_after_resolution(govclaw_tmp_state, capsys):
    rec, _ = _seed_pending()
    govclaw_cli.main(["approve", rec.approval_id])
    capsys.readouterr()  # drain approval output
    rc = govclaw_cli.main(["audit", "--tail", "10"])
    assert rc == 0
    out = capsys.readouterr().out
    assert rec.approval_id[:8] in out


def test_policy_prints_default_bundle(govclaw_tmp_state, capsys):
    rc = govclaw_cli.main(["policy"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "default_v1" in out
    assert "hardline rules" in out
    assert "approval rules" in out
