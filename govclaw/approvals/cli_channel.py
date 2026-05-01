"""Inline CLI self-approval channel.

When the only required approver is the local operator (``"user"``) and
we're running an interactive CLI session, we can prompt synchronously
inside the ``pre_tool_call`` hook and unblock the call in the same
attempt — no agent retry needed.

Multi-party approvals (or non-interactive contexts like gateway runs,
cron, batch_runner) skip this channel and use ``gateway_channel`` instead;
the plugin returns a "queued for approval" block message and the caller
re-runs the action once approvals land.

The ``try_inline_approve`` return is tri-state on purpose:

* ``"approved"`` — operator explicitly approved at the prompt.
* ``"denied"``   — operator explicitly denied at the prompt.
* ``"skipped"``  — no prompt happened (non-interactive, or this approval
  needs more than just the local operator). Caller should fall through
  to the multi-party gateway channel.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Literal, Optional

from ..schemas import ActionPacket, Decision
from . import store as approvals_store

logger = logging.getLogger(__name__)


InlineResult = Literal["approved", "denied", "skipped"]


def _is_interactive_cli() -> bool:
    """Best-effort: are we in an interactive terminal session?"""
    if os.environ.get("HERMES_NONINTERACTIVE") == "1":
        return False
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (ValueError, AttributeError):
        return False


def _format_prompt(packet: ActionPacket, decision: Decision) -> str:
    args_preview = packet.proposed_action.args
    if isinstance(args_preview, dict):
        # Compact, single-line preview for terminal display.
        items = []
        for k, v in list(args_preview.items())[:6]:
            sval = repr(v)
            if len(sval) > 80:
                sval = sval[:79] + "…"
            items.append(f"{k}={sval}")
        args_str = ", ".join(items)
    else:
        args_str = repr(args_preview)

    lines = [
        "",
        "─" * 72,
        "GovClaw approval request",
        "─" * 72,
        f"  tool        : {packet.proposed_action.tool}",
        f"  args        : {args_str}",
        f"  risk        : {decision.risk_level}",
        f"  why         : {decision.explanation}",
        f"  policy hits : {', '.join(decision.policy_hits) or '(reviewer)'}",
        f"  trace       : {packet.trace_id}",
        "─" * 72,
        "[a]pprove / [d]eny  > ",
    ]
    return "\n".join(lines)


def can_self_approve(decision: Decision) -> bool:
    """Are the required approvers limited to the local operator?"""
    required = set(decision.required_approvals or [])
    return required.issubset({"user", "self", ""})


def try_inline_approve(
    packet: ActionPacket,
    decision: Decision,
    *,
    approval_id: str,
    db_path: Optional[str] = None,
) -> InlineResult:
    """Prompt the operator on stdin/stdout. Returns one of approved/denied/skipped.

    Records the resolution in the approvals store iff the operator was
    actually prompted. ``skipped`` leaves the pending row untouched so the
    caller can fall through to the gateway channel.
    """
    if not _is_interactive_cli():
        return "skipped"
    if not can_self_approve(decision):
        return "skipped"

    prompt = _format_prompt(packet, decision)
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        approvals_store.resolve(approval_id, actor="user", grant=False, db_path=db_path)
        return "denied"
    except OSError:
        # Treat IO failure as "couldn't prompt" — fall through, don't deny.
        return "skipped"

    answer = (line or "").strip().lower()
    grant = answer in {"a", "approve", "y", "yes"}
    approvals_store.resolve(approval_id, actor="user", grant=grant, db_path=db_path)
    return "approved" if grant else "denied"
