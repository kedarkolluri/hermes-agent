"""Multi-party approval delivery via Hermes's gateway adapters.

When an action requires approvals beyond the local operator (or we're not
in an interactive CLI), GovClaw publishes the approval request through
whichever notify callback the active gateway has registered.

Resolution is out-of-band — the user (or a remote approver) replies via:

* the gateway adapter's reply handler (Telegram/Discord/Slack pattern-match
  on ``approve <id>`` / ``deny <id>``), or
* the ``hermes govclaw approve|deny <id>`` CLI subcommand.

Either path lands in :func:`govclaw.approvals.store.resolve`. When the agent
retries the same intent, ``fetch_cached_grant`` returns the now-approved
record and the plugin lets the call through.

This module is deliberately thin: it owns the registration table and the
delivery contract, nothing else. Gateway plugins call
:func:`register_notifier` at session start and :func:`unregister_notifier`
at session end.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from ..schemas import ActionPacket, Decision
from .store import ApprovalRecord

logger = logging.getLogger(__name__)


# Notifier signature: cb(payload: dict) -> None
# Payload keys: approval_id, trace_id, tool, args_preview, risk_level,
#               required, explanation, expires_at.
Notifier = Callable[[Dict[str, Any]], None]


_notifiers: Dict[str, Notifier] = {}
_lock = threading.Lock()


def register_notifier(session_key: str, cb: Notifier) -> None:
    """Register a per-session callback that delivers approval requests.

    Mirrors ``tools/approval.register_gateway_notify``: gateway adapters
    call this once per session so GovClaw can route approval requests to
    the right chat / DM / channel.
    """
    if not session_key:
        return
    with _lock:
        _notifiers[session_key] = cb


def unregister_notifier(session_key: str) -> None:
    with _lock:
        _notifiers.pop(session_key, None)


def has_notifier(session_key: str) -> bool:
    with _lock:
        return session_key in _notifiers


def _payload_for(record: ApprovalRecord, decision: Decision) -> Dict[str, Any]:
    """Build the dict handed to the gateway notify callback."""
    args = record.action_packet.get("proposed_action", {}).get("args", {})
    if isinstance(args, dict):
        preview = {k: args[k] for k in list(args)[:6]}
    else:
        preview = {}
    return {
        "approval_id": record.approval_id,
        "trace_id": record.trace_id,
        "tool": record.tool,
        "args_preview": preview,
        "risk_level": decision.risk_level,
        "required": list(record.required),
        "explanation": decision.explanation,
        "expires_at": record.expires_at,
    }


def deliver(
    packet: ActionPacket,
    decision: Decision,
    record: ApprovalRecord,
) -> bool:
    """Hand the approval request to the registered gateway notifier.

    Returns True iff a notifier was found and called without raising.
    Best-effort: a notifier exception is logged but not propagated.
    """
    session_key = packet.actor.get("session_id") or ""
    with _lock:
        cb = _notifiers.get(session_key)
    if cb is None:
        return False
    try:
        cb(_payload_for(record, decision))
        return True
    except Exception as exc:
        logger.warning(
            "govclaw: gateway notifier for session %s raised: %s",
            session_key,
            exc,
        )
        return False


def format_pending_message(record: ApprovalRecord, decision: Decision) -> str:
    """Block-message body the agent loop sees.

    The agent will surface this back to the user; at minimum it must
    include the approval_id so the human can grant via CLI or chat.
    """
    waiting_on = ", ".join(record.required) or "user"
    return (
        f"GovClaw: action requires approval (id: {record.approval_id}). "
        f"Awaiting: {waiting_on}. Risk: {decision.risk_level}. "
        f"Reason: {decision.explanation} "
        f"To approve: `hermes govclaw approve {record.approval_id}` "
        f"or reply `approve {record.approval_id}` in this chat. "
        f"The action will not run until approved."
    )


# Read accessor for tests / introspection.
def list_notifier_session_keys() -> List[str]:
    with _lock:
        return list(_notifiers.keys())
