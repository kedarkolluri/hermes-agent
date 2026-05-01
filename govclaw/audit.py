"""Append-only JSONL audit log.

One line per event. The plugin writes:

* a ``decision`` event from ``pre_tool_call`` after every governance verdict
  (allow / deny / require_approval, including hardline + auto-allow),
* an ``outcome`` event from ``post_tool_call`` after the tool ran, with the
  result-summary and duration,
* an ``approval_resolved`` event when a pending approval is granted or
  denied out of band.

Writes are best-effort: if the audit file can't be opened or written we log
and continue. The agent loop must never be blocked by a logger failure.

Storage layout::

    $HERMES_HOME/govclaw/audit.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .schemas import ActionPacket, Decision

logger = logging.getLogger(__name__)


_DEFAULT_PATH = "~/.hermes/govclaw/audit.jsonl"
_lock = threading.Lock()


def _resolve_path(override: Optional[str] = None) -> Path:
    raw = override or os.environ.get("GOVCLAW_AUDIT_PATH") or _DEFAULT_PATH
    return Path(os.path.expanduser(raw))


def _ensure_dir(path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        return True
    except OSError as exc:
        logger.warning("govclaw: cannot create audit dir %s: %s", path.parent, exc)
        return False


def _summarise_result(result: Any, *, max_chars: int = 512) -> str:
    """Compact one-line representation of a tool result for the audit log."""
    if result is None:
        return ""
    if isinstance(result, str):
        s = result
    else:
        try:
            s = json.dumps(result, default=str)
        except (TypeError, ValueError):
            s = repr(result)
    s = s.replace("\n", " ").strip()
    if len(s) > max_chars:
        s = s[: max_chars - 1] + "…"
    return s


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def _write(event: Dict[str, Any], *, path_override: Optional[str] = None) -> bool:
    """Append one JSONL event. Returns True on success."""
    path = _resolve_path(path_override)
    if not _ensure_dir(path):
        return False
    line = json.dumps(event, default=str, sort_keys=True)
    try:
        with _lock:
            # Open per write so log rotation by an external process works.
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")
        return True
    except OSError as exc:
        logger.warning("govclaw: audit write failed (%s): %s", path, exc)
        return False


# ---------------------------------------------------------------------------
# Public events
# ---------------------------------------------------------------------------


def log_decision(
    packet: ActionPacket,
    decision: Decision,
    *,
    path_override: Optional[str] = None,
) -> bool:
    """Record a governance decision."""
    event = {
        "ts": time.time(),
        "event_type": "decision",
        "trace_id": packet.trace_id,
        "session_id": packet.actor.get("session_id"),
        "task_id": packet.actor.get("task_id"),
        "tool": packet.proposed_action.tool,
        "decision": decision.decision,
        "risk_level": decision.risk_level,
        "source": decision.source,
        "policy_hits": list(decision.policy_hits),
        "required_approvals": list(decision.required_approvals),
        "explanation": decision.explanation,
        "action_packet": packet.to_dict(),
    }
    return _write(event, path_override=path_override)


def log_outcome(
    *,
    trace_id: str,
    tool_name: str,
    args: Dict[str, Any],
    result: Any,
    duration_ms: int,
    session_id: str = "",
    task_id: str = "",
    path_override: Optional[str] = None,
) -> bool:
    """Record the result of a tool execution that GovClaw allowed."""
    event = {
        "ts": time.time(),
        "event_type": "outcome",
        "trace_id": trace_id,
        "session_id": session_id,
        "task_id": task_id,
        "tool": tool_name,
        "duration_ms": duration_ms,
        "result_summary": _summarise_result(result),
    }
    return _write(event, path_override=path_override)


def log_approval_resolution(
    *,
    approval_id: str,
    trace_id: str,
    status: str,
    granted_by: Optional[str] = None,
    denied_by: Optional[str] = None,
    note: str = "",
    path_override: Optional[str] = None,
) -> bool:
    """Record that a pending approval was granted, denied, or expired."""
    event = {
        "ts": time.time(),
        "event_type": "approval_resolved",
        "approval_id": approval_id,
        "trace_id": trace_id,
        "status": status,
        "granted_by": granted_by,
        "denied_by": denied_by,
        "note": note,
    }
    return _write(event, path_override=path_override)


def audit_path(override: Optional[str] = None) -> Path:
    """Return the resolved audit log path (handy for the CLI subcommand)."""
    return _resolve_path(override)
