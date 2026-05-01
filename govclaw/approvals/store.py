"""SQLite-backed pending-approval store.

One row per approval request. Once all required approvers have granted,
the row is marked ``approved`` and the plugin can let the next attempt
through. Denials are terminal. Rows expire after a configurable TTL.

We also maintain a ``cache_key`` index so a session that just got
approval for a specific tool+args combination doesn't have to re-prompt
on every retry — ``fetch_cached_grant`` returns the most recent live
grant for ``(session_id, tool, args_hash)``.

The DB lives at ``$HERMES_HOME/govclaw/approvals.db`` and is created on
first use. We keep the schema deliberately small — this is operational
state, not analytics. Audit log (``audit.py``) is the system of record.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from ..schemas import ActionPacket, Decision

logger = logging.getLogger(__name__)


_DEFAULT_DB_PATH = "~/.hermes/govclaw/approvals.db"
_DEFAULT_TTL_SECS = 60 * 60  # one hour grant cache; configurable via env
_lock = threading.Lock()


def _resolve_db_path(override: Optional[str] = None) -> Path:
    raw = override or os.environ.get("GOVCLAW_APPROVALS_DB") or _DEFAULT_DB_PATH
    return Path(os.path.expanduser(raw))


def _ttl_secs() -> int:
    try:
        return int(os.environ.get("GOVCLAW_APPROVAL_TTL_SECS", _DEFAULT_TTL_SECS))
    except ValueError:
        return _DEFAULT_TTL_SECS


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_approvals (
    approval_id     TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL,
    session_id      TEXT,
    tool            TEXT NOT NULL,
    cache_key       TEXT NOT NULL,
    action_packet   TEXT NOT NULL,
    decision        TEXT NOT NULL,
    required        TEXT NOT NULL,  -- JSON list
    granted         TEXT NOT NULL DEFAULT '[]',
    denied          TEXT NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL,  -- pending|approved|denied|expired
    created_at      REAL NOT NULL,
    expires_at      REAL NOT NULL,
    resolved_at     REAL
);

CREATE INDEX IF NOT EXISTS idx_pending_status_cache
    ON pending_approvals (cache_key, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_pending_status_session
    ON pending_approvals (session_id, status, expires_at);
"""


@contextmanager
def _connect(db_path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = _resolve_db_path(db_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.warning("govclaw: cannot create approvals dir %s: %s", path.parent, exc)
        raise
    with _lock:
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(_SCHEMA)
            yield conn
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Record
# ---------------------------------------------------------------------------


@dataclass
class ApprovalRecord:
    approval_id: str
    trace_id: str
    session_id: str
    tool: str
    cache_key: str
    action_packet: Dict[str, Any]
    decision: Dict[str, Any]
    required: List[str]
    granted: List[str] = field(default_factory=list)
    denied: List[str] = field(default_factory=list)
    status: str = "pending"
    created_at: float = 0.0
    expires_at: float = 0.0
    resolved_at: Optional[float] = None

    @classmethod
    def _from_row(cls, row: sqlite3.Row) -> "ApprovalRecord":
        return cls(
            approval_id=row["approval_id"],
            trace_id=row["trace_id"],
            session_id=row["session_id"] or "",
            tool=row["tool"],
            cache_key=row["cache_key"],
            action_packet=json.loads(row["action_packet"]),
            decision=json.loads(row["decision"]),
            required=json.loads(row["required"]),
            granted=json.loads(row["granted"]),
            denied=json.loads(row["denied"]),
            status=row["status"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            resolved_at=row["resolved_at"],
        )

    def fully_approved(self) -> bool:
        return all(a in self.granted for a in self.required)

    def any_denied(self) -> bool:
        return bool(self.denied)


# ---------------------------------------------------------------------------
# Cache key — used to dedupe re-requests of the same intent
# ---------------------------------------------------------------------------


def cache_key_for(packet: ActionPacket) -> str:
    """Stable hash of (session, tool, args) used to look up live grants."""
    payload = {
        "session": packet.actor.get("session_id") or "",
        "tool": packet.proposed_action.tool,
        "args": packet.proposed_action.args,
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def request(
    packet: ActionPacket,
    decision: Decision,
    *,
    db_path: Optional[str] = None,
    ttl_secs: Optional[int] = None,
) -> ApprovalRecord:
    """Insert a new pending approval row and return it.

    Idempotent on ``cache_key`` for the same session: if there's a live
    pending row for the same intent we return it instead of inserting a
    duplicate. (Granted rows are returned by ``fetch_cached_grant``, not
    here.)
    """
    now = time.time()
    ttl = ttl_secs if ttl_secs is not None else _ttl_secs()
    cache_key = cache_key_for(packet)
    session_id = packet.actor.get("session_id") or ""

    with _connect(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM pending_approvals "
            "WHERE cache_key = ? AND status = 'pending' AND expires_at > ? "
            "ORDER BY created_at DESC LIMIT 1",
            (cache_key, now),
        ).fetchone()
        if existing:
            return ApprovalRecord._from_row(existing)

        record = ApprovalRecord(
            approval_id=str(uuid.uuid4()),
            trace_id=packet.trace_id,
            session_id=session_id,
            tool=packet.proposed_action.tool,
            cache_key=cache_key,
            action_packet=packet.to_dict(),
            decision=decision.to_dict(),
            required=list(decision.required_approvals or ["user"]),
            status="pending",
            created_at=now,
            expires_at=now + ttl,
        )
        conn.execute(
            "INSERT INTO pending_approvals "
            "(approval_id, trace_id, session_id, tool, cache_key, "
            " action_packet, decision, required, granted, denied, "
            " status, created_at, expires_at, resolved_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                record.approval_id,
                record.trace_id,
                record.session_id,
                record.tool,
                record.cache_key,
                json.dumps(record.action_packet, default=str, sort_keys=True),
                json.dumps(record.decision, default=str, sort_keys=True),
                json.dumps(record.required),
                json.dumps(record.granted),
                json.dumps(record.denied),
                record.status,
                record.created_at,
                record.expires_at,
                record.resolved_at,
            ),
        )
        return record


def resolve(
    approval_id: str,
    *,
    actor: str,
    grant: bool,
    db_path: Optional[str] = None,
) -> Optional[ApprovalRecord]:
    """Apply a single approver's grant or denial.

    Returns the updated record. Returns None if the approval doesn't
    exist or has expired. Status transitions:

    * any denial      → status='denied'
    * all granted     → status='approved'
    * otherwise       → stays 'pending'
    """
    now = time.time()
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM pending_approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        if row is None:
            return None
        record = ApprovalRecord._from_row(row)

        if record.status != "pending":
            return record  # already resolved; idempotent
        if record.expires_at <= now:
            conn.execute(
                "UPDATE pending_approvals SET status='expired', resolved_at=? "
                "WHERE approval_id = ?",
                (now, approval_id),
            )
            record.status = "expired"
            record.resolved_at = now
            return record

        if grant:
            if actor not in record.granted:
                record.granted.append(actor)
        else:
            if actor not in record.denied:
                record.denied.append(actor)

        if record.any_denied():
            record.status = "denied"
            record.resolved_at = now
        elif record.fully_approved():
            record.status = "approved"
            record.resolved_at = now

        conn.execute(
            "UPDATE pending_approvals SET granted=?, denied=?, "
            " status=?, resolved_at=? WHERE approval_id = ?",
            (
                json.dumps(record.granted),
                json.dumps(record.denied),
                record.status,
                record.resolved_at,
                approval_id,
            ),
        )
        return record


def fetch_cached_grant(
    packet: ActionPacket, *, db_path: Optional[str] = None
) -> Optional[ApprovalRecord]:
    """Return the most recent live ``approved`` record for the same intent.

    Used by the plugin on re-attempt: if the user already approved this
    exact (session, tool, args) within the TTL, let it through without
    prompting again.
    """
    now = time.time()
    cache_key = cache_key_for(packet)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM pending_approvals "
            "WHERE cache_key = ? AND status = 'approved' AND expires_at > ? "
            "ORDER BY resolved_at DESC LIMIT 1",
            (cache_key, now),
        ).fetchone()
        return ApprovalRecord._from_row(row) if row else None


def record(approval_id: str, *, db_path: Optional[str] = None) -> Optional[ApprovalRecord]:
    """Look up a single record by id."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM pending_approvals WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
        return ApprovalRecord._from_row(row) if row else None


def pending(
    *,
    session_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[ApprovalRecord]:
    """List live pending approvals (oldest first)."""
    now = time.time()
    with _connect(db_path) as conn:
        if session_id is not None:
            rows = conn.execute(
                "SELECT * FROM pending_approvals "
                "WHERE status = 'pending' AND expires_at > ? AND session_id = ? "
                "ORDER BY created_at ASC",
                (now, session_id),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM pending_approvals "
                "WHERE status = 'pending' AND expires_at > ? "
                "ORDER BY created_at ASC",
                (now,),
            ).fetchall()
        return [ApprovalRecord._from_row(r) for r in rows]
