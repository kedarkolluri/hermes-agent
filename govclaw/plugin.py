"""GovClaw plugin entry point.

Wires the deterministic policy engine + LLM reviewer + approvals store +
audit log into the Hermes plugin system. The plugin shim at
``plugins/govclaw/__init__.py`` calls :func:`register` with a plugin
context; everything else lives in this package.

Hooks registered:

* ``pre_tool_call``  — governance verdict; may return a block message.
* ``post_tool_call`` — append the outcome to the audit log.

Fail-closed: any unhandled exception inside the hook returns a block
message rather than letting the call through. Governance failures must
not become silent permits.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Optional

from . import audit
from .approvals import (
    cli_channel,
    gateway_channel,
    store as approvals_store,
)
from .config import GovClawConfig, load as load_config
from .intent import build as build_packet, is_idempotent, is_mutating
from .policy import evaluate as evaluate_policy, get_bundle
from .reviewer import ReviewerConfig, review as run_review
from .schemas import ActionPacket, Decision

logger = logging.getLogger(__name__)


# Cache the config at first hook fire — discovered after Hermes config
# loading completes, so we can't compute it at import time.
_config: Optional[GovClawConfig] = None
_config_lock = threading.Lock()

# Per-trace map so post_tool_call can attribute the outcome to the same
# trace_id we used for the decision event. Keyed by tool_call_id (set by
# Hermes for every tool call).
_trace_by_call: Dict[str, str] = {}
_trace_lock = threading.Lock()


def _get_config() -> GovClawConfig:
    global _config
    with _config_lock:
        if _config is None:
            _config = load_config()
        return _config


def _record_trace(tool_call_id: str, trace_id: str) -> None:
    if not tool_call_id:
        return
    with _trace_lock:
        _trace_by_call[tool_call_id] = trace_id


def _pop_trace(tool_call_id: str) -> Optional[str]:
    if not tool_call_id:
        return None
    with _trace_lock:
        return _trace_by_call.pop(tool_call_id, None)


# ---------------------------------------------------------------------------
# pre_tool_call
# ---------------------------------------------------------------------------


def _block(message: str) -> Dict[str, str]:
    return {"action": "block", "message": message}


def pre_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_extra: Any,
) -> Optional[Dict[str, str]]:
    """Hermes ``pre_tool_call`` hook — governance verdict.

    Returns ``{"action": "block", "message": ...}`` to block the tool, or
    ``None`` to allow.
    """
    try:
        return _pre_tool_call_inner(
            tool_name=tool_name,
            args=args,
            task_id=task_id,
            session_id=session_id,
            tool_call_id=tool_call_id,
        )
    except Exception:
        # Fail-closed. We log the traceback to the regular logger; the
        # block message is intentionally generic so we don't leak internals.
        logger.exception("govclaw pre_tool_call failed; failing closed")
        return _block(
            "GovClaw governance check failed; refusing the tool call. "
            "See the Hermes log for details."
        )


def _pre_tool_call_inner(
    *,
    tool_name: str,
    args: Optional[Dict[str, Any]],
    task_id: str,
    session_id: str,
    tool_call_id: str,
) -> Optional[Dict[str, str]]:
    cfg = _get_config()
    if not cfg.enabled:
        return None
    if not tool_name:
        return None

    bundle = get_bundle(cfg.policy_bundle)

    # Observer-only for read-only tools; never block, never audit.
    if is_idempotent(tool_name):
        return None
    # Anything not in MUTATING_TOOL_NAMES and not in the bundle's auto_allow
    # passes through silently. The policy engine still has the final say if
    # a future bundle adds an "always_review" list (TODO v2).
    if not is_mutating(tool_name) and tool_name not in set(bundle.auto_allow_tools):
        return None

    packet = build_packet(
        tool_name=tool_name,
        args=args,
        task_id=task_id,
        session_id=session_id,
        tool_call_id=tool_call_id,
        policy_bundle=cfg.policy_bundle,
    )

    # Re-attempt fast path: did the same intent already get approved?
    cached = approvals_store.fetch_cached_grant(packet)
    if cached is not None:
        decision = Decision.from_dict({**cached.decision, "decision": "allow",
                                       "source": "approvals_cache"})
        decision.explanation = (
            f"Previously approved (approval_id={cached.approval_id})."
        )
        audit.log_decision(packet, decision, path_override=cfg.audit_path)
        _record_trace(tool_call_id, packet.trace_id)
        return None

    verdict = evaluate_policy(packet, bundle)

    if verdict.hardline_deny:
        decision = verdict.as_decision()
        audit.log_decision(packet, decision, path_override=cfg.audit_path)
        return _block(decision.explanation)

    if verdict.auto_allow:
        decision = verdict.as_decision()
        audit.log_decision(packet, decision, path_override=cfg.audit_path)
        _record_trace(tool_call_id, packet.trace_id)
        return None

    # Reviewer call (or skip, if disabled).
    reviewer_cfg = ReviewerConfig(
        enabled=cfg.reviewer_enabled,
        timeout_s=cfg.reviewer_timeout_s,
    )
    decision = run_review(packet, verdict, reviewer_cfg)
    audit.log_decision(packet, decision, path_override=cfg.audit_path)

    if decision.decision == "allow":
        _record_trace(tool_call_id, packet.trace_id)
        return None
    if decision.decision == "deny":
        return _block(decision.explanation or "Denied by GovClaw governance.")

    if decision.decision == "require_approval":
        return _handle_approval(packet, decision, cfg)

    # Unknown decision value — fail closed.
    return _block("GovClaw: unrecognized decision; failing closed.")


def _handle_approval(
    packet: ActionPacket,
    decision: Decision,
    cfg: GovClawConfig,
) -> Dict[str, str]:
    record = approvals_store.request(
        packet,
        decision,
        ttl_secs=cfg.approval_ttl_secs,
    )

    # Inline CLI fast-path: only viable when self-approval is enabled and
    # the only approver is the local operator. Returns "skipped" when
    # we're non-interactive or the policy needs more than the local user
    # — in those cases we fall through to the gateway channel.
    if cfg.approvals_cli_self_approve and cli_channel.can_self_approve(decision):
        result = cli_channel.try_inline_approve(
            packet, decision, approval_id=record.approval_id
        )
        if result == "approved":
            audit.log_approval_resolution(
                approval_id=record.approval_id,
                trace_id=packet.trace_id,
                status="approved",
                granted_by="user",
                note="cli_inline",
            )
            _record_trace(tool_call_id_for(packet), packet.trace_id)
            return None  # type: ignore[return-value]
        if result == "denied":
            audit.log_approval_resolution(
                approval_id=record.approval_id,
                trace_id=packet.trace_id,
                status="denied",
                denied_by="user",
                note="cli_inline_deny",
            )
            return _block(
                f"GovClaw: action denied by operator at CLI prompt "
                f"(approval_id={record.approval_id})."
            )
        # "skipped" → fall through to gateway path below.

    # Multi-party / non-interactive path: deliver via gateway notifier
    # (best-effort) and tell the agent to stop.
    if cfg.approvals_gateway_multi_party:
        gateway_channel.deliver(packet, decision, record)
    return _block(gateway_channel.format_pending_message(record, decision))


def tool_call_id_for(packet: ActionPacket) -> str:
    """Pull the tool_call_id out of a packet's context for trace bookkeeping."""
    val = packet.context.get("tool_call_id") if isinstance(packet.context, dict) else None
    return str(val or "")


# ---------------------------------------------------------------------------
# post_tool_call
# ---------------------------------------------------------------------------


def post_tool_call(
    tool_name: str = "",
    args: Optional[Dict[str, Any]] = None,
    result: Any = None,
    duration_ms: int = 0,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_extra: Any,
) -> None:
    """Audit-log the outcome of a tool execution we previously allowed."""
    try:
        cfg = _get_config()
        if not cfg.enabled:
            return
        trace_id = _pop_trace(tool_call_id)
        if not trace_id:
            # We didn't issue a decision for this tool (idempotent / disabled);
            # nothing to attribute the outcome to.
            return
        audit.log_outcome(
            trace_id=trace_id,
            tool_name=tool_name,
            args=args or {},
            result=result,
            duration_ms=int(duration_ms or 0),
            session_id=session_id,
            task_id=task_id,
            path_override=cfg.audit_path,
        )
    except Exception:
        # Audit failures must never break the agent loop.
        logger.exception("govclaw post_tool_call failed")


# ---------------------------------------------------------------------------
# Plugin registration entry point
# ---------------------------------------------------------------------------


def register(ctx: Any) -> None:
    """Hermes plugin registration. Called by ``plugins/govclaw/__init__.py``."""
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)


def reset_for_tests() -> None:
    """Test-only helper: drop cached config + trace map."""
    global _config
    with _config_lock:
        _config = None
    with _trace_lock:
        _trace_by_call.clear()
