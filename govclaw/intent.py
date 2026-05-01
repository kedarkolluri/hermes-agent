"""ActionPacket synthesis from raw ``pre_tool_call`` kwargs.

The plugin hook receives ``(tool_name, args, task_id, session_id, tool_call_id)``.
:func:`build` turns those into an :class:`ActionPacket`, attaching:

* ``state_change`` — true iff ``tool_name`` is in
  :data:`agent.tool_guardrails.MUTATING_TOOL_NAMES`. This is the same
  classification Hermes already uses for its loop-detection guardrails, so
  GovClaw stays consistent with the rest of the codebase.
* ``irreversible`` — true for a small set of obvious one-way operations
  (e.g. ``send_message``, ``cronjob``, ``terminal`` calls that match the
  destructive shell pattern below).
* ``mutating`` — alias of ``state_change`` for the spec field name.

We intentionally do not try to be exhaustive here. The deterministic policy
engine and the LLM reviewer make the actual decisions; this module's job is
to give them a tidy, consistent input.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from .schemas import ActionPacket

try:
    # Reuse Hermes's existing classification — single source of truth.
    from agent.tool_guardrails import (
        IDEMPOTENT_TOOL_NAMES,
        MUTATING_TOOL_NAMES,
    )
except Exception:  # pragma: no cover — bare-import fallback for tests
    IDEMPOTENT_TOOL_NAMES = frozenset()  # type: ignore[assignment]
    MUTATING_TOOL_NAMES = frozenset()  # type: ignore[assignment]


# Tools whose effects are practically impossible to undo from inside Hermes.
# Conservative — false negatives just mean the reviewer/policy gets less
# context, not that something dangerous slips through.
_IRREVERSIBLE_TOOLS = frozenset(
    {
        "send_message",
        "cronjob",
        "delegate_task",
    }
)

# Shell-command patterns that are functionally irreversible. Matched against
# the ``command`` arg of the ``terminal`` tool. Kept narrow on purpose —
# anything ambiguous defers to the LLM reviewer.
_IRREVERSIBLE_SHELL_PATTERNS = (
    re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*\s+|-[a-zA-Z]*f[a-zA-Z]*\s+|-rf\s+|-fr\s+)"),
    re.compile(r"\bdd\s+.*\bof=/dev/"),
    re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b"),
    re.compile(r"\bshred\b"),
    re.compile(r"\bgit\s+push\s+(?:--force|-f)\b"),
    re.compile(r"\bgit\s+reset\s+--hard\b"),
)


def _looks_irreversible_shell(command: str) -> bool:
    if not command:
        return False
    return any(p.search(command) for p in _IRREVERSIBLE_SHELL_PATTERNS)


def is_mutating(tool_name: str) -> bool:
    """Whether GovClaw should review this tool by default.

    Uses ``MUTATING_TOOL_NAMES`` from ``agent/tool_guardrails.py``. Tools
    not in that set (and not in the always-review list of the active
    policy bundle) are observed only — never blocked.
    """
    return tool_name in MUTATING_TOOL_NAMES


def is_idempotent(tool_name: str) -> bool:
    """Read-only / idempotent tools we never review."""
    return tool_name in IDEMPOTENT_TOOL_NAMES


def is_irreversible(tool_name: str, args: Dict[str, Any]) -> bool:
    """Best-effort irreversibility check."""
    if tool_name in _IRREVERSIBLE_TOOLS:
        return True
    if tool_name == "terminal":
        cmd = args.get("command") if isinstance(args, dict) else None
        return _looks_irreversible_shell(cmd or "")
    return False


def _principal_from_session(session_id: str) -> str:
    """Resolve the human principal driving this session.

    v1 returns ``"user"`` always — gateway sessions all map to the local
    operator. Multi-tenant principal resolution is a v2 concern when we wire
    the multi-party approval routing.
    """
    return "user"


def build(
    *,
    tool_name: str,
    args: Optional[Dict[str, Any]],
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    user_task: Optional[str] = None,
    policy_bundle: str = "default",
    extra_context: Optional[Dict[str, Any]] = None,
    extra_stakeholders: Optional[List[str]] = None,
) -> ActionPacket:
    """Synthesize an ActionPacket from raw pre_tool_call kwargs."""
    safe_args: Dict[str, Any] = dict(args) if isinstance(args, dict) else {}

    state_change = is_mutating(tool_name)
    context: Dict[str, Any] = {
        "cwd": os.getcwd(),
        "tool_call_id": tool_call_id,
    }
    if user_task:
        context["user_task"] = user_task
    if extra_context:
        context.update(extra_context)

    stakeholders: List[str] = ["user"]
    if extra_stakeholders:
        for s in extra_stakeholders:
            if s and s not in stakeholders:
                stakeholders.append(s)

    return ActionPacket.new(
        tool=tool_name,
        args=safe_args,
        session_id=session_id,
        task_id=task_id,
        principal=_principal_from_session(session_id),
        state_change=state_change,
        irreversible=is_irreversible(tool_name, safe_args),
        mutating=state_change,
        context=context,
        stakeholders=stakeholders,
        policy_bundle=policy_bundle,
    )
