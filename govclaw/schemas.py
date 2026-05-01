"""ActionPacket and Decision schemas.

These are the two structured types that flow through GovClaw:

* ``ActionPacket`` — built from a raw tool call before policy evaluation.
* ``Decision`` — produced by the policy engine and/or LLM reviewer.

Plain dataclasses (no pydantic) so importing GovClaw stays cheap and we don't
add a runtime dep. Validation is handled at construction time via the
``from_dict`` / ``ensure_valid`` classmethods.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set


# Decisions GovClaw v1 supports. ``transform`` is reserved for v2 (see plan
# §"Out of scope"). Anything outside this set fails closed.
ALLOWED_DECISIONS: Set[str] = {
    "allow",
    "deny",
    "require_approval",
}

# Risk levels the reviewer may emit. Used for audit ranking and approval
# routing; not enforced as gates.
RISK_LEVELS: Set[str] = {"low", "medium", "high", "critical"}


@dataclass
class ProposedAction:
    """The concrete tool invocation Hermes wants to make."""

    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    state_change: bool = False
    irreversible: bool = False
    mutating: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActionPacket:
    """Structured representation of a proposed agent action.

    Built by ``govclaw.intent.build`` from the raw kwargs the
    ``pre_tool_call`` hook receives.
    """

    trace_id: str
    actor: Dict[str, Any]
    proposed_action: ProposedAction
    context: Dict[str, Any] = field(default_factory=dict)
    stakeholders: List[str] = field(default_factory=list)
    policy_bundle: str = "default"
    created_at: float = field(default_factory=time.time)

    @classmethod
    def new(
        cls,
        *,
        tool: str,
        args: Dict[str, Any],
        session_id: str = "",
        task_id: str = "",
        principal: str = "user",
        state_change: bool = False,
        irreversible: bool = False,
        mutating: bool = False,
        context: Optional[Dict[str, Any]] = None,
        stakeholders: Optional[List[str]] = None,
        policy_bundle: str = "default",
    ) -> "ActionPacket":
        return cls(
            trace_id=str(uuid.uuid4()),
            actor={
                "agent": "hermes",
                "session_id": session_id,
                "task_id": task_id,
                "principal": principal,
            },
            proposed_action=ProposedAction(
                tool=tool,
                args=dict(args or {}),
                state_change=state_change,
                irreversible=irreversible,
                mutating=mutating,
            ),
            context=dict(context or {}),
            stakeholders=list(stakeholders or []),
            policy_bundle=policy_bundle,
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # asdict() recurses into ProposedAction already.
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, sort_keys=True)


@dataclass
class Decision:
    """The verdict GovClaw returns for a single ActionPacket.

    Produced by either the deterministic policy engine alone (for hardline
    deny / auto-allow shortcuts) or by the LLM reviewer (for ambiguous calls).
    """

    decision: str
    risk_level: str = "medium"
    explanation: str = ""
    policy_hits: List[str] = field(default_factory=list)
    required_approvals: List[str] = field(default_factory=list)
    affected_stakeholders: List[str] = field(default_factory=list)
    audit_required: bool = True
    source: str = "policy"  # "policy" | "reviewer" | "fallback"

    def __post_init__(self) -> None:
        if self.decision not in ALLOWED_DECISIONS:
            raise ValueError(
                f"invalid decision {self.decision!r}; "
                f"must be one of {sorted(ALLOWED_DECISIONS)}"
            )
        if self.risk_level not in RISK_LEVELS:
            raise ValueError(
                f"invalid risk_level {self.risk_level!r}; "
                f"must be one of {sorted(RISK_LEVELS)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Decision":
        """Build from a dict (e.g. parsed from the reviewer LLM JSON output).

        Drops unknown keys silently so reviewer prompts can evolve without
        breaking existing audit logs.
        """
        kwargs = {
            k: data[k]
            for k in (
                "decision",
                "risk_level",
                "explanation",
                "policy_hits",
                "required_approvals",
                "affected_stakeholders",
                "audit_required",
                "source",
            )
            if k in data
        }
        return cls(**kwargs)


def deny(reason: str, *, source: str = "policy", policy_hits: Optional[List[str]] = None) -> Decision:
    """Convenience constructor for a hard-deny decision."""
    return Decision(
        decision="deny",
        risk_level="critical",
        explanation=reason,
        policy_hits=list(policy_hits or []),
        source=source,
    )


def allow(reason: str = "", *, source: str = "policy", policy_hits: Optional[List[str]] = None) -> Decision:
    """Convenience constructor for an allow decision."""
    return Decision(
        decision="allow",
        risk_level="low",
        explanation=reason,
        policy_hits=list(policy_hits or []),
        source=source,
    )


def require_approval(
    reason: str,
    approvers: List[str],
    *,
    risk_level: str = "high",
    source: str = "policy",
    policy_hits: Optional[List[str]] = None,
) -> Decision:
    """Convenience constructor for a require_approval decision."""
    return Decision(
        decision="require_approval",
        risk_level=risk_level,
        explanation=reason,
        policy_hits=list(policy_hits or []),
        required_approvals=list(approvers),
        source=source,
    )
