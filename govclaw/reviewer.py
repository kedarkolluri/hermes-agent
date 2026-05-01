"""LLM reviewer — second-opinion governance call.

Invoked when the deterministic policy engine returns ``needs_review`` (i.e.
the call isn't auto-allowed and isn't hardline-denied). The reviewer calls
Hermes's existing auxiliary LLM client (:func:`agent.auxiliary_client.call_llm`)
under the ``governance`` task slot and parses a structured Decision out of
the response.

Invariants the reviewer enforces *after* it gets the LLM's answer:

1. **Cannot weaken a hardline deny** — but hardline denials never reach the
   reviewer in the first place; the plugin short-circuits earlier.
2. **Cannot drop a policy-required approver** — if the policy engine listed
   ``required_approvers``, the reviewer's own list is unioned with them.
3. **Decision must be one of the v1-supported values** — anything else
   collapses to ``require_approval`` (fail-closed).
4. **Parse failure → fall back to the policy verdict**, so a flaky LLM
   never causes a tool to execute that the policy wouldn't have allowed
   on its own.

The reviewer is sync (the surrounding ``pre_tool_call`` hook is sync).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .policy import PolicyVerdict
from .schemas import (
    ALLOWED_DECISIONS,
    ActionPacket,
    Decision,
    require_approval,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT = """\
You are GovClaw, a stakeholder-governance reviewer for an autonomous agent
named Hermes. Hermes proposes tool calls; you decide whether each call should
be allowed, denied, or held for human approval.

You serve the user's interests, not Hermes's convenience. Your priorities,
in order:
  1. Law and regulation
  2. The user's explicit authorization
  3. Data integrity and reversibility
  4. Convenience

Reply with JSON ONLY, matching this schema exactly:
{
  "decision": "allow" | "deny" | "require_approval",
  "risk_level": "low" | "medium" | "high" | "critical",
  "explanation": "<one or two sentences>",
  "required_approvals": ["user", ...],   // only when decision=require_approval
  "affected_stakeholders": ["..."]
}

Rules:
- If a deterministic policy rule already required approval, you MUST keep
  decision="require_approval" or stricter (you may add more approvers, never
  remove them).
- For irreversible side effects on external systems (sending messages,
  scheduling cron, destructive git, outbound POST/PUT/DELETE, package
  install), default to require_approval unless the user has clearly
  authorized this exact action.
- Prefer require_approval over allow when in doubt.
- Never weaken a policy hit. Never approve something the policy denied.

No prose outside the JSON. No markdown fences.
"""


def _packet_brief(packet: ActionPacket) -> Dict[str, Any]:
    """Compact JSON view of the packet for the reviewer prompt."""
    return {
        "trace_id": packet.trace_id,
        "actor": packet.actor,
        "stakeholders": packet.stakeholders,
        "policy_bundle": packet.policy_bundle,
        "proposed_action": packet.proposed_action.to_dict(),
        "context": {
            k: v for k, v in packet.context.items() if k in {"cwd", "user_task"}
        },
    }


def _verdict_brief(verdict: PolicyVerdict) -> Dict[str, Any]:
    return {
        "matched_rule_ids": verdict.matched_rule_ids,
        "approval_required": verdict.approval_required,
        "required_approvers": verdict.required_approvers,
        "approval_explanation": verdict.approval_explanation,
        "risk_level": verdict.risk_level,
    }


def build_messages(
    packet: ActionPacket, verdict: PolicyVerdict
) -> List[Dict[str, str]]:
    """Build the chat messages payload for the reviewer call."""
    user_payload = {
        "action_packet": _packet_brief(packet),
        "policy_verdict": _verdict_brief(verdict),
        "instructions": (
            "Review the proposed action above and return a JSON Decision. "
            "If policy_verdict.approval_required is true, you must keep "
            "decision='require_approval' or stricter."
        ),
    }
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(user_payload, sort_keys=True)},
    ]


# ---------------------------------------------------------------------------
# Client glue
# ---------------------------------------------------------------------------


# A minimal Callable[[messages, **kwargs], str] surface so tests can inject a
# fake without monkey-patching the global auxiliary client.
ReviewerClient = Callable[..., str]


def _default_client(messages: List[Dict[str, str]], *, timeout: float = 8.0) -> str:
    """Default reviewer client — calls Hermes's auxiliary LLM.

    Reads provider/model from the ``auxiliary.governance`` config slot if
    present; otherwise falls back to the ``approval`` slot Hermes already
    configures (so existing setups work without new config). Returns the
    raw text content; parsing happens upstream.
    """
    from agent.auxiliary_client import call_llm  # local import — heavy module

    try:
        response = call_llm(
            task="governance",
            messages=messages,
            temperature=0.0,
            max_tokens=512,
            timeout=timeout,
        )
    except RuntimeError:
        # No "governance" task configured — fall back to the "approval" slot
        # which the smart-approval feature already uses.
        response = call_llm(
            task="approval",
            messages=messages,
            temperature=0.0,
            max_tokens=512,
            timeout=timeout,
        )

    try:
        return response.choices[0].message.content or ""
    except (AttributeError, IndexError):
        return ""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def parse_response(raw: str) -> Optional[Dict[str, Any]]:
    """Best-effort JSON extraction from the reviewer response.

    Tolerates surrounding prose (some models add a sentence despite the
    prompt) by grabbing the first balanced ``{...}`` object. Returns None
    on failure; callers should fall back to the policy verdict.
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    # Strip code fences if present.
    if raw.startswith("```"):
        raw = raw.strip("`")
        # Drop a leading "json\n" tag.
        if raw.lower().startswith("json"):
            raw = raw[4:].lstrip("\n")

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    match = _JSON_OBJECT_RE.search(raw)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


@dataclass
class ReviewerConfig:
    enabled: bool = True
    timeout_s: float = 8.0
    client: Optional[ReviewerClient] = None


def review(
    packet: ActionPacket,
    verdict: PolicyVerdict,
    config: Optional[ReviewerConfig] = None,
) -> Decision:
    """Run the reviewer and return a final Decision.

    Falls back to ``verdict.as_decision()`` on any failure (network, parse,
    schema-violation). Never raises.
    """
    cfg = config or ReviewerConfig()
    if not cfg.enabled:
        return verdict.as_decision()

    client: ReviewerClient = cfg.client or _default_client
    messages = build_messages(packet, verdict)

    try:
        raw = client(messages, timeout=cfg.timeout_s)
    except Exception as exc:
        logger.warning("govclaw reviewer call failed: %s", exc)
        return _fallback(verdict, reason="reviewer_call_failed")

    parsed = parse_response(raw)
    if not isinstance(parsed, dict):
        logger.warning("govclaw reviewer returned unparseable response: %r", raw[:200])
        return _fallback(verdict, reason="reviewer_unparseable")

    decision_value = parsed.get("decision")
    if decision_value not in ALLOWED_DECISIONS:
        logger.warning("govclaw reviewer returned unknown decision %r", decision_value)
        return _fallback(verdict, reason="reviewer_unknown_decision")

    # Build a Decision, defaulting fields the LLM omitted.
    try:
        decision = Decision.from_dict({
            **parsed,
            "source": "reviewer",
            "policy_hits": list(verdict.matched_rule_ids)
                + list(parsed.get("policy_hits") or []),
        })
    except (TypeError, ValueError) as exc:
        logger.warning("govclaw reviewer Decision construction failed: %s", exc)
        return _fallback(verdict, reason="reviewer_invalid_fields")

    return _enforce_invariants(decision, verdict)


# ---------------------------------------------------------------------------
# Invariants & fallback
# ---------------------------------------------------------------------------


def _fallback(verdict: PolicyVerdict, *, reason: str) -> Decision:
    """Conservative fallback: prefer the policy verdict over an unusable LLM.

    If the policy itself was ``needs_review`` with no rule matches, fall
    back to require_approval([user]) — never auto-allow on the LLM's
    behalf if it didn't tell us anything we can validate.
    """
    if verdict.hardline_deny or verdict.auto_allow or verdict.approval_required:
        d = verdict.as_decision()
        d.source = "fallback"
        d.policy_hits = list(d.policy_hits) + [f"fallback:{reason}"]
        return d
    return require_approval(
        f"Reviewer unavailable ({reason}); requiring user approval.",
        ["user"],
        risk_level="high",
        source="fallback",
        policy_hits=[f"fallback:{reason}"],
    )


def _enforce_invariants(decision: Decision, verdict: PolicyVerdict) -> Decision:
    """Apply the no-weakening rules described in this module's docstring."""
    if verdict.hardline_deny:
        # Defensive — should never happen because plugin short-circuits before
        # the reviewer runs. If it does, the deny stands.
        decision.decision = "deny"
        decision.risk_level = "critical"
        decision.policy_hits = list(decision.policy_hits) + ["enforced:hardline"]
        return decision

    if verdict.approval_required:
        if decision.decision == "allow":
            decision.decision = "require_approval"
            decision.policy_hits = list(decision.policy_hits) + [
                "enforced:no_weaken_policy_approval"
            ]
        # Union approver lists — never drop a policy-required approver.
        merged: List[str] = list(decision.required_approvals)
        for a in verdict.required_approvers:
            if a not in merged:
                merged.append(a)
        decision.required_approvals = merged or ["user"]
        # Risk floor: keep the policy's risk level if higher.
        if _rank(verdict.risk_level) > _rank(decision.risk_level):
            decision.risk_level = verdict.risk_level

    if decision.decision == "require_approval" and not decision.required_approvals:
        decision.required_approvals = ["user"]

    return decision


_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _rank(level: str) -> int:
    return _RANK.get(level, 1)
