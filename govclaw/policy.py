"""Deterministic policy engine.

Loads YAML policy bundles from ``govclaw/policies/`` and evaluates an
:class:`ActionPacket` against them. Returns a :class:`PolicyVerdict` that
the plugin uses directly (for hardline / auto-allow shortcuts) or hands to
the LLM reviewer.

The engine is intentionally narrow: it only handles patterns it can match
deterministically. Everything else is "needs review", which sends the
packet to the LLM. We never silently approve something the policy didn't
explicitly cover.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern

try:
    import yaml
except Exception:  # pragma: no cover — yaml is in hermes-agent's deps
    yaml = None  # type: ignore[assignment]

from .schemas import ActionPacket, Decision, allow, deny, require_approval

logger = logging.getLogger(__name__)


_POLICY_DIR = Path(__file__).parent / "policies"


# ---------------------------------------------------------------------------
# Bundle representation
# ---------------------------------------------------------------------------


@dataclass
class _CompiledRule:
    """A single approval/hardline rule with regexes pre-compiled."""

    id: str
    tool: Optional[str]
    command_patterns: List[Pattern[str]] = field(default_factory=list)
    args_contain: List[Pattern[str]] = field(default_factory=list)
    required: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    explanation: str = ""
    deny_message: str = ""

    def matches(self, packet: ActionPacket) -> bool:
        if self.tool and packet.proposed_action.tool != self.tool:
            return False
        if self.command_patterns or self.args_contain:
            haystack = self._haystack(packet)
            if self.command_patterns and not any(
                p.search(haystack) for p in self.command_patterns
            ):
                return False
            if self.args_contain and not any(
                p.search(haystack) for p in self.args_contain
            ):
                return False
        return True

    @staticmethod
    def _haystack(packet: ActionPacket) -> str:
        """Concatenate string-valued args into one searchable blob."""
        parts: List[str] = []
        cmd = packet.proposed_action.args.get("command")
        if isinstance(cmd, str):
            parts.append(cmd)
        for k, v in packet.proposed_action.args.items():
            if k == "command":
                continue
            if isinstance(v, str):
                parts.append(v)
        return "\n".join(parts)


@dataclass
class PolicyBundle:
    """Loaded + compiled policy bundle."""

    policy_id: str
    description: str = ""
    stakeholder_priority: List[str] = field(default_factory=list)
    hardline: List[_CompiledRule] = field(default_factory=list)
    approval_rules: List[_CompiledRule] = field(default_factory=list)
    auto_allow_tools: List[str] = field(default_factory=list)
    audit_all_state_changes: bool = True
    audit_all_denials: bool = True
    audit_all_approvals: bool = True
    audit_all_reviews: bool = True


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


@dataclass
class PolicyVerdict:
    """What the policy engine concluded.

    * ``hardline_deny`` — short-circuit to deny; do not call the reviewer.
    * ``auto_allow``    — short-circuit to allow; do not call the reviewer.
    * ``approval_required`` — at least one approval rule matched. Reviewer
      is still consulted to confirm (and may escalate further), but the
      required-approver list is already determined.
    * ``needs_review``  — defer to the reviewer entirely.
    """

    hardline_deny: bool = False
    auto_allow: bool = False
    approval_required: bool = False
    needs_review: bool = True
    matched_rule_ids: List[str] = field(default_factory=list)
    required_approvers: List[str] = field(default_factory=list)
    deny_message: str = ""
    approval_explanation: str = ""
    risk_level: str = "medium"

    def as_decision(self) -> Decision:
        """Materialise the verdict as a Decision (used when no reviewer ran)."""
        if self.hardline_deny:
            return deny(
                self.deny_message or "Hardline policy violation.",
                source="policy",
                policy_hits=list(self.matched_rule_ids),
            )
        if self.auto_allow:
            return allow(
                "Auto-allowed by policy.",
                source="policy",
                policy_hits=list(self.matched_rule_ids),
            )
        if self.approval_required:
            return require_approval(
                self.approval_explanation or "Policy requires approval.",
                self.required_approvers,
                risk_level=self.risk_level,
                source="policy",
                policy_hits=list(self.matched_rule_ids),
            )
        # Defer-to-reviewer state has no standalone Decision; the plugin
        # must call the reviewer. Falling back to a conservative
        # require_approval here makes the function total and safe.
        return require_approval(
            "No deterministic policy match; conservative fallback.",
            ["user"],
            source="fallback",
            policy_hits=list(self.matched_rule_ids),
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _compile_patterns(raw: Any) -> List[Pattern[str]]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    out: List[Pattern[str]] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        try:
            out.append(re.compile(entry, re.IGNORECASE))
        except re.error as exc:
            logger.warning("govclaw: skipping invalid regex %r: %s", entry, exc)
    return out


def _compile_rule(node: Dict[str, Any], *, hardline: bool) -> Optional[_CompiledRule]:
    when = node.get("when") or {}
    rule = _CompiledRule(
        id=str(node.get("id") or "anonymous"),
        tool=when.get("tool") if isinstance(when, dict) else None,
        command_patterns=_compile_patterns((when or {}).get("command_matches")),
        args_contain=_compile_patterns((when or {}).get("args_contain")),
        required=list(node.get("required") or []),
        risk_level=str(node.get("risk_level") or ("critical" if hardline else "medium")),
        explanation=str(node.get("explanation") or ""),
        deny_message=str(node.get("message") or "") if hardline else "",
    )
    if not rule.tool and not rule.command_patterns and not rule.args_contain:
        logger.warning("govclaw: rule %s has no match criteria; skipping", rule.id)
        return None
    return rule


def load_bundle(name: str = "default") -> PolicyBundle:
    """Load and compile the named policy bundle.

    Bundles live in ``govclaw/policies/<name>.yaml``. Falls back to a
    locked-down bundle (block everything mutating, require user approval)
    if the file is missing or unparseable — never silently no-ops.
    """
    if yaml is None:
        logger.warning("govclaw: PyYAML missing; using locked-down fallback bundle")
        return _fallback_bundle(name)

    path = _POLICY_DIR / f"{name}.yaml"
    if not path.is_file():
        # Allow bundles to live alongside user config too.
        user_dir = Path(os.path.expanduser("~/.hermes/govclaw/policies"))
        path = user_dir / f"{name}.yaml"
    if not path.is_file():
        logger.warning("govclaw: bundle %s not found; using fallback", name)
        return _fallback_bundle(name)

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        logger.error("govclaw: failed to parse %s: %s", path, exc)
        return _fallback_bundle(name)

    bundle = PolicyBundle(
        policy_id=str(data.get("policy_id") or name),
        description=str(data.get("description") or ""),
        stakeholder_priority=list(data.get("stakeholder_priority") or []),
        auto_allow_tools=list((data.get("auto_allow") or {}).get("tools") or []),
    )
    for raw in data.get("hardline_deny") or []:
        if isinstance(raw, dict):
            rule = _compile_rule(raw, hardline=True)
            if rule:
                bundle.hardline.append(rule)
    for raw in data.get("approval_rules") or []:
        if isinstance(raw, dict):
            rule = _compile_rule(raw, hardline=False)
            if rule:
                bundle.approval_rules.append(rule)

    audit = data.get("audit_rules") or {}
    if isinstance(audit, dict):
        bundle.audit_all_state_changes = bool(audit.get("all_state_changes", True))
        bundle.audit_all_denials = bool(audit.get("all_denials", True))
        bundle.audit_all_approvals = bool(audit.get("all_approvals", True))
        bundle.audit_all_reviews = bool(audit.get("all_reviews", True))

    return bundle


def _fallback_bundle(name: str) -> PolicyBundle:
    """Locked-down bundle used when a real bundle can't be loaded.

    Every mutating call requires user approval. Failing closed beats
    failing open when the policy file itself is broken.
    """
    bundle = PolicyBundle(
        policy_id=f"{name}_fallback",
        description="Locked-down fallback (real bundle unavailable).",
    )
    bundle.approval_rules.append(
        _CompiledRule(
            id="fallback_require_user_approval",
            tool=None,
            command_patterns=[],
            args_contain=[],
            required=["user"],
            risk_level="high",
            explanation="Policy bundle unavailable; conservative fallback.",
        )
    )
    return bundle


# Single bundle cache. Reload by passing ``force=True`` to :func:`get_bundle`.
_bundle_cache: Dict[str, PolicyBundle] = {}


def get_bundle(name: str = "default", *, force: bool = False) -> PolicyBundle:
    if force:
        _bundle_cache.pop(name, None)
    if name not in _bundle_cache:
        _bundle_cache[name] = load_bundle(name)
    return _bundle_cache[name]


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(packet: ActionPacket, bundle: Optional[PolicyBundle] = None) -> PolicyVerdict:
    """Run ``packet`` through the bundle and return a verdict."""
    if bundle is None:
        bundle = get_bundle(packet.policy_bundle)

    # 1. Hardline denials — first match wins.
    for rule in bundle.hardline:
        if rule.matches(packet):
            return PolicyVerdict(
                hardline_deny=True,
                needs_review=False,
                matched_rule_ids=[rule.id],
                deny_message=rule.deny_message or "Hardline policy violation.",
                risk_level="critical",
            )

    # 2. Auto-allow shortcut.
    if packet.proposed_action.tool in set(bundle.auto_allow_tools):
        return PolicyVerdict(
            auto_allow=True,
            needs_review=False,
            matched_rule_ids=[f"auto_allow:{packet.proposed_action.tool}"],
            risk_level="low",
        )

    # 3. Approval rules — collect all matches; union the required-approver lists.
    matched_ids: List[str] = []
    required: List[str] = []
    explanation_parts: List[str] = []
    risk_level = "medium"
    for rule in bundle.approval_rules:
        if rule.matches(packet):
            matched_ids.append(rule.id)
            for r in rule.required:
                if r not in required:
                    required.append(r)
            if rule.explanation:
                explanation_parts.append(rule.explanation)
            if _risk_rank(rule.risk_level) > _risk_rank(risk_level):
                risk_level = rule.risk_level

    if matched_ids:
        return PolicyVerdict(
            approval_required=True,
            needs_review=True,  # reviewer still consulted to confirm/escalate
            matched_rule_ids=matched_ids,
            required_approvers=required or ["user"],
            approval_explanation="; ".join(explanation_parts) or "Policy requires approval.",
            risk_level=risk_level,
        )

    # 4. No deterministic match — defer to the reviewer.
    return PolicyVerdict(needs_review=True, matched_rule_ids=[], risk_level="medium")


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_rank(level: str) -> int:
    return _RISK_ORDER.get(level, 1)
