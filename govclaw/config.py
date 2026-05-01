"""Lightweight config accessor for GovClaw.

Reads the ``govclaw:`` block from Hermes's ``config.yaml`` (via the
existing ``hermes_cli.config`` helpers) with sensible defaults. We
intentionally don't add a new config file format — GovClaw is one block
inside the existing user config.

Defaults:

    govclaw:
      enabled: true
      policy_bundle: default
      reviewer:
        enabled: true
        timeout_s: 8
      audit:
        path: ~/.hermes/govclaw/audit.jsonl
      approvals:
        cli_self_approve: true
        gateway_multi_party: true
        ttl_secs: 3600
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class GovClawConfig:
    enabled: bool = True
    policy_bundle: str = "default"
    reviewer_enabled: bool = True
    reviewer_timeout_s: float = 8.0
    audit_path: Optional[str] = None
    approvals_cli_self_approve: bool = True
    approvals_gateway_multi_party: bool = True
    approval_ttl_secs: int = 3600


_DEFAULT = GovClawConfig()


def _get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def load() -> GovClawConfig:
    """Load and freeze the GovClaw config from ``~/.hermes/config.yaml``.

    Falls back silently to defaults if the config file is missing,
    malformed, or has no ``govclaw:`` block. Never raises — governance
    must keep working even if config IO breaks.
    """
    try:
        from hermes_cli.config import load_config  # local import — heavy
        cfg = load_config()
    except Exception:
        return _DEFAULT
    if not isinstance(cfg, dict):
        return _DEFAULT
    block = cfg.get("govclaw")
    if not isinstance(block, dict):
        return _DEFAULT

    return GovClawConfig(
        enabled=bool(_get(block, "enabled", default=_DEFAULT.enabled)),
        policy_bundle=str(_get(block, "policy_bundle", default=_DEFAULT.policy_bundle)),
        reviewer_enabled=bool(_get(block, "reviewer", "enabled", default=_DEFAULT.reviewer_enabled)),
        reviewer_timeout_s=float(_get(block, "reviewer", "timeout_s", default=_DEFAULT.reviewer_timeout_s)),
        audit_path=_get(block, "audit", "path", default=None),
        approvals_cli_self_approve=bool(
            _get(block, "approvals", "cli_self_approve", default=_DEFAULT.approvals_cli_self_approve)
        ),
        approvals_gateway_multi_party=bool(
            _get(block, "approvals", "gateway_multi_party", default=_DEFAULT.approvals_gateway_multi_party)
        ),
        approval_ttl_secs=int(_get(block, "approvals", "ttl_secs", default=_DEFAULT.approval_ttl_secs)),
    )
