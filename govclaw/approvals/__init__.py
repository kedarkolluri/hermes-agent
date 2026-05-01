"""Approval state machine + delivery channels.

Submodules:

* :mod:`store` — SQLite-backed pending approvals table.
* :mod:`cli_channel` — synchronous self-approval via the existing
  ``tools/approval.py`` CLI prompt.
* :mod:`gateway_channel` — multi-party delivery via Hermes's gateway
  adapters (Telegram/Discord/Slack/etc.).

The plugin (``govclaw.plugin``) orchestrates these — request a pending
record, route to the right channel based on required-approver list and
session surface, and let the agent loop retry once approvals come back.
"""

from .store import (
    ApprovalRecord,
    cache_key_for,
    request as request_approval,
    resolve as resolve_approval,
    fetch_cached_grant,
    pending,
    record as fetch_record,
)

__all__ = [
    "ApprovalRecord",
    "cache_key_for",
    "request_approval",
    "resolve_approval",
    "fetch_cached_grant",
    "pending",
    "fetch_record",
]
