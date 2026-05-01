"""``hermes govclaw`` CLI subcommand handlers.

Subcommands:

* ``list``    — show pending approvals (optionally filtered by session).
* ``approve`` — grant a pending approval by id.
* ``deny``    — deny a pending approval by id.
* ``audit``   — tail or print the audit log.
* ``policy``  — show the active policy bundle (id, rule counts).

Designed to be called from ``hermes_cli/main.py`` via a thin dispatcher;
each handler returns an int exit code and prints to stdout/stderr directly
so it composes with the rest of the Hermes CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import audit
from .approvals import store
from .config import load as load_config
from .policy import get_bundle


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_list(args: argparse.Namespace) -> int:
    records = store.pending(session_id=args.session or None)
    if not records:
        print("No pending approvals.")
        return 0
    print(f"{'ID':36}  {'TOOL':16}  {'REQUIRED':24}  AGE_S")
    import time
    now = time.time()
    for r in records:
        age = int(now - r.created_at)
        req = ",".join(r.required)
        if len(req) > 23:
            req = req[:22] + "…"
        print(f"{r.approval_id:36}  {r.tool:16}  {req:24}  {age}")
    return 0


def _resolve_one(approval_id: str, *, grant: bool, actor: str) -> int:
    rec = store.resolve(approval_id, actor=actor, grant=grant)
    if rec is None:
        print(f"Unknown approval id: {approval_id}", file=sys.stderr)
        return 1
    audit.log_approval_resolution(
        approval_id=rec.approval_id,
        trace_id=rec.trace_id,
        status=rec.status,
        granted_by=actor if grant else None,
        denied_by=actor if not grant else None,
        note="cli_subcommand",
    )
    verb = "approved" if grant else "denied"
    print(
        f"Approval {rec.approval_id} {verb} by {actor}. "
        f"Status: {rec.status}. Granted: {rec.granted}. Denied: {rec.denied}."
    )
    return 0 if rec.status in {"approved", "pending"} else 0


def _cmd_approve(args: argparse.Namespace) -> int:
    return _resolve_one(args.approval_id, grant=True, actor=args.as_user or "user")


def _cmd_deny(args: argparse.Namespace) -> int:
    return _resolve_one(args.approval_id, grant=False, actor=args.as_user or "user")


def _cmd_audit(args: argparse.Namespace) -> int:
    cfg = load_config()
    path: Path = audit.audit_path(cfg.audit_path)
    if not path.exists():
        print(f"No audit log at {path}", file=sys.stderr)
        return 1

    if args.json:
        with open(path) as f:
            for line in f:
                sys.stdout.write(line)
        return 0

    # Human-friendly tail.
    n = max(1, args.tail)
    lines: List[str] = []
    with open(path) as f:
        for line in f:
            lines.append(line)
            if len(lines) > n:
                lines.pop(0)
    for line in lines:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            sys.stdout.write(line)
            continue
        et = d.get("event_type", "?")
        if et == "decision":
            print(
                f"[{d.get('ts'):.3f}] decision  {d.get('tool'):16} "
                f"{d.get('decision'):16} src={d.get('source')} "
                f"hits={','.join(d.get('policy_hits') or []) or '-'}"
            )
        elif et == "outcome":
            print(
                f"[{d.get('ts'):.3f}] outcome   {d.get('tool'):16} "
                f"dur={d.get('duration_ms')}ms "
                f"trace={d.get('trace_id')[:8]}"
            )
        elif et == "approval_resolved":
            print(
                f"[{d.get('ts'):.3f}] approval  {d.get('approval_id')[:8]} "
                f"-> {d.get('status'):10} "
                f"by={d.get('granted_by') or d.get('denied_by') or '-'}"
            )
        else:
            sys.stdout.write(line)
    return 0


def _cmd_policy(args: argparse.Namespace) -> int:
    cfg = load_config()
    bundle = get_bundle(args.bundle or cfg.policy_bundle, force=True)
    print(f"policy_id        : {bundle.policy_id}")
    print(f"description      : {bundle.description.strip().splitlines()[0] if bundle.description else '(none)'}")
    print(f"hardline rules   : {len(bundle.hardline)}")
    print(f"approval rules   : {len(bundle.approval_rules)}")
    print(f"auto_allow tools : {', '.join(bundle.auto_allow_tools) or '(none)'}")
    print(f"audit settings   : "
          f"state_changes={bundle.audit_all_state_changes}, "
          f"denials={bundle.audit_all_denials}, "
          f"approvals={bundle.audit_all_approvals}, "
          f"reviews={bundle.audit_all_reviews}")
    return 0


# ---------------------------------------------------------------------------
# Argument parser + dispatcher
# ---------------------------------------------------------------------------


def attach_subparsers(parent: argparse._SubParsersAction) -> None:
    """Attach the govclaw subcommands to an existing argparse subparser group.

    Used by ``hermes_cli/main.py`` so ``hermes govclaw <cmd>`` shares the
    same top-level parser as the rest of the CLI.
    """
    p_list = parent.add_parser("list", help="List pending approvals.")
    p_list.add_argument("--session", help="Filter by session id.", default=None)
    p_list.set_defaults(func=_cmd_list)

    p_approve = parent.add_parser("approve", help="Approve a pending request.")
    p_approve.add_argument("approval_id")
    p_approve.add_argument("--as-user", help="Actor name (default: user).", default=None,
                           dest="as_user")
    p_approve.set_defaults(func=_cmd_approve)

    p_deny = parent.add_parser("deny", help="Deny a pending request.")
    p_deny.add_argument("approval_id")
    p_deny.add_argument("--as-user", help="Actor name (default: user).", default=None,
                        dest="as_user")
    p_deny.set_defaults(func=_cmd_deny)

    p_audit = parent.add_parser("audit", help="Tail or dump the audit log.")
    p_audit.add_argument("--tail", type=int, default=20, help="Lines from end (default: 20).")
    p_audit.add_argument("--json", action="store_true", help="Print raw JSONL.")
    p_audit.set_defaults(func=_cmd_audit)

    p_policy = parent.add_parser("policy", help="Show the active policy bundle.")
    p_policy.add_argument("--bundle", default=None, help="Bundle name override.")
    p_policy.set_defaults(func=_cmd_policy)


def build_parser(prog: str = "hermes govclaw") -> argparse.ArgumentParser:
    """Standalone parser — used by ``python -m govclaw.cli`` and tests."""
    parser = argparse.ArgumentParser(
        prog=prog,
        description="GovClaw — stakeholder governance runtime for Hermes.",
    )
    subs = parser.add_subparsers(dest="cmd", required=True)
    attach_subparsers(subs)
    return parser


def cmd_govclaw(args: argparse.Namespace) -> int:
    """Hermes-CLI dispatcher entry — invoked by ``hermes govclaw ...``.

    The top-level parser stores the subcommand handler in ``args.func``;
    if no subcommand was given, print usage.
    """
    func = getattr(args, "func", None)
    if func is None or func is cmd_govclaw:
        build_parser().print_help()
        return 2
    return int(func(args))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
