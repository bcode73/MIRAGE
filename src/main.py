"""MIRAGE command-line orchestrator.

Ties the pieces together into a usable tool: load an engagement profile, open the
tamper-evident audit journal (optionally HMAC-signed), run authorized modules,
roll everything back, and generate the purple-team detection report.

Every state-changing command runs through :class:`~src.context.EngagementContext`,
so nothing happens outside the engagement's scope and everything is journaled.

Usage examples::

    # Backdate a file (planned only, unless the profile allows applying)
    python -m src.main timestomp backdate --profile eng.json --journal run.jsonl \\
        C:/RedTeamLab/secret.txt 2024-01-15 --no-dry-run

    # Roll back everything recorded in the journal
    python -m src.main revert --profile eng.json --journal run.jsonl

    # Produce the detection report for the SOC
    python -m src.main report --journal run.jsonl --profile eng.json --out ./out
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):  # allow `python src/main.py` as well as `-m src.main`
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import timeline_spoofer
from src.audit import AuditJournal, ReverterRegistry
from src.context import EngagementContext
from src.engagement import EngagementProfile
from src.errors import ConfigError, MirageError
from src.report import PurpleTeamReport
from src.timeline_spoofer import TimelineSpoofer


def _parse_dt(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigError(f"invalid date/time {value!r} (use ISO-8601, e.g. 2024-01-15 or 2024-01-15T09:00:00Z)") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_hmac_key(args: argparse.Namespace) -> bytes | None:
    if getattr(args, "hmac_key_file", None):
        key = Path(args.hmac_key_file).read_bytes().strip()
        return key or None
    if getattr(args, "hmac_key_env", None):
        value = os.environ.get(args.hmac_key_env)
        return value.encode("utf-8") if value else None
    return None


def _all_reverters(backend=None) -> ReverterRegistry:
    registry = ReverterRegistry()
    timeline_spoofer.register_reverters(registry, backend)
    return registry


def _require(args: argparse.Namespace, *names: str) -> None:
    for name in names:
        if not getattr(args, name, None):
            raise ConfigError(f"--{name.replace('_', '-')} is required for this command")


def _build_context(args: argparse.Namespace) -> EngagementContext:
    _require(args, "profile", "journal")
    profile = EngagementProfile.load(args.profile)
    journal = AuditJournal(
        args.journal, profile.engagement_id, profile.operator, hmac_key=_load_hmac_key(args)
    )
    dry_run = getattr(args, "dry_run", None)
    return EngagementContext(profile, journal, _all_reverters(), dry_run=dry_run)


def _print_entry(entry) -> None:
    print(f"[{entry.status}] #{entry.seq} {entry.action} ({entry.technique}) -> {entry.target}")
    if entry.before is not None:
        print(f"  before: {entry.before}")
    if entry.after is not None:
        print(f"  after:  {entry.after}")


# commands

def cmd_timestomp(args: argparse.Namespace) -> int:
    ctx = _build_context(args)
    spoofer = TimelineSpoofer(ctx)
    if args.ts_action == "backdate":
        entry = spoofer.backdate(args.file, _parse_dt(args.when))
    elif args.ts_action == "set":
        if not (args.modified or args.accessed or args.created):
            raise ConfigError("set requires at least one of --modified/--accessed/--created")
        entry = spoofer.set_times(
            args.file,
            modified=_parse_dt(args.modified) if args.modified else None,
            accessed=_parse_dt(args.accessed) if args.accessed else None,
            created=_parse_dt(args.created) if args.created else None,
        )
    elif args.ts_action == "match":
        entry = spoofer.match_to(args.file, args.reference)
    else:  # pragma: no cover - argparse enforces choices
        raise ConfigError(f"unknown timestomp action {args.ts_action!r}")
    _print_entry(entry)
    if ctx.dry_run:
        print("(dry run: no changes were applied)")
    return 0


def cmd_revert(args: argparse.Namespace) -> int:
    ctx = _build_context(args)
    result = ctx.revert(strict=args.strict)
    print(f"reverted {len(result.reverted)} action(s)")
    if result.failed:
        print(f"failed to revert {len(result.failed)} action(s):")
        for seq, reason in sorted(result.failed.items()):
            print(f"  #{seq}: {reason}")
        return 1
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    _require(args, "journal")
    profile = EngagementProfile.load(args.profile) if args.profile else None
    engagement_id = profile.engagement_id if profile else "report"
    operator = profile.operator if profile else "report"
    journal = AuditJournal(args.journal, engagement_id, operator, hmac_key=_load_hmac_key(args))
    report = PurpleTeamReport.from_journal(journal, profile)
    if args.out:
        paths = report.write_files(args.out)
        for kind, path in paths.items():
            print(f"{kind}: {path}")
        return 0
    if args.format == "json":
        print(report.to_json())
    elif args.format == "navigator":
        import json

        print(json.dumps(report.to_navigator_layer(), indent=2, ensure_ascii=False))
    else:
        print(report.to_markdown())
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _require(args, "journal")
    # AuditJournal verifies the hash chain (and signatures, if a key is given) on load.
    journal = AuditJournal(args.journal, "verify", "verify", hmac_key=_load_hmac_key(args))
    count = len(journal)
    print(f"journal OK: {count} {'entry' if count == 1 else 'entries'} verified")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    _require(args, "profile")
    profile = EngagementProfile.load(args.profile)
    print(f"Engagement: {profile.engagement_id}  ({profile.client})")
    print(f"Operator:   {profile.operator}   Authorized by: {profile.authorized_by}")
    print(f"Window:     {profile.starts_at.isoformat()} -> {profile.expires_at.isoformat()}")
    print(f"Active now: {profile.is_active()}")
    print(f"Hosts:      {', '.join(profile.allowed_hosts)}")
    print(f"Techniques: {', '.join(profile.techniques)}")
    print(f"Dry-run default: {profile.dry_run_default}")
    if getattr(args, "journal", None) and Path(args.journal).exists():
        journal = AuditJournal(args.journal, profile.engagement_id, profile.operator, hmac_key=_load_hmac_key(args))
        print(f"Journal:    {len(journal)} entries, {len(journal.pending_applied())} pending revert")
    return 0


# parser

def _add_engagement_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="path to the engagement profile JSON")
    parser.add_argument("--journal", help="path to the audit journal (JSONL)")
    parser.add_argument("--hmac-key-env", help="environment variable holding the journal HMAC key")
    parser.add_argument("--hmac-key-file", help="file holding the journal HMAC key")


def build_parser() -> argparse.ArgumentParser:
    eng = argparse.ArgumentParser(add_help=False)
    _add_engagement_args(eng)

    parser = argparse.ArgumentParser(prog="mirage", description="MIRAGE adversary-emulation orchestrator")
    sub = parser.add_subparsers(dest="command", required=True)

    # timestomp
    tp = sub.add_parser("timestomp", help="file timestamp manipulation (T1070.006)")
    ts_sub = tp.add_subparsers(dest="ts_action", required=True)

    bd = ts_sub.add_parser("backdate", parents=[eng], help="set all timestamps to one point in time")
    bd.add_argument("file")
    bd.add_argument("when", help="ISO-8601 date or datetime")
    bd.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None)
    bd.set_defaults(func=cmd_timestomp)

    st = ts_sub.add_parser("set", parents=[eng], help="set a subset of timestamps")
    st.add_argument("file")
    st.add_argument("--modified")
    st.add_argument("--accessed")
    st.add_argument("--created")
    st.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None)
    st.set_defaults(func=cmd_timestomp)

    mt = ts_sub.add_parser("match", parents=[eng], help="clone another file's timestamps")
    mt.add_argument("file")
    mt.add_argument("reference")
    mt.add_argument("--dry-run", action=argparse.BooleanOptionalAction, default=None)
    mt.set_defaults(func=cmd_timestomp)

    # revert
    rv = sub.add_parser("revert", parents=[eng], help="roll back every applied action in the journal")
    rv.add_argument("--strict", action=argparse.BooleanOptionalAction, default=False,
                    help="abort on the first failure instead of continuing")
    rv.set_defaults(func=cmd_revert)

    # report
    rp = sub.add_parser("report", parents=[eng], help="generate the purple-team detection report")
    rp.add_argument("--out", help="output directory (writes json, md, and navigator files)")
    rp.add_argument("--format", choices=("json", "md", "navigator"), default="md",
                    help="stdout format when --out is not given (default: md)")
    rp.set_defaults(func=cmd_report)

    # verify
    vf = sub.add_parser("verify", parents=[eng], help="verify the journal's integrity")
    vf.set_defaults(func=cmd_verify)

    # info
    nf = sub.add_parser("info", parents=[eng], help="show engagement and journal summary")
    nf.set_defaults(func=cmd_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except MirageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
