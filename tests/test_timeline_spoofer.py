"""Tests for the timestomp module wired through the engagement context (T1070.006)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.audit import STATUS_APPLIED, STATUS_PLANNED, AuditJournal
from src.context import EngagementContext
from src.engagement import EngagementProfile
from src.errors import ScopeError
from src.timeline_spoofer import ACTION_SET, TECHNIQUE, FileTimes, PortableBackend, TimelineSpoofer

from conftest import make_profile_dict


def _spoofer(tmp_path, journal_path, *, dry_run=False) -> TimelineSpoofer:
    # Authorize the whole tmp dir so real files on this box are in scope.
    profile = EngagementProfile.from_dict(
        make_profile_dict(
            allowed_hosts=["*"],
            techniques=["T1070.006"],
            dry_run_default=dry_run,
            scope={"allowed_paths": [f"{tmp_path}/*"], "allowed_registry_keys": []},
        )
    )
    journal = AuditJournal(journal_path, profile.engagement_id, profile.operator)
    ctx = EngagementContext(profile, journal)
    return TimelineSpoofer(ctx, backend=PortableBackend())


def _make_file(tmp_path, name="target.txt") -> str:
    p = tmp_path / name
    p.write_text("payload", encoding="utf-8")
    return str(p)


def test_backdate_changes_then_reverts_exactly(tmp_path, journal_path):
    spoofer = _spoofer(tmp_path, journal_path)
    target = _make_file(tmp_path)
    original = spoofer.backend.capture(target)

    entry = spoofer.backdate(target, datetime(2020, 1, 15, 9, 0, tzinfo=timezone.utc))
    assert entry.status == STATUS_APPLIED
    assert entry.action == ACTION_SET and entry.technique == TECHNIQUE

    after = spoofer.backend.capture(target)
    assert datetime.fromtimestamp(after.modified_ns / 1e9, tz=timezone.utc).year == 2020
    assert after.modified_ns != original.modified_ns

    result = spoofer.context.revert()
    assert result.ok
    restored = spoofer.backend.capture(target)
    assert restored.modified_ns == original.modified_ns
    assert restored.accessed_ns == original.accessed_ns


def test_dry_run_does_not_touch_file(tmp_path, journal_path):
    spoofer = _spoofer(tmp_path, journal_path, dry_run=True)
    target = _make_file(tmp_path)
    original = spoofer.backend.capture(target)

    entry = spoofer.backdate(target, datetime(2019, 6, 1, tzinfo=timezone.utc))
    assert entry.status == STATUS_PLANNED
    assert spoofer.backend.capture(target).modified_ns == original.modified_ns  # unchanged
    # The before-state was still captured for the record.
    assert entry.before["modified_ns"] == original.modified_ns


def test_out_of_scope_path_refused(tmp_path, journal_path):
    spoofer = _spoofer(tmp_path, journal_path)
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    try:
        with pytest.raises(ScopeError):
            spoofer.backdate(str(outside), datetime(2020, 1, 1, tzinfo=timezone.utc))
        assert len(spoofer.context.journal) == 0  # nothing recorded
    finally:
        outside.unlink()


def test_set_times_only_modified_leaves_accessed(tmp_path, journal_path):
    spoofer = _spoofer(tmp_path, journal_path)
    target = _make_file(tmp_path)
    original = spoofer.backend.capture(target)

    spoofer.set_times(target, modified=datetime(2021, 3, 3, tzinfo=timezone.utc))
    after = spoofer.backend.capture(target)
    assert datetime.fromtimestamp(after.modified_ns / 1e9, tz=timezone.utc).year == 2021
    assert after.accessed_ns == original.accessed_ns  # untouched


def test_match_to_clones_reference_timestamps(tmp_path, journal_path):
    spoofer = _spoofer(tmp_path, journal_path)
    target = _make_file(tmp_path, "target.txt")
    reference = _make_file(tmp_path, "reference.txt")
    # Give the reference a distinctive time so the clone is observable.
    spoofer.set_times(reference, modified=datetime(2018, 12, 25, tzinfo=timezone.utc))
    ref_times = spoofer.backend.capture(reference)

    spoofer.match_to(target, reference)
    assert spoofer.backend.capture(target).modified_ns == ref_times.modified_ns


def test_filetimes_roundtrip():
    ft = FileTimes(accessed_ns=1, modified_ns=2, created_ns=None)
    assert FileTimes.from_dict(ft.to_dict()) == ft
    assert ft.as_iso()["created"] is None
    assert ft.as_iso()["modified"].startswith("1970-01-01")


def test_journal_feeds_report(tmp_path, journal_path):
    # The action a timestomp emits is exactly what the purple-team report consumes.
    from src.report import PurpleTeamReport

    spoofer = _spoofer(tmp_path, journal_path)
    target = _make_file(tmp_path)
    spoofer.backdate(target, datetime(2020, 1, 1, tzinfo=timezone.utc))

    report = PurpleTeamReport.from_journal(spoofer.context.journal)
    exps = report.expectations()
    assert len(exps) == 1
    assert exps[0].technique_id == "T1070.006"
    assert exps[0].technique_name == "Timestomp"
    assert target in exps[0].target
