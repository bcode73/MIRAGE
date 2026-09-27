"""End-to-end tests for the engagement context backbone (#1 + #2 together)."""

from __future__ import annotations

import pytest

from src.audit import STATUS_APPLIED, STATUS_PLANNED, AuditJournal
from src.context import EngagementContext
from src.engagement import EngagementProfile
from src.errors import ScopeError, TechniqueNotAuthorizedError

from conftest import make_profile_dict


def _context(journal_path, **overrides) -> tuple[EngagementContext, dict]:
    profile = EngagementProfile.from_dict(make_profile_dict(**overrides))
    journal = AuditJournal(journal_path, profile.engagement_id, profile.operator)
    return EngagementContext(profile, journal), {"k": "original"}


def _kv_action(ctx, store, *, target="C:/RedTeamLab/a.txt"):
    return ctx.perform(
        action="kv.set",
        technique="T1070.006",
        target=target,
        target_kind="path",
        capture_before=lambda: {"value": store["k"]},
        apply=lambda: store.__setitem__("k", "tampered") or {"value": "tampered"},
        reverter=lambda entry: store.__setitem__("k", entry.before["value"]),
    )


def test_apply_then_revert_roundtrip(journal_path):
    ctx, store = _context(journal_path)  # dry_run False by default in make_profile_dict
    entry = _kv_action(ctx, store)
    assert entry.status == STATUS_APPLIED
    assert store["k"] == "tampered"

    result = ctx.revert()
    assert result.ok
    assert store["k"] == "original"


def test_dry_run_plans_without_applying(journal_path):
    ctx, store = _context(journal_path, dry_run_default=True)
    entry = _kv_action(ctx, store)
    assert entry.status == STATUS_PLANNED
    assert store["k"] == "original"          # apply() was never called
    assert entry.before == {"value": "original"}


def test_out_of_scope_target_blocked_before_apply(journal_path):
    ctx, store = _context(journal_path)
    with pytest.raises(ScopeError):
        _kv_action(ctx, store, target="C:/Windows/System32/evil.txt")
    assert store["k"] == "original"          # nothing applied
    assert len(ctx.journal) == 0             # nothing journaled


def test_unauthorized_technique_blocked(journal_path):
    ctx, store = _context(journal_path)
    with pytest.raises(TechniqueNotAuthorizedError):
        ctx.perform(
            action="kv.set",
            technique="T1055",  # not authorized
            target="C:/RedTeamLab/a.txt",
            target_kind="path",
            capture_before=lambda: {"value": store["k"]},
            apply=lambda: {"value": "x"},
        )


def test_wrong_host_fails_context_construction(journal_path):
    profile = EngagementProfile.from_dict(make_profile_dict(allowed_hosts=["some-other-box"]))
    journal = AuditJournal(journal_path, profile.engagement_id, profile.operator)
    with pytest.raises(Exception):
        EngagementContext(profile, journal)
