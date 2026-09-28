"""Tests for the event-log control module wired through the context (T1562.002)."""

from __future__ import annotations

import pytest

from src.audit import STATUS_PLANNED, AuditJournal
from src.context import EngagementContext
from src.engagement import EngagementProfile
from src.errors import ScopeError, TechniqueNotAuthorizedError
from src.event_injector import InMemoryEventLogBackend, EventLogController

from conftest import make_profile_dict


def _controller(journal_path, *, dry_run=False, techniques=("T1562.002",),
                allowed=("Security", "Microsoft-Windows-Sysmon/Operational")):
    profile = EngagementProfile.from_dict(
        make_profile_dict(
            allowed_hosts=["*"],
            techniques=list(techniques),
            dry_run_default=dry_run,
            scope={"allowed_paths": [], "allowed_registry_keys": [], "allowed_channels": list(allowed)},
        )
    )
    journal = AuditJournal(journal_path, profile.engagement_id, profile.operator)
    ctx = EngagementContext(profile, journal)
    backend = InMemoryEventLogBackend()
    return EventLogController(ctx, backend), backend, ctx


def test_disable_then_revert(journal_path):
    controller, backend, ctx = _controller(journal_path)
    assert backend.is_enabled("Security") is True
    controller.disable_channel("Security")
    assert backend.is_enabled("Security") is False
    ctx.revert()
    assert backend.is_enabled("Security") is True


def test_enable_when_disabled_reverts_to_disabled(journal_path):
    controller, backend, ctx = _controller(journal_path)
    backend.set_enabled("Security", False)
    controller.enable_channel("Security")
    assert backend.is_enabled("Security") is True
    ctx.revert()
    assert backend.is_enabled("Security") is False


def test_out_of_scope_channel_refused(journal_path):
    controller, _, ctx = _controller(journal_path)
    with pytest.raises(ScopeError):
        controller.disable_channel("Application")  # not in allowed_channels
    assert len(ctx.journal) == 0


def test_unauthorized_technique_refused(journal_path):
    controller, _, _ = _controller(journal_path, techniques=("T1070.006",))
    with pytest.raises(TechniqueNotAuthorizedError):
        controller.disable_channel("Security")


def test_dry_run_changes_nothing(journal_path):
    controller, backend, _ = _controller(journal_path, dry_run=True)
    entry = controller.disable_channel("Security")
    assert entry.status == STATUS_PLANNED
    assert backend.is_enabled("Security") is True  # unchanged


def test_report_maps_technique(journal_path):
    from src.report import PurpleTeamReport

    controller, _, ctx = _controller(journal_path)
    controller.disable_channel("Security")
    report = PurpleTeamReport.from_journal(ctx.journal)
    exp = report.expectations()[0]
    assert exp.technique_id == "T1562.002"
    assert exp.technique_name == "Disable Windows Event Logging"
