"""Tests for the registry artifact module wired through the context (T1112)."""

from __future__ import annotations

import pytest

from src.audit import STATUS_PLANNED, AuditJournal
from src.context import EngagementContext
from src.engagement import EngagementProfile
from src.errors import ScopeError, TechniqueNotAuthorizedError
from src.registry_planter import (
    MARKER_NAME,
    RECENTDOCS_KEY,
    InMemoryRegistryBackend,
    RegistryPlanter,
    RegValue,
)

from conftest import make_profile_dict

KEY = r"HKCU\Software\Test\App"


def _planter(journal_path, *, dry_run=False, attributable=True, techniques=("T1112",),
             allowed=(r"HKCU\Software\Test\*", RECENTDOCS_KEY + r"\*")):
    profile = EngagementProfile.from_dict(
        make_profile_dict(
            allowed_hosts=["*"],
            techniques=list(techniques),
            dry_run_default=dry_run,
            scope={"allowed_paths": [], "allowed_registry_keys": list(allowed)},
        )
    )
    journal = AuditJournal(journal_path, profile.engagement_id, profile.operator)
    ctx = EngagementContext(profile, journal)
    backend = InMemoryRegistryBackend()
    return RegistryPlanter(ctx, backend, attributable=attributable), backend, ctx


def test_set_value_applies_and_reverts(journal_path):
    planter, backend, ctx = _planter(journal_path)
    planter.set_value(KEY, "Downloaded", "C:/loot/tool.exe")
    assert backend.get_value(KEY, "Downloaded").data == "C:/loot/tool.exe"
    assert backend.get_value(KEY, MARKER_NAME).data == "TEST-2026-001"  # attributability marker

    ctx.revert()
    assert backend.get_value(KEY, "Downloaded") is None
    assert backend.get_value(KEY, MARKER_NAME) is None  # marker removed too


def test_attributable_false_writes_no_marker(journal_path):
    planter, backend, _ = _planter(journal_path, attributable=False)
    planter.set_value(KEY, "Downloaded", "x")
    assert backend.get_value(KEY, MARKER_NAME) is None


def test_overwrite_restores_original_value(journal_path):
    planter, backend, ctx = _planter(journal_path, attributable=False)
    backend.set_value(KEY, "Existing", RegValue("REG_SZ", "original"))
    planter.set_value(KEY, "Existing", "tampered")
    assert backend.get_value(KEY, "Existing").data == "tampered"
    ctx.revert()
    assert backend.get_value(KEY, "Existing").data == "original"


def test_remove_value_reverts_to_original(journal_path):
    planter, backend, ctx = _planter(journal_path, attributable=False)
    backend.set_value(KEY, "Doomed", RegValue("REG_SZ", "keepme"))
    planter.remove_value(KEY, "Doomed")
    assert backend.get_value(KEY, "Doomed") is None
    ctx.revert()
    assert backend.get_value(KEY, "Doomed").data == "keepme"


def test_out_of_scope_key_refused(journal_path):
    planter, backend, ctx = _planter(journal_path)
    with pytest.raises(ScopeError):
        planter.set_value(r"HKLM\SYSTEM\Setup", "x", "y")
    assert len(ctx.journal) == 0


def test_unauthorized_technique_refused(journal_path):
    planter, _, _ = _planter(journal_path, techniques=("T1070.006",))
    with pytest.raises(TechniqueNotAuthorizedError):
        planter.set_value(KEY, "x", "y")


def test_dry_run_writes_nothing(journal_path):
    planter, backend, _ = _planter(journal_path, dry_run=True)
    entry = planter.set_value(KEY, "Downloaded", "x")
    assert entry.status == STATUS_PLANNED
    assert backend.get_value(KEY, "Downloaded") is None
    assert backend.get_value(KEY, MARKER_NAME) is None


def test_plant_recent_doc_and_report(journal_path):
    from src.report import PurpleTeamReport

    planter, backend, ctx = _planter(journal_path, attributable=False)
    planter.plant_recent_doc("innocuous.pdf", r"C:\Users\Public\innocuous.pdf")
    assert backend.get_value(RECENTDOCS_KEY, "innocuous.pdf").data == r"C:\Users\Public\innocuous.pdf"

    report = PurpleTeamReport.from_journal(ctx.journal)
    assert report.expectations()[0].technique_id == "T1112"
    assert report.expectations()[0].technique_name == "Modify Registry"
