"""Shared fixtures and builders for the MIRAGE test suite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest


def make_profile_dict(**overrides: Any) -> dict[str, Any]:
    """A valid engagement profile dict whose window spans 'now'."""
    now = datetime.now(timezone.utc)
    data: dict[str, Any] = {
        "engagement_id": "TEST-2026-001",
        "client": "Test Client",
        "operator": "operator@test.example",
        "authorized_by": "poc@test.example",
        "roe_reference": "RoE-TEST-1",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "allowed_hosts": ["*"],
        "techniques": ["T1070.006", "T1562"],
        "dry_run_default": False,
        "scope": {
            "allowed_paths": ["C:/RedTeamLab/*"],
            "allowed_registry_keys": [
                "hkcu/software/microsoft/windows/currentversion/explorer/recentdocs/*"
            ],
            "denied_paths": ["C:/RedTeamLab/off-limits/*"],
            "denied_registry_keys": [],
        },
    }
    data.update(overrides)
    return data


@pytest.fixture
def profile_dict() -> dict[str, Any]:
    return make_profile_dict()


@pytest.fixture
def journal_path(tmp_path):
    return tmp_path / "journal.jsonl"
