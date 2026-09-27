"""Tests for engagement authorization and scope enforcement (#1)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.engagement import EngagementProfile, Scope
from src.errors import (
    ConfigError,
    EngagementInactiveError,
    HostNotAuthorizedError,
    ScopeError,
    TechniqueNotAuthorizedError,
)

from conftest import make_profile_dict


def test_valid_profile_loads(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    assert profile.engagement_id == "TEST-2026-001"
    assert profile.is_active()


@pytest.mark.parametrize("missing", ["engagement_id", "client", "operator", "authorized_by", "roe_reference"])
def test_missing_required_field_raises(profile_dict, missing):
    del profile_dict[missing]
    with pytest.raises(ConfigError):
        EngagementProfile.from_dict(profile_dict)


def test_blank_required_field_raises(profile_dict):
    profile_dict["operator"] = "   "
    with pytest.raises(ConfigError):
        EngagementProfile.from_dict(profile_dict)


def test_expiry_before_start_raises(profile_dict):
    now = datetime.now(timezone.utc)
    profile_dict["starts_at"] = now.isoformat()
    profile_dict["expires_at"] = (now - timedelta(hours=1)).isoformat()
    with pytest.raises(ConfigError):
        EngagementProfile.from_dict(profile_dict)


def test_empty_hosts_or_techniques_raise(profile_dict):
    d = dict(profile_dict, allowed_hosts=[])
    with pytest.raises(ConfigError):
        EngagementProfile.from_dict(d)
    d = dict(profile_dict, techniques=[])
    with pytest.raises(ConfigError):
        EngagementProfile.from_dict(d)


def test_assert_active_window():
    now = datetime.now(timezone.utc)
    future = EngagementProfile.from_dict(
        make_profile_dict(
            starts_at=(now + timedelta(hours=1)).isoformat(),
            expires_at=(now + timedelta(hours=2)).isoformat(),
        )
    )
    with pytest.raises(EngagementInactiveError):
        future.assert_active()

    expired = EngagementProfile.from_dict(
        make_profile_dict(
            starts_at=(now - timedelta(hours=2)).isoformat(),
            expires_at=(now - timedelta(hours=1)).isoformat(),
        )
    )
    with pytest.raises(EngagementInactiveError):
        expired.assert_active()


def test_host_authorization():
    profile = EngagementProfile.from_dict(make_profile_dict(allowed_hosts=["LAB-WIN10-01"]))
    profile.assert_host("LAB-WIN10-01")
    profile.assert_host("lab-win10-01")  # case-insensitive
    with pytest.raises(HostNotAuthorizedError):
        profile.assert_host("attacker-laptop")


def test_wildcard_host_allows_any(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    profile.assert_host("anything-at-all")


def test_technique_parent_authorizes_subtechnique(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    profile.assert_technique("T1070.006")   # exact
    profile.assert_technique("T1562.002")   # parent T1562 authorizes sub
    with pytest.raises(TechniqueNotAuthorizedError):
        profile.assert_technique("T1055")


def test_path_scope_allow_and_default_deny(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    profile.scope.check_path("C:/RedTeamLab/secret.txt")
    profile.scope.check_path(r"C:\RedTeamLab\nested\a.txt")  # backslashes normalize
    with pytest.raises(ScopeError):
        profile.scope.check_path("C:/Windows/System32/notepad.exe")  # not listed


def test_deny_takes_precedence_over_allow(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    with pytest.raises(ScopeError):
        profile.scope.check_path("C:/RedTeamLab/off-limits/evidence.txt")


def test_builtin_denylist_always_applies(profile_dict):
    # Even if an operator tries to allow a sensitive hive, the default deny wins.
    profile_dict["scope"]["allowed_paths"].append("*")
    profile = EngagementProfile.from_dict(profile_dict)
    with pytest.raises(ScopeError):
        profile.scope.check_path("C:/Windows/System32/config/SAM")


def test_registry_scope(profile_dict):
    profile = EngagementProfile.from_dict(profile_dict)
    profile.scope.check_registry_key(
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\FakeDownload"
    )
    with pytest.raises(ScopeError):
        profile.scope.check_registry_key(r"HKLM\SAM\Domains\Account")


def test_scope_rejects_non_list():
    with pytest.raises(ConfigError):
        Scope.from_dict({"allowed_paths": "C:/nope"})
