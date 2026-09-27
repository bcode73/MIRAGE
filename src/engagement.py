"""Engagement authorization and scope enforcement.

Every state-changing MIRAGE action must be authorized against an
:class:`EngagementProfile` loaded from an operator-supplied file. The profile
encodes the rules of engagement (RoE): who authorized the work, the validity
window, the hosts the tool may run on, the file/registry targets that are in
scope, and the ATT&CK techniques that are permitted.

This layer is deliberately restrictive and defaults to deny:

* An action outside the engagement window is refused (a built-in kill-switch).
* An action on a host that is not listed is refused.
* A target that is not explicitly in scope is refused.
* A target that matches the denylist is refused even if it also matches an
  allow rule; denies always win.

The denylist ships with defaults that block target classes with no legitimate
adversary-emulation purpose (for example, tampering with other operating-system
accounts). Operators extend, but cannot silently weaken, those defaults.
"""

from __future__ import annotations

import fnmatch
import json
import socket
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import (
    ConfigError,
    EngagementInactiveError,
    HostNotAuthorizedError,
    ScopeError,
    TechniqueNotAuthorizedError,
)

# Denied by default. These are additive: an operator profile may add more denies
# but cannot remove these. They exist to keep the tool pointed at authorized
# adversary emulation rather than at tampering that only serves to mislead a real
# investigation or implicate an uninvolved account.
DEFAULT_DENIED_PATHS: tuple[str, ...] = (
    "*/windows/system32/config/sam",
    "*/windows/system32/config/security",
)
DEFAULT_DENIED_REGISTRY_KEYS: tuple[str, ...] = (
    "hklm/sam/*",
    "hklm/security/*",
)


def _normalize_path(value: str) -> str:
    """Fold a path to a stable form for case-insensitive glob matching.

    Windows paths are case-insensitive and mix separators; normalize both so the
    same target compares equal regardless of how it was typed.
    """
    return value.strip().replace("\\", "/").rstrip("/").lower()


def _normalize_key(value: str) -> str:
    """Normalize a registry key path (case-insensitive, forward slashes)."""
    return value.strip().replace("\\", "/").strip("/").lower()


def _matches(target: str, rule: str) -> bool:
    """True if ``target`` matches ``rule`` as an exact value, prefix, or glob."""
    if target == rule:
        return True
    if fnmatch.fnmatch(target, rule):
        return True
    # Treat a plain rule as a directory/key prefix.
    return target.startswith(rule + "/")


@dataclass(frozen=True)
class Scope:
    """The set of targets an engagement may touch.

    Allow rules and deny rules accept exact values, ``*`` globs, or prefixes.
    Deny rules always take precedence over allow rules.
    """

    allowed_paths: tuple[str, ...] = ()
    allowed_registry_keys: tuple[str, ...] = ()
    denied_paths: tuple[str, ...] = ()
    denied_registry_keys: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Scope":
        def norm_list(key: str, normalizer) -> tuple[str, ...]:
            raw = data.get(key, [])
            if not isinstance(raw, (list, tuple)):
                raise ConfigError(f"scope.{key} must be a list")
            return tuple(normalizer(str(item)) for item in raw)

        denied_paths = norm_list("denied_paths", _normalize_path) + DEFAULT_DENIED_PATHS
        denied_keys = (
            norm_list("denied_registry_keys", _normalize_key)
            + DEFAULT_DENIED_REGISTRY_KEYS
        )
        return cls(
            allowed_paths=norm_list("allowed_paths", _normalize_path),
            allowed_registry_keys=norm_list("allowed_registry_keys", _normalize_key),
            denied_paths=denied_paths,
            denied_registry_keys=denied_keys,
        )

    def check_path(self, path: str) -> None:
        """Raise :class:`ScopeError` unless ``path`` is in scope and not denied."""
        target = _normalize_path(path)
        for rule in self.denied_paths:
            if _matches(target, rule):
                raise ScopeError(f"path is explicitly denied by scope: {path!r} (rule {rule!r})")
        if not any(_matches(target, rule) for rule in self.allowed_paths):
            raise ScopeError(f"path is not in the authorized scope: {path!r}")

    def check_registry_key(self, key: str) -> None:
        """Raise :class:`ScopeError` unless ``key`` is in scope and not denied."""
        target = _normalize_key(key)
        for rule in self.denied_registry_keys:
            if _matches(target, rule):
                raise ScopeError(f"registry key is explicitly denied: {key!r} (rule {rule!r})")
        if not any(_matches(target, rule) for rule in self.allowed_registry_keys):
            raise ScopeError(f"registry key is not in the authorized scope: {key!r}")


def _parse_ts(value: Any, fieldname: str) -> datetime:
    if not isinstance(value, str):
        raise ConfigError(f"{fieldname} must be an ISO-8601 timestamp string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ConfigError(f"{fieldname} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class EngagementProfile:
    """An authorized engagement: the single source of truth for what is permitted."""

    engagement_id: str
    client: str
    operator: str
    authorized_by: str
    roe_reference: str
    starts_at: datetime
    expires_at: datetime
    allowed_hosts: tuple[str, ...]
    techniques: tuple[str, ...]
    scope: Scope
    dry_run_default: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    # loading
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EngagementProfile":
        required_strings = (
            "engagement_id",
            "client",
            "operator",
            "authorized_by",
            "roe_reference",
        )
        values: dict[str, Any] = {}
        for name in required_strings:
            raw = data.get(name)
            if not isinstance(raw, str) or not raw.strip():
                raise ConfigError(f"engagement field {name!r} is required and must be a non-empty string")
            values[name] = raw.strip()

        starts_at = _parse_ts(data.get("starts_at"), "starts_at")
        expires_at = _parse_ts(data.get("expires_at"), "expires_at")
        if expires_at <= starts_at:
            raise ConfigError("expires_at must be after starts_at")

        hosts = data.get("allowed_hosts")
        if not isinstance(hosts, (list, tuple)) or not hosts:
            raise ConfigError("allowed_hosts must be a non-empty list")
        allowed_hosts = tuple(str(h).strip().lower() for h in hosts)

        techniques = data.get("techniques")
        if not isinstance(techniques, (list, tuple)) or not techniques:
            raise ConfigError("techniques must be a non-empty list of ATT&CK technique IDs")
        techniques_t = tuple(str(t).strip().upper() for t in techniques)

        scope_data = data.get("scope", {})
        if not isinstance(scope_data, Mapping):
            raise ConfigError("scope must be an object")
        scope = Scope.from_dict(scope_data)

        metadata = data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ConfigError("metadata must be an object")

        return cls(
            engagement_id=values["engagement_id"],
            client=values["client"],
            operator=values["operator"],
            authorized_by=values["authorized_by"],
            roe_reference=values["roe_reference"],
            starts_at=starts_at,
            expires_at=expires_at,
            allowed_hosts=allowed_hosts,
            techniques=techniques_t,
            scope=scope,
            dry_run_default=bool(data.get("dry_run_default", True)),
            metadata=dict(metadata),
        )

    @classmethod
    def load(cls, path: str | Path) -> "EngagementProfile":
        p = Path(path)
        try:
            raw = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read engagement profile {str(path)!r}: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"engagement profile {str(path)!r} is not valid JSON: {exc}") from exc
        if not isinstance(data, Mapping):
            raise ConfigError("engagement profile must be a JSON object")
        return cls.from_dict(data)

    # authorization
    def is_active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.starts_at <= now < self.expires_at

    def assert_active(self, now: datetime | None = None) -> None:
        """Raise :class:`EngagementInactiveError` outside the engagement window."""
        now = now or datetime.now(timezone.utc)
        if now < self.starts_at:
            raise EngagementInactiveError(
                f"engagement {self.engagement_id} has not started (starts {self.starts_at.isoformat()})"
            )
        if now >= self.expires_at:
            raise EngagementInactiveError(
                f"engagement {self.engagement_id} expired at {self.expires_at.isoformat()}"
            )

    def assert_host(self, hostname: str | None = None) -> None:
        """Raise :class:`HostNotAuthorizedError` if run on an unlisted host."""
        host = (hostname or socket.gethostname()).strip().lower()
        if "*" in self.allowed_hosts:
            return
        if host not in self.allowed_hosts:
            raise HostNotAuthorizedError(
                f"host {host!r} is not authorized for engagement {self.engagement_id}"
            )

    def assert_technique(self, technique_id: str) -> None:
        """Raise :class:`TechniqueNotAuthorizedError` for an unlisted technique.

        A parent technique authorizes its sub-techniques: authorizing ``T1070``
        also authorizes ``T1070.006``.
        """
        want = technique_id.strip().upper()
        for authorized in self.techniques:
            if want == authorized or want.startswith(authorized + "."):
                return
        raise TechniqueNotAuthorizedError(
            f"technique {want} is not authorized for engagement {self.engagement_id}"
        )

    def with_scope(self, scope: Scope) -> "EngagementProfile":
        """Return a copy with a replaced scope (useful in tests)."""
        return replace(self, scope=scope)
