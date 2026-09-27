"""Exception hierarchy for MIRAGE.

All errors raised by MIRAGE derive from :class:`MirageError` so callers can catch
the whole family with a single ``except``. Authorization failures form their own
sub-tree because they are the ones an operator most often needs to handle
explicitly (an out-of-scope target should stop an engagement, not crash it).
"""

from __future__ import annotations


class MirageError(Exception):
    """Base class for every MIRAGE error."""


class ConfigError(MirageError):
    """An engagement profile is missing, malformed, or internally inconsistent."""


class AuthorizationError(MirageError):
    """An action is not permitted by the active engagement profile."""


class ScopeError(AuthorizationError):
    """A target is outside the authorized scope, or is explicitly denied."""


class EngagementInactiveError(AuthorizationError):
    """The engagement window is not currently open (not started yet or expired)."""


class TechniqueNotAuthorizedError(AuthorizationError):
    """A technique was requested that the engagement did not authorize."""


class HostNotAuthorizedError(AuthorizationError):
    """The tool is running on a host the engagement did not authorize."""


class AuditError(MirageError):
    """Base class for audit-journal errors."""


class IntegrityError(AuditError):
    """The audit journal failed hash-chain or signature verification."""


class RevertError(MirageError):
    """An applied action could not be reverted."""
