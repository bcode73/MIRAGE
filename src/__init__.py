"""MIRAGE - adversary-emulation harness for anti-forensic technique detection testing.

This package emulates timeline- and artifact-tampering TTPs (MITRE ATT&CK T1070,
T1562) under an authorized engagement so blue teams can validate their detections.
Every action is gated by an :class:`~src.engagement.EngagementProfile` and recorded
to a tamper-evident, fully reversible :class:`~src.audit.AuditJournal`.
"""

from __future__ import annotations

from .audit import AuditEntry, AuditJournal, ReverterRegistry, RevertEngine, RevertResult
from .context import EngagementContext
from .engagement import EngagementProfile, Scope
from .errors import (
    AuditError,
    AuthorizationError,
    ConfigError,
    EngagementInactiveError,
    HostNotAuthorizedError,
    IntegrityError,
    MirageError,
    RevertError,
    ScopeError,
    TechniqueNotAuthorizedError,
)

__version__ = "0.1.0"

__all__ = [
    "AuditEntry",
    "AuditJournal",
    "ReverterRegistry",
    "RevertEngine",
    "RevertResult",
    "EngagementContext",
    "EngagementProfile",
    "Scope",
    "MirageError",
    "ConfigError",
    "AuthorizationError",
    "ScopeError",
    "EngagementInactiveError",
    "HostNotAuthorizedError",
    "TechniqueNotAuthorizedError",
    "AuditError",
    "IntegrityError",
    "RevertError",
    "__version__",
]
