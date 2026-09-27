"""MIRAGE - adversary-emulation harness for anti-forensic technique detection testing.

This package emulates timeline- and artifact-tampering TTPs (MITRE ATT&CK T1070,
T1112, T1562) under an authorized engagement so blue teams can validate their
detections. Every action is gated by an :class:`~src.engagement.EngagementProfile`
and recorded to a tamper-evident, fully reversible
:class:`~src.audit.AuditJournal`; :class:`~src.report.PurpleTeamReport` turns that
journal into ATT&CK-mapped detection expectations for the SOC.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from .attack import CATALOG, Technique, lookup
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

# Loaded lazily so `python -m src.report` does not import the module twice.
_LAZY = {"PurpleTeamReport": "report", "DetectionExpectation": "report"}


def __getattr__(name: str):
    module = _LAZY.get(name)
    if module is not None:
        return getattr(importlib.import_module(f".{module}", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:  # for type checkers / IDEs only
    from .report import DetectionExpectation, PurpleTeamReport

__all__ = [
    "AuditEntry",
    "AuditJournal",
    "ReverterRegistry",
    "RevertEngine",
    "RevertResult",
    "EngagementContext",
    "EngagementProfile",
    "Scope",
    "PurpleTeamReport",
    "DetectionExpectation",
    "Technique",
    "CATALOG",
    "lookup",
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
