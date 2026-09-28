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
_LAZY = {
    "PurpleTeamReport": "report",
    "DetectionExpectation": "report",
    "TimelineSpoofer": "timeline_spoofer",
    "FileTimes": "timeline_spoofer",
    "TimestompBackend": "timeline_spoofer",
    "PortableBackend": "timeline_spoofer",
    "WindowsBackend": "timeline_spoofer",
    "RegistryPlanter": "registry_planter",
    "RegValue": "registry_planter",
    "RegistryBackend": "registry_planter",
    "InMemoryRegistryBackend": "registry_planter",
    "WinRegBackend": "registry_planter",
    "EventLogController": "event_injector",
    "EventLogBackend": "event_injector",
    "InMemoryEventLogBackend": "event_injector",
    "WevtutilBackend": "event_injector",
}


def __getattr__(name: str):
    module = _LAZY.get(name)
    if module is not None:
        return getattr(importlib.import_module(f".{module}", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


if TYPE_CHECKING:  # for type checkers / IDEs only
    from .report import DetectionExpectation, PurpleTeamReport
    from .event_injector import (
        EventLogBackend,
        EventLogController,
        InMemoryEventLogBackend,
        WevtutilBackend,
    )
    from .registry_planter import (
        InMemoryRegistryBackend,
        RegistryBackend,
        RegistryPlanter,
        RegValue,
        WinRegBackend,
    )
    from .timeline_spoofer import (
        FileTimes,
        PortableBackend,
        TimelineSpoofer,
        TimestompBackend,
        WindowsBackend,
    )

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
    "TimelineSpoofer",
    "FileTimes",
    "TimestompBackend",
    "PortableBackend",
    "WindowsBackend",
    "RegistryPlanter",
    "RegValue",
    "RegistryBackend",
    "InMemoryRegistryBackend",
    "WinRegBackend",
    "EventLogController",
    "EventLogBackend",
    "InMemoryEventLogBackend",
    "WevtutilBackend",
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
