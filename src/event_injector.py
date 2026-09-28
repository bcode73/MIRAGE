"""Windows event-logging tamper emulation (MITRE ATT&CK T1562.002).

Authorized, journaled, reversible enable/disable of Windows event-log channels, so
a SOC can validate that it detects attempts to blind its telemetry (Security event
4719 audit-policy change, 1100 logging-service shutdown, service state changes).
The original channel state is captured and restored exactly at revert.

Scope of this module
--------------------
It emulates the reversible T1562.002 primitive only. It deliberately does NOT:

* forge Security-channel events (e.g. counterfeit 4624 logons) -- fabricating
  convincing false telemetry serves evidence-planting, not detection testing; and
* clear real event logs -- a clear is destructive and cannot be reversed.

Backends
--------
InMemoryEventLogBackend is used for tests and non-Windows hosts. WevtutilBackend
shells out to ``wevtutil`` on Windows (lazily) to read and set channel state.
"""

from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .audit import AuditEntry
    from .context import EngagementContext

TECHNIQUE = "T1562.002"
ACTION_SET_ENABLED = "eventlog.set_enabled"


class EventLogBackend(ABC):
    name = "abstract"

    @abstractmethod
    def is_enabled(self, channel: str) -> bool:
        ...

    @abstractmethod
    def set_enabled(self, channel: str, enabled: bool) -> None:
        ...


class InMemoryEventLogBackend(EventLogBackend):
    """Dict-backed channel state for tests and non-Windows hosts (default enabled)."""

    name = "in-memory"

    def __init__(self) -> None:
        self._state: dict[str, bool] = {}

    def is_enabled(self, channel: str) -> bool:
        return self._state.get(channel.lower(), True)

    def set_enabled(self, channel: str, enabled: bool) -> None:
        self._state[channel.lower()] = enabled


class WevtutilBackend(EventLogBackend):
    """Real Windows backend using ``wevtutil`` (lazy; requires privileges)."""

    name = "wevtutil"

    def is_enabled(self, channel: str) -> bool:
        out = subprocess.run(
            ["wevtutil", "gl", channel], capture_output=True, text=True, check=True
        ).stdout
        for line in out.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("enabled:"):
                return stripped.split(":", 1)[1].strip() == "true"
        raise RuntimeError(f"could not determine enabled state for channel {channel!r}")

    def set_enabled(self, channel: str, enabled: bool) -> None:
        subprocess.run(
            ["wevtutil", "sl", channel, f"/e:{'true' if enabled else 'false'}"],
            capture_output=True, text=True, check=True,
        )


def default_eventlog_backend() -> EventLogBackend:
    return WevtutilBackend() if sys.platform == "win32" else InMemoryEventLogBackend()


class EventLogController:
    """Authorized, audited, reversible event-log channel control (T1562.002)."""

    def __init__(self, context: "EngagementContext", backend: EventLogBackend | None = None) -> None:
        self.context = context
        self.backend = backend or default_eventlog_backend()

    def set_enabled(self, channel: str, enabled: bool) -> "AuditEntry":
        def capture_before() -> dict[str, bool]:
            return {"enabled": self.backend.is_enabled(channel)}

        def apply() -> dict[str, bool]:
            self.backend.set_enabled(channel, enabled)
            return {"enabled": enabled}

        def reverter(entry: "AuditEntry") -> None:
            self.backend.set_enabled(channel, bool(entry.before["enabled"]))

        return self.context.perform(
            action=ACTION_SET_ENABLED,
            technique=TECHNIQUE,
            target=channel,
            target_kind="channel",
            capture_before=capture_before,
            apply=apply,
            reverter=reverter,
        )

    def disable_channel(self, channel: str) -> "AuditEntry":
        """Disable a log channel (emulates blinding a telemetry source)."""
        return self.set_enabled(channel, False)

    def enable_channel(self, channel: str) -> "AuditEntry":
        return self.set_enabled(channel, True)


def register_reverters(registry, backend: EventLogBackend | None = None) -> None:
    """Register this module's reverter so revert works in a fresh process."""
    be = backend or default_eventlog_backend()

    def _revert(entry) -> None:
        be.set_enabled(entry.target, bool(entry.before["enabled"]))

    registry.register(ACTION_SET_ENABLED, _revert)
