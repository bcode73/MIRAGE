"""File timestamp manipulation (MITRE ATT&CK T1070.006, Timestomp).

Adversary-emulation module. It rewrites a target file's timestamps under an
authorized engagement, always capturing the original values first so every change
is recorded in the audit journal and can be reverted exactly. All operations go
through an :class:`~src.context.EngagementContext`, so a timestomp is refused
unless the engagement is active, the host is authorized, T1070.006 is permitted,
and the target path is in scope.

Backends
--------
Setting the *modified* and *accessed* times is portable and works everywhere via
``os.utime`` (the ``PortableBackend``). Setting the *creation* time requires the
Windows ``SetFileTime`` API (the ``WindowsBackend``); on other platforms the
creation time is reported when the OS exposes it but cannot be changed. The
backend is selected automatically but can be injected for testing.
"""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .audit import AuditEntry
    from .context import EngagementContext

TECHNIQUE = "T1070.006"
ACTION_SET = "timestomp.set"

# FILETIME epoch (1601-01-01) offset from the Unix epoch, in 100-nanosecond units.
_FILETIME_EPOCH_OFFSET = 116444736000000000


def _dt_to_ns(value: datetime) -> int:
    """Convert a datetime to Unix epoch nanoseconds; naive input is treated as UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.timestamp() * 1_000_000_000)


@dataclass(frozen=True)
class FileTimes:
    """A file's timestamps in Unix epoch nanoseconds; ``None`` means unknown/unchanged."""

    accessed_ns: int | None = None
    modified_ns: int | None = None
    created_ns: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"accessed_ns": self.accessed_ns, "modified_ns": self.modified_ns, "created_ns": self.created_ns}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileTimes":
        return cls(
            accessed_ns=data.get("accessed_ns"),
            modified_ns=data.get("modified_ns"),
            created_ns=data.get("created_ns"),
        )

    def as_iso(self) -> dict[str, str | None]:
        def iso(ns: int | None) -> str | None:
            if ns is None:
                return None
            return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).isoformat()

        return {"accessed": iso(self.accessed_ns), "modified": iso(self.modified_ns), "created": iso(self.created_ns)}


class TimestompBackend(ABC):
    """Captures and applies file timestamps on a given platform."""

    name: str = "abstract"
    can_set_created: bool = False

    @abstractmethod
    def capture(self, path: str) -> FileTimes:
        ...

    @abstractmethod
    def apply(self, path: str, times: FileTimes) -> None:
        ...


class PortableBackend(TimestompBackend):
    """Cross-platform backend using ``os.stat`` / ``os.utime``.

    Reads all timestamps the OS exposes but only writes accessed and modified
    times; creation time cannot be set through portable APIs.
    """

    name = "portable"
    can_set_created = False

    def capture(self, path: str) -> FileTimes:
        st = os.stat(path)
        created_ns: int | None = None
        if sys.platform == "win32":
            created_ns = st.st_ctime_ns
        elif hasattr(st, "st_birthtime_ns"):
            created_ns = st.st_birthtime_ns  # type: ignore[attr-defined]
        elif hasattr(st, "st_birthtime"):
            created_ns = int(st.st_birthtime * 1_000_000_000)  # type: ignore[attr-defined]
        return FileTimes(accessed_ns=st.st_atime_ns, modified_ns=st.st_mtime_ns, created_ns=created_ns)

    def apply(self, path: str, times: FileTimes) -> None:
        current = self.capture(path)
        accessed = times.accessed_ns if times.accessed_ns is not None else current.accessed_ns
        modified = times.modified_ns if times.modified_ns is not None else current.modified_ns
        os.utime(path, ns=(accessed, modified))


class WindowsBackend(TimestompBackend):
    """Windows backend using ``CreateFileW`` + ``SetFileTime`` for all three times.

    Requires Windows and sufficient privileges. ctypes and ``ctypes.wintypes`` are
    imported lazily so this module stays importable on non-Windows hosts.
    """

    name = "windows"
    can_set_created = True

    def capture(self, path: str) -> FileTimes:
        st = os.stat(path)
        return FileTimes(accessed_ns=st.st_atime_ns, modified_ns=st.st_mtime_ns, created_ns=st.st_ctime_ns)

    def apply(self, path: str, times: FileTimes) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        FILE_WRITE_ATTRIBUTES = 0x0100
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        create_file = kernel32.CreateFileW
        create_file.restype = wintypes.HANDLE
        create_file.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        set_file_time = kernel32.SetFileTime
        set_file_time.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)
        ]
        close_handle = kernel32.CloseHandle

        def to_ft(ns: int | None):
            if ns is None:
                return None
            val = ns // 100 + _FILETIME_EPOCH_OFFSET
            return FILETIME(val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF)

        handle = create_file(
            str(path), FILE_WRITE_ATTRIBUTES, 0, None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            raise OSError(ctypes.get_last_error(), f"CreateFileW failed for {path!r}")
        try:
            created = to_ft(times.created_ns)
            accessed = to_ft(times.accessed_ns)
            modified = to_ft(times.modified_ns)
            ok = set_file_time(
                handle,
                ctypes.byref(created) if created else None,
                ctypes.byref(accessed) if accessed else None,
                ctypes.byref(modified) if modified else None,
            )
            if not ok:
                raise OSError(ctypes.get_last_error(), f"SetFileTime failed for {path!r}")
        finally:
            close_handle(handle)


def default_backend() -> TimestompBackend:
    return WindowsBackend() if sys.platform == "win32" else PortableBackend()


class TimelineSpoofer:
    """Authorized, audited, reversible file-timestamp manipulation (T1070.006)."""

    def __init__(self, context: "EngagementContext", backend: TimestompBackend | None = None) -> None:
        self.context = context
        self.backend = backend or default_backend()

    def _perform(self, path: str | Path, compute_new: Callable[[FileTimes], FileTimes]) -> "AuditEntry":
        target = str(path)

        def capture_before() -> dict[str, Any]:
            return self.backend.capture(target).to_dict()

        def apply() -> dict[str, Any]:
            new_times = compute_new(self.backend.capture(target))
            self.backend.apply(target, new_times)
            return self.backend.capture(target).to_dict()

        def reverter(entry: "AuditEntry") -> None:
            self.backend.apply(target, FileTimes.from_dict(entry.before))

        return self.context.perform(
            action=ACTION_SET,
            technique=TECHNIQUE,
            target=target,
            target_kind="path",
            capture_before=capture_before,
            apply=apply,
            reverter=reverter,
        )

    def set_times(
        self,
        path: str | Path,
        *,
        accessed: datetime | None = None,
        modified: datetime | None = None,
        created: datetime | None = None,
    ) -> "AuditEntry":
        """Set any subset of timestamps; unspecified ones are left unchanged."""

        def compute_new(current: FileTimes) -> FileTimes:
            return FileTimes(
                accessed_ns=_dt_to_ns(accessed) if accessed is not None else current.accessed_ns,
                modified_ns=_dt_to_ns(modified) if modified is not None else current.modified_ns,
                created_ns=_dt_to_ns(created) if created is not None else current.created_ns,
            )

        return self._perform(path, compute_new)

    def backdate(self, path: str | Path, when: datetime) -> "AuditEntry":
        """Set accessed, modified, and created to a single point in time."""
        return self.set_times(path, accessed=when, modified=when, created=when)

    def match_to(self, path: str | Path, reference: str | Path) -> "AuditEntry":
        """Copy another file's timestamps onto the target (blend-in / time-cloning)."""
        ref_times = self.backend.capture(str(reference))
        return self._perform(path, lambda current: ref_times)
