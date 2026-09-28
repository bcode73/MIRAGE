"""Windows registry artifact emulation (MITRE ATT&CK T1112, Modify Registry).

Authorized, journaled, reversible registry modification for detection testing. It
emulates the planting of explorer MRU artifacts (RecentDocs, TypedURLs, RunMRU)
so a SOC can validate that it detects unexpected registry activity, then restores
the original state exactly at the end of the engagement.

Attributability
---------------
To keep this a detection test rather than a means of fabricating evidence, every
key this module writes to also receives a ``__MIRAGE__`` marker value recording
the engagement ID. Together with the signed audit journal and guaranteed revert,
that makes any planted artifact plainly identifiable as a sanctioned test rather
than genuine user activity. This module does not fabricate artifacts designed to
implicate a specific person or application.

Backends
--------
InMemoryRegistryBackend is used for tests and non-Windows hosts.
WinRegBackend uses the stdlib ``winreg`` module (imported lazily) on Windows.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit import AuditEntry
    from .context import EngagementContext

TECHNIQUE = "T1112"
ACTION_SET = "registry.set_value"
ACTION_DELETE = "registry.delete_value"
ACTION_MARKER = "registry.marker"

MARKER_NAME = "__MIRAGE__"
RECENTDOCS_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
TYPEDURLS_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedURLs"


@dataclass(frozen=True)
class RegValue:
    """A registry value: its type name (e.g. ``REG_SZ``) and its data."""

    type: str
    data: Any

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "data": self.data}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegValue":
        return cls(type=data["type"], data=data["data"])


class RegistryBackend(ABC):
    name = "abstract"

    @abstractmethod
    def get_value(self, key: str, name: str) -> RegValue | None:
        ...

    @abstractmethod
    def set_value(self, key: str, name: str, value: RegValue) -> None:
        ...

    @abstractmethod
    def delete_value(self, key: str, name: str) -> None:
        ...


class InMemoryRegistryBackend(RegistryBackend):
    """Dict-backed registry for tests and non-Windows hosts."""

    name = "in-memory"

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], RegValue] = {}

    @staticmethod
    def _k(key: str, name: str) -> tuple[str, str]:
        return (key.replace("\\", "/").strip("/").lower(), name.lower())

    def get_value(self, key: str, name: str) -> RegValue | None:
        return self._store.get(self._k(key, name))

    def set_value(self, key: str, name: str, value: RegValue) -> None:
        self._store[self._k(key, name)] = value

    def delete_value(self, key: str, name: str) -> None:
        self._store.pop(self._k(key, name), None)


class WinRegBackend(RegistryBackend):
    """Real Windows backend using the stdlib ``winreg`` module (lazy import)."""

    name = "winreg"

    _HIVES = {
        "HKCU": "HKEY_CURRENT_USER",
        "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
        "HKEY_USERS": "HKEY_USERS",
        "HKCC": "HKEY_CURRENT_CONFIG",
        "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
    }

    def _split(self, key: str):
        import winreg

        parts = key.replace("/", "\\").split("\\", 1)
        if len(parts) != 2:
            raise ValueError(f"registry key must include a hive and subkey: {key!r}")
        hive_name = self._HIVES.get(parts[0].upper())
        if hive_name is None:
            raise ValueError(f"unknown registry hive in {key!r}")
        return getattr(winreg, hive_name), parts[1]

    def get_value(self, key: str, name: str) -> RegValue | None:
        import winreg

        hive, subkey = self._split(key)
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as handle:
                data, type_int = winreg.QueryValueEx(handle, name)
        except FileNotFoundError:
            return None
        return RegValue(type=_regtype_name(type_int), data=data)

    def set_value(self, key: str, name: str, value: RegValue) -> None:
        import winreg

        hive, subkey = self._split(key)
        with winreg.CreateKey(hive, subkey) as handle:
            winreg.SetValueEx(handle, name, 0, _regtype_int(value.type), value.data)

    def delete_value(self, key: str, name: str) -> None:
        import winreg

        hive, subkey = self._split(key)
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as handle:
                winreg.DeleteValue(handle, name)
        except FileNotFoundError:
            pass


def _regtype_int(type_name: str) -> int:
    import winreg

    try:
        return getattr(winreg, type_name)
    except AttributeError as exc:
        raise ValueError(f"unknown registry type {type_name!r}") from exc


def _regtype_name(type_int: int) -> str:
    import winreg

    for attr in ("REG_SZ", "REG_EXPAND_SZ", "REG_BINARY", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ", "REG_NONE"):
        if getattr(winreg, attr, object()) == type_int:
            return attr
    return f"REG_TYPE_{type_int}"


def default_registry_backend() -> RegistryBackend:
    return WinRegBackend() if sys.platform == "win32" else InMemoryRegistryBackend()


class RegistryPlanter:
    """Authorized, audited, reversible registry modification (T1112)."""

    def __init__(
        self,
        context: "EngagementContext",
        backend: RegistryBackend | None = None,
        *,
        attributable: bool = True,
    ) -> None:
        self.context = context
        self.backend = backend or default_registry_backend()
        self.attributable = attributable
        self._marked: set[str] = set()

    def _write(self, key: str, name: str, action: str, new_value: RegValue | None) -> "AuditEntry":
        target = f"{key}\\{name}"

        def capture_before() -> Any:
            current = self.backend.get_value(key, name)
            return current.to_dict() if current is not None else None

        def apply() -> Any:
            if new_value is None:
                self.backend.delete_value(key, name)
                return None
            self.backend.set_value(key, name, new_value)
            return new_value.to_dict()

        def reverter(entry: "AuditEntry") -> None:
            if entry.before is None:
                self.backend.delete_value(key, name)
            else:
                self.backend.set_value(key, name, RegValue.from_dict(entry.before))

        return self.context.perform(
            action=action,
            technique=TECHNIQUE,
            target=target,
            target_kind="registry",
            capture_before=capture_before,
            apply=apply,
            reverter=reverter,
        )

    def _ensure_marker(self, key: str) -> None:
        if key in self._marked:
            return
        existing = self.backend.get_value(key, MARKER_NAME)
        marker = self.context.profile.engagement_id
        if existing is None or existing.data != marker:
            self._write(key, MARKER_NAME, ACTION_MARKER, RegValue("REG_SZ", marker))
        self._marked.add(key)

    def set_value(self, key: str, name: str, data: Any, value_type: str = "REG_SZ") -> "AuditEntry":
        """Set a registry value, capturing the original for exact revert."""
        if self.attributable:
            self._ensure_marker(key)
        return self._write(key, name, ACTION_SET, RegValue(value_type, data))

    def remove_value(self, key: str, name: str) -> "AuditEntry":
        """Delete a registry value, capturing the original for exact revert."""
        return self._write(key, name, ACTION_DELETE, None)

    def plant_recent_doc(self, name: str, path: str) -> "AuditEntry":
        """Plant a RecentDocs artifact (a classic T1112 target)."""
        return self.set_value(RECENTDOCS_KEY, name, path)


def register_reverters(registry, backend: RegistryBackend | None = None) -> None:
    """Register this module's reverters so revert works in a fresh process."""
    be = backend or default_registry_backend()

    def _revert(entry) -> None:
        key, _, name = entry.target.rpartition("\\")
        if entry.before is None:
            be.delete_value(key, name)
        else:
            be.set_value(key, name, RegValue.from_dict(entry.before))

    for action in (ACTION_SET, ACTION_DELETE, ACTION_MARKER):
        registry.register(action, _revert)
