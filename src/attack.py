"""MITRE ATT&CK mapping catalog for the TTPs MIRAGE emulates.

This is the reference data that turns an audit journal into something a SOC can
act on. For each technique MIRAGE can emulate, it records the tactic, the data
sources and concrete telemetry (Windows / Sysmon event IDs) a defender should be
collecting, the observables the emulated action leaves behind, and detection
guidance. The report layer joins journal entries to this catalog on the ATT&CK
technique ID recorded with every action.

The content here is defensive: it describes what blue teams should look for. It
is intentionally decoupled from the offensive modules so the mapping can be
reviewed, extended, and validated on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    """Detection-oriented metadata for one ATT&CK (sub-)technique."""

    id: str
    name: str
    tactic: str
    tactic_id: str
    data_sources: tuple[str, ...] = ()
    event_ids: tuple[str, ...] = ()
    observables: tuple[str, ...] = ()
    detection: tuple[str, ...] = ()
    references: tuple[str, ...] = field(default_factory=tuple)

    @property
    def url(self) -> str:
        base = "https://attack.mitre.org/techniques/"
        return base + self.id.replace(".", "/") + "/"


CATALOG: dict[str, Technique] = {
    "T1070": Technique(
        id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=("File: File Modification", "Command: Command Execution", "Windows Event Log"),
        detection=(
            "Alert on deletion or modification of forensic artifacts (logs, file "
            "timestamps, command history) that is inconsistent with normal admin activity.",
        ),
    ),
    "T1070.001": Technique(
        id="T1070.001",
        name="Clear Windows Event Logs",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=("Windows Event Log", "Command: Command Execution", "Process: Process Creation"),
        event_ids=(
            "Security 1102 (the audit log was cleared)",
            "System 104 (event log file was cleared)",
            "Sysmon 1 (process create) for wevtutil.exe / PowerShell Clear-EventLog",
        ),
        observables=(
            "wevtutil cl/clear-log or PowerShell [Diagnostics.EventLog]::Clear invocation",
            "A gap in log continuity immediately following the clear event",
        ),
        detection=(
            "1102/104 should be rare and always investigated; correlate with the process "
            "that issued the clear and the account used.",
        ),
    ),
    "T1070.006": Technique(
        id="T1070.006",
        name="Timestomp",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=("File: File Metadata", "File: File Modification"),
        event_ids=(
            "Sysmon 2 (a process changed a file creation time)",
            "Security 4663 (object access) where file SACLs are configured",
        ),
        observables=(
            "MFT $STANDARD_INFORMATION timestamps that disagree with $FILE_NAME timestamps",
            "Creation time later than modification time, or timestamps predating volume format",
            "Sub-second precision zeroed (many timestomp routines set whole-second times)",
        ),
        detection=(
            "Compare $SI and $FN timestamps in the MFT; most timestomping alters $SI only.",
            "Baseline expected timestamps for sensitive paths and alert on backdating.",
        ),
    ),
    "T1112": Technique(
        id="T1112",
        name="Modify Registry",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=(
            "Windows Registry: Registry Key Modification",
            "Command: Command Execution",
            "Process: Process Creation",
        ),
        event_ids=(
            "Sysmon 13 (registry value set)",
            "Sysmon 12/14 (registry key/value create, delete, rename)",
            "Security 4657 (a registry value was modified) where SACLs are configured",
        ),
        observables=(
            "Unexpected writes to explorer artifact keys (RecentDocs, TypedURLs, RunMRU)",
            "Registry values whose write time is inconsistent with genuine user activity",
        ),
        detection=(
            "Baseline per-user explorer MRU keys and alert on values written outside "
            "interactive sessions or by non-explorer processes.",
        ),
    ),
    "T1562": Technique(
        id="T1562",
        name="Impair Defenses",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=("Command: Command Execution", "Windows Registry", "Sensor Health"),
        detection=(
            "Monitor for changes that disable or blind security telemetry; treat loss of "
            "expected sensor heartbeats as an incident.",
        ),
    ),
    "T1562.002": Technique(
        id="T1562.002",
        name="Disable Windows Event Logging",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        data_sources=(
            "Command: Command Execution",
            "Windows Registry: Registry Key Modification",
            "Windows Service",
        ),
        event_ids=(
            "Security 1100 (the event logging service was shut down)",
            "Security 4719 (system audit policy was changed)",
            "Sysmon 13 on HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\*",
        ),
        observables=(
            "auditpol.exe /set changes disabling subcategories",
            "EventLog service stop/disable, or registry edits to its configuration",
        ),
        detection=(
            "4719/1100 should be exceptional; alert and correlate with the initiating account.",
            "Watch for auditpol usage and EventLog service state changes.",
        ),
    ),
}


def lookup(technique_id: str) -> Technique | None:
    """Resolve a technique ID, falling back from a sub-technique to its parent."""
    tid = technique_id.strip().upper()
    if tid in CATALOG:
        return CATALOG[tid]
    if "." in tid:
        parent = tid.split(".", 1)[0]
        return CATALOG.get(parent)
    return None
