"""Purple-team detection report generator.

Consumes an :class:`~src.audit.AuditJournal` and emits, for every emulated
action, the telemetry a blue team should have captured -- mapped to MITRE ATT&CK
via :mod:`src.attack`. The output is meant to be diffed against the SOC's own
SIEM/EDR alerts: any expectation with no corresponding detection is a coverage
gap and a finding for the engagement report.

Three renderings are produced:

* ``to_dict`` / JSON  -- machine-readable, for tooling and diffing.
* ``to_markdown``     -- human-readable, drops straight into a report.
* ``to_navigator_layer`` -- an ATT&CK Navigator layer highlighting exercised
  techniques, for import into the MITRE ATT&CK Navigator.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .attack import CATALOG, Technique, lookup
from .audit import STATUS_APPLIED, STATUS_PLANNED, AuditEntry, AuditJournal
from .engagement import EngagementProfile

# Statuses that represent an emulated adversary action worth validating detection for.
DEFAULT_REPORTED_STATUSES = (STATUS_APPLIED, STATUS_PLANNED)


@dataclass
class DetectionExpectation:
    """What the SOC should have observed for a single journal entry."""

    seq: int
    timestamp: str
    action: str
    status: str
    operator: str
    target: str
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: str
    mapped: bool
    data_sources: list[str] = field(default_factory=list)
    expected_event_ids: list[str] = field(default_factory=list)
    expected_observables: list[str] = field(default_factory=list)
    detection_guidance: list[str] = field(default_factory=list)
    reference_url: str = ""


def _engagement_header(entries: Iterable[AuditEntry], profile: EngagementProfile | None) -> dict[str, Any]:
    entries = list(entries)
    first = entries[0] if entries else None
    if profile is not None:
        return {
            "engagement_id": profile.engagement_id,
            "client": profile.client,
            "operator": profile.operator,
            "authorized_by": profile.authorized_by,
            "roe_reference": profile.roe_reference,
            "allowed_hosts": list(profile.allowed_hosts),
            "window": {
                "starts_at": profile.starts_at.isoformat(),
                "expires_at": profile.expires_at.isoformat(),
            },
        }
    return {
        "engagement_id": first.engagement_id if first else "unknown",
        "operator": first.operator if first else "unknown",
        "client": None,
        "authorized_by": None,
        "roe_reference": None,
        "allowed_hosts": [],
        "window": None,
    }


class PurpleTeamReport:
    def __init__(
        self,
        entries: Iterable[AuditEntry],
        profile: EngagementProfile | None = None,
        *,
        reported_statuses: tuple[str, ...] = DEFAULT_REPORTED_STATUSES,
    ) -> None:
        self._all_entries = list(entries)
        self.profile = profile
        self.reported_statuses = reported_statuses
        self.generated_at = datetime.now(timezone.utc).isoformat()

    @classmethod
    def from_journal(cls, journal: AuditJournal, profile: EngagementProfile | None = None, **kw) -> "PurpleTeamReport":
        return cls(journal.entries, profile, **kw)

    # -- core --------------------------------------------------------------

    def expectations(self) -> list[DetectionExpectation]:
        out: list[DetectionExpectation] = []
        for entry in self._all_entries:
            if entry.status not in self.reported_statuses:
                continue
            out.append(self._expectation_for(entry))
        return out

    def _expectation_for(self, entry: AuditEntry) -> DetectionExpectation:
        tech: Technique | None = lookup(entry.technique)
        if tech is None:
            return DetectionExpectation(
                seq=entry.seq,
                timestamp=entry.timestamp,
                action=entry.action,
                status=entry.status,
                operator=entry.operator,
                target=entry.target,
                technique_id=entry.technique,
                technique_name="(unmapped technique)",
                tactic="unknown",
                tactic_id="",
                mapped=False,
            )
        return DetectionExpectation(
            seq=entry.seq,
            timestamp=entry.timestamp,
            action=entry.action,
            status=entry.status,
            operator=entry.operator,
            target=entry.target,
            technique_id=tech.id,
            technique_name=tech.name,
            tactic=tech.tactic,
            tactic_id=tech.tactic_id,
            mapped=True,
            data_sources=list(tech.data_sources),
            expected_event_ids=list(tech.event_ids),
            expected_observables=list(tech.observables),
            detection_guidance=list(tech.detection),
            reference_url=tech.url,
        )

    def attack_coverage(self) -> list[dict[str, Any]]:
        """Per-technique summary of what was exercised, sorted by technique ID."""
        counts: dict[str, dict[str, Any]] = {}
        for exp in self.expectations():
            row = counts.setdefault(
                exp.technique_id,
                {
                    "technique_id": exp.technique_id,
                    "technique_name": exp.technique_name,
                    "tactic": exp.tactic,
                    "mapped": exp.mapped,
                    "action_count": 0,
                    "reference_url": exp.reference_url,
                },
            )
            row["action_count"] += 1
        return [counts[k] for k in sorted(counts)]

    # -- renderings --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        expectations = self.expectations()
        coverage = self.attack_coverage()
        return {
            "generated_at": self.generated_at,
            "tool": "MIRAGE",
            "report_type": "purple-team-detection-validation",
            "engagement": _engagement_header(self._all_entries, self.profile),
            "summary": {
                "action_count": len(expectations),
                "technique_count": len(coverage),
                "unmapped_actions": sum(1 for e in expectations if not e.mapped),
            },
            "attack_coverage": coverage,
            "expectations": [asdict(e) for e in expectations],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_navigator_layer(self) -> dict[str, Any]:
        coverage = self.attack_coverage()
        max_count = max((row["action_count"] for row in coverage), default=1)
        header = _engagement_header(self._all_entries, self.profile)
        techniques = [
            {
                "techniqueID": row["technique_id"],
                "score": row["action_count"],
                "comment": f"{row['action_count']} MIRAGE action(s)",
                "enabled": True,
            }
            for row in coverage
            if row["mapped"]
        ]
        return {
            "name": f"MIRAGE - {header['engagement_id']}",
            "versions": {"attack": "14", "navigator": "4.9.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Techniques exercised by MIRAGE during authorized adversary emulation.",
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffe6e6", "#ff3333"],
                "minValue": 0,
                "maxValue": max_count,
            },
            "legendItems": [],
        }

    def to_markdown(self) -> str:
        header = _engagement_header(self._all_entries, self.profile)
        expectations = self.expectations()
        coverage = self.attack_coverage()
        lines: list[str] = []
        lines.append("# MIRAGE Purple-Team Detection Report")
        lines.append("")
        lines.append(f"_Generated {self.generated_at}_")
        lines.append("")
        lines.append("## Engagement")
        lines.append("")
        lines.append(f"- Engagement: `{header['engagement_id']}`")
        if header.get("client"):
            lines.append(f"- Client: {header['client']}")
        lines.append(f"- Operator: {header['operator']}")
        if header.get("authorized_by"):
            lines.append(f"- Authorized by: {header['authorized_by']}")
        if header.get("roe_reference"):
            lines.append(f"- RoE: {header['roe_reference']}")
        if header.get("allowed_hosts"):
            lines.append(f"- Hosts: {', '.join(header['allowed_hosts'])}")
        if header.get("window"):
            lines.append(f"- Window: {header['window']['starts_at']} -> {header['window']['expires_at']}")
        lines.append("")
        lines.append(
            f"**{len(expectations)} emulated action(s)** across "
            f"**{len(coverage)} ATT&CK technique(s)**. Compare each expected detection "
            "below against your SIEM/EDR; anything not detected is a coverage gap."
        )
        lines.append("")

        lines.append("## ATT&CK coverage")
        lines.append("")
        lines.append("| Technique | Name | Tactic | Actions |")
        lines.append("| --- | --- | --- | --- |")
        for row in coverage:
            tid = f"[{row['technique_id']}]({row['reference_url']})" if row["reference_url"] else row["technique_id"]
            lines.append(f"| {tid} | {row['technique_name']} | {row['tactic']} | {row['action_count']} |")
        lines.append("")

        lines.append("## Expected detections")
        lines.append("")
        for exp in expectations:
            lines.append(f"### #{exp.seq} - {exp.action} ({exp.technique_id})")
            lines.append("")
            lines.append(f"- Technique: {exp.technique_name} ({exp.tactic}) - {exp.reference_url}")
            lines.append(f"- Target: `{exp.target}`")
            lines.append(f"- When: {exp.timestamp}  |  Status: {exp.status}  |  Operator: {exp.operator}")
            if not exp.mapped:
                lines.append("- NOTE: technique is not in the MIRAGE ATT&CK catalog; add a mapping.")
                lines.append("")
                continue
            if exp.data_sources:
                lines.append(f"- Data sources: {', '.join(exp.data_sources)}")
            if exp.expected_event_ids:
                lines.append("- Expected telemetry:")
                lines.extend(f"    - {ev}" for ev in exp.expected_event_ids)
            if exp.expected_observables:
                lines.append("- Observables:")
                lines.extend(f"    - {ob}" for ob in exp.expected_observables)
            if exp.detection_guidance:
                lines.append("- Detection guidance:")
                lines.extend(f"    - {g}" for g in exp.detection_guidance)
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # -- file output -------------------------------------------------------

    def write_files(self, out_dir: str | Path, *, prefix: str = "mirage-report") -> dict[str, Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = {
            "json": out / f"{prefix}.json",
            "markdown": out / f"{prefix}.md",
            "navigator": out / f"{prefix}.navigator.json",
        }
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        paths["markdown"].write_text(self.to_markdown(), encoding="utf-8")
        paths["navigator"].write_text(
            json.dumps(self.to_navigator_layer(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return paths


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.report",
        description="Generate a purple-team detection report from a MIRAGE audit journal.",
    )
    parser.add_argument("journal", help="path to the audit journal (JSONL)")
    parser.add_argument("--profile", help="engagement profile JSON for a richer header", default=None)
    parser.add_argument("--out", help="output directory for report files", default=None)
    parser.add_argument(
        "--format",
        choices=("json", "md", "navigator"),
        default="md",
        help="format to print to stdout when --out is not given (default: md)",
    )
    args = parser.parse_args(argv)

    profile = EngagementProfile.load(args.profile) if args.profile else None
    engagement_id = profile.engagement_id if profile else "report"
    operator = profile.operator if profile else "report"
    journal = AuditJournal(args.journal, engagement_id, operator)
    report = PurpleTeamReport.from_journal(journal, profile)

    if args.out:
        paths = report.write_files(args.out)
        for kind, path in paths.items():
            print(f"{kind}: {path}")
        return 0

    if args.format == "json":
        print(report.to_json())
    elif args.format == "navigator":
        print(json.dumps(report.to_navigator_layer(), indent=2, ensure_ascii=False))
    else:
        print(report.to_markdown())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
