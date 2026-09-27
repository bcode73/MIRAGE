"""Tests for the ATT&CK mapping and purple-team report generator (#3)."""

from __future__ import annotations

import json

from src.attack import lookup
from src.audit import AuditJournal
from src.engagement import EngagementProfile
from src.report import PurpleTeamReport

from conftest import make_profile_dict


def _journal_with_actions(path) -> AuditJournal:
    j = AuditJournal(path, "TEST-2026-001", "operator@test.example")
    j.record(action="timestomp.set", technique="T1070.006",
             target="C:/RedTeamLab/secret.txt", before={"mtime": 100}, after={"mtime": 1})
    j.record(action="registry.plant", technique="T1112",
             target="HKCU/.../RecentDocs/FakeDownload", before=None, after={"value": "x"})
    j.record(action="eventlog.clear", technique="T1070.001",
             target="Security", before=None, after=None)
    return j


def test_attack_lookup_and_subtechnique_fallback():
    assert lookup("T1070.006").name == "Timestomp"
    assert lookup("t1112").id == "T1112"          # case-insensitive
    assert lookup("T1070.999").id == "T1070"      # unknown sub falls back to parent
    assert lookup("T9999") is None


def test_technique_url():
    assert lookup("T1070.006").url == "https://attack.mitre.org/techniques/T1070/006/"


def test_report_expectations_and_coverage(journal_path):
    journal = _journal_with_actions(journal_path)
    profile = EngagementProfile.from_dict(make_profile_dict(techniques=["T1070", "T1112"]))
    report = PurpleTeamReport.from_journal(journal, profile)

    exps = report.expectations()
    assert len(exps) == 3
    ts = next(e for e in exps if e.action == "timestomp.set")
    assert ts.technique_name == "Timestomp"
    assert ts.tactic == "Defense Evasion"
    assert any("Sysmon 2" in ev for ev in ts.expected_event_ids)
    assert ts.mapped

    coverage = report.attack_coverage()
    ids = {row["technique_id"] for row in coverage}
    assert ids == {"T1070.006", "T1112", "T1070.001"}
    assert all(row["action_count"] == 1 for row in coverage)


def test_report_dict_structure(journal_path):
    report = PurpleTeamReport.from_journal(_journal_with_actions(journal_path))
    d = report.to_dict()
    assert d["report_type"] == "purple-team-detection-validation"
    assert d["summary"]["action_count"] == 3
    assert d["summary"]["technique_count"] == 3
    assert d["summary"]["unmapped_actions"] == 0
    assert len(d["expectations"]) == 3


def test_report_markdown_mentions_targets_and_techniques(journal_path):
    journal = _journal_with_actions(journal_path)
    profile = EngagementProfile.from_dict(make_profile_dict())
    md = PurpleTeamReport.from_journal(journal, profile).to_markdown()
    assert "# MIRAGE Purple-Team Detection Report" in md
    assert "Timestomp" in md
    assert "C:/RedTeamLab/secret.txt" in md
    assert "attack.mitre.org/techniques/T1070/006/" in md
    assert "TEST-2026-001" in md


def test_navigator_layer_valid(journal_path):
    layer = PurpleTeamReport.from_journal(_journal_with_actions(journal_path)).to_navigator_layer()
    assert layer["domain"] == "enterprise-attack"
    tids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1070.006" in tids and "T1112" in tids
    # round-trips as JSON
    json.loads(json.dumps(layer))


def test_unmapped_technique_is_flagged(journal_path):
    j = AuditJournal(journal_path, "E1", "op@test")
    j.record(action="mystery.op", technique="T9999", target="x", before=None, after=None)
    report = PurpleTeamReport.from_journal(j)
    d = report.to_dict()
    assert d["summary"]["unmapped_actions"] == 1
    assert d["expectations"][0]["mapped"] is False
    assert "unmapped" in report.to_markdown().lower()


def test_write_files(tmp_path, journal_path):
    report = PurpleTeamReport.from_journal(_journal_with_actions(journal_path))
    paths = report.write_files(tmp_path / "out")
    assert paths["json"].exists() and paths["markdown"].exists() and paths["navigator"].exists()
    json.loads(paths["json"].read_text(encoding="utf-8"))
    json.loads(paths["navigator"].read_text(encoding="utf-8"))


def test_reverted_and_failed_excluded_by_default(journal_path):
    j = AuditJournal(journal_path, "E1", "op@test")
    j.record(action="timestomp.set", technique="T1070.006", target="C:/RedTeamLab/a", before={"m": 1}, after={"m": 2})
    j.record(action="timestomp.set", technique="T1070.006", target="C:/RedTeamLab/a",
             before={"m": 2}, after={"m": 1}, status="reverted", reverts_seq=0)
    report = PurpleTeamReport.from_journal(j)
    assert len(report.expectations()) == 1  # only the applied action, not the revert
