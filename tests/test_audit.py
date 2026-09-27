"""Tests for the tamper-evident audit journal and revert engine (#2)."""

from __future__ import annotations

import pytest

from src.audit import (
    STATUS_APPLIED,
    STATUS_REVERTED,
    AuditJournal,
    ReverterRegistry,
    RevertEngine,
)
from src.errors import IntegrityError, RevertError


def _record_two(journal: AuditJournal) -> None:
    journal.record(action="a.one", technique="T1070.006", target="C:/lab/a", before={"v": 0}, after={"v": 1})
    journal.record(action="a.two", technique="T1070.006", target="C:/lab/b", before={"v": 2}, after={"v": 3})


def test_record_builds_chain_and_verifies(journal_path):
    journal = AuditJournal(journal_path, "E1", "op@test")
    _record_two(journal)
    assert len(journal) == 2
    assert journal.entries[0].prev_hash == "0" * 64
    assert journal.entries[1].prev_hash == journal.entries[0].entry_hash
    journal.verify()  # does not raise


def test_reload_verifies(journal_path):
    _record_two(AuditJournal(journal_path, "E1", "op@test"))
    reopened = AuditJournal(journal_path, "E1", "op@test")  # verifies on load
    assert len(reopened) == 2


def test_tampered_entry_detected(journal_path):
    _record_two(AuditJournal(journal_path, "E1", "op@test"))
    lines = journal_path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"C:/lab/a"', '"C:/lab/HACKED"')
    journal_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(IntegrityError):
        AuditJournal(journal_path, "E1", "op@test")


def test_hmac_signature_roundtrip_and_wrong_key(journal_path):
    AuditJournal(journal_path, "E1", "op@test", hmac_key=b"correct-key").record(
        action="a.one", technique="T1070.006", target="C:/lab/a", before=None, after=None
    )
    AuditJournal(journal_path, "E1", "op@test", hmac_key=b"correct-key")  # ok
    with pytest.raises(IntegrityError):
        AuditJournal(journal_path, "E1", "op@test", hmac_key=b"wrong-key")


def test_revert_restores_state_and_preserves_record(journal_path):
    store = {"k": "original"}
    registry = ReverterRegistry()
    registry.register("kv.set", lambda entry: store.__setitem__("k", entry.before["value"]))

    journal = AuditJournal(journal_path, "E1", "op@test")
    store["k"] = "tampered"
    journal.record(
        action="kv.set", technique="T1070.006", target="kv://k",
        before={"value": "original"}, after={"value": "tampered"},
    )
    assert journal.pending_applied()

    result = RevertEngine(journal, registry).revert_all()
    assert result.ok
    assert store["k"] == "original"          # state restored
    assert not journal.pending_applied()     # nothing left to revert
    # The record is preserved: original applied entry stays, a reverted entry is appended.
    statuses = [e.status for e in journal]
    assert STATUS_APPLIED in statuses and STATUS_REVERTED in statuses
    assert journal.reverted_seqs() == {0}


def test_double_revert_is_noop(journal_path):
    store = {"k": "original"}
    registry = ReverterRegistry()
    registry.register("kv.set", lambda entry: store.__setitem__("k", entry.before["value"]))
    journal = AuditJournal(journal_path, "E1", "op@test")
    journal.record(action="kv.set", technique="T1070.006", target="kv://k",
                   before={"value": "original"}, after={"value": "tampered"})

    engine = RevertEngine(journal, registry)
    engine.revert_all()
    second = engine.revert_all()
    assert second.reverted == []  # already reverted, nothing to do


def test_missing_reverter_strict_raises(journal_path):
    journal = AuditJournal(journal_path, "E1", "op@test")
    journal.record(action="unknown.action", technique="T1070.006", target="x", before=1, after=2)
    with pytest.raises(RevertError):
        RevertEngine(journal, ReverterRegistry()).revert_all(strict=True)


def test_missing_reverter_nonstrict_reports(journal_path):
    journal = AuditJournal(journal_path, "E1", "op@test")
    journal.record(action="unknown.action", technique="T1070.006", target="x", before=1, after=2)
    result = RevertEngine(journal, ReverterRegistry()).revert_all(strict=False)
    assert not result.ok
    assert 0 in result.failed
