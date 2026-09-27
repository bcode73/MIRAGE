"""Tamper-evident audit journal and revert engine.

Unlike anti-forensic tooling that tries to erase its own traces, MIRAGE keeps a
complete, append-only, hash-chained record of every change it makes. The journal
is a primary deliverable: it lets the operator prove exactly what was done, lets
the client reconcile those actions against their own telemetry, and drives a
guaranteed rollback of every applied action at the end of the engagement.

Integrity model
---------------
Each entry stores the SHA-256 of the previous entry (``prev_hash``) plus the
SHA-256 of its own canonical content (``entry_hash``), forming a hash chain: any
edit, reorder, or deletion of a past entry breaks verification. When an HMAC key
is supplied, each entry is additionally signed, so an attacker who rewrites the
whole chain still cannot forge valid signatures without the key.

Revert model
------------
Reverting does not delete anything. The engine restores each applied action's
recorded ``before`` state, then appends a new ``reverted`` entry that references
the original. The record of both the change and its rollback is preserved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .errors import AuditError, IntegrityError, RevertError

GENESIS_HASH = "0" * 64

# Action lifecycle states.
STATUS_PLANNED = "planned"   # recorded in a dry run; never applied to the target
STATUS_APPLIED = "applied"   # change was made to the target
STATUS_REVERTED = "reverted" # a follow-up entry undoing an earlier applied entry
STATUS_FAILED = "failed"     # an attempted change did not complete


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used for hashing and signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class AuditEntry:
    """One immutable record in the journal.

    ``before`` and ``after`` are free-form JSON-serializable snapshots. ``before``
    must carry everything a reverter needs to restore the target.
    """

    seq: int
    timestamp: str
    engagement_id: str
    operator: str
    action: str
    technique: str
    target: str
    status: str
    before: Any
    after: Any
    prev_hash: str
    reverts_seq: int | None = None
    entry_hash: str = ""
    signature: str | None = None

    def content(self) -> dict[str, Any]:
        """The signed/hashed portion of the entry (everything but hash + signature)."""
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "action": self.action,
            "technique": self.technique,
            "target": self.target,
            "status": self.status,
            "before": self.before,
            "after": self.after,
            "prev_hash": self.prev_hash,
            "reverts_seq": self.reverts_seq,
        }

    def compute_hash(self) -> str:
        return hashlib.sha256(_canonical(self.content())).hexdigest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)

    @classmethod
    def from_json(cls, line: str) -> "AuditEntry":
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"journal line is not valid JSON: {exc}") from exc
        try:
            return cls(**data)
        except TypeError as exc:
            raise IntegrityError(f"journal line has unexpected fields: {exc}") from exc


class AuditJournal:
    """Append-only, hash-chained journal persisted as JSON lines.

    An existing journal is loaded and verified on construction, so tampering is
    detected before any new entry is appended.
    """

    def __init__(
        self,
        path: str | Path,
        engagement_id: str,
        operator: str,
        hmac_key: bytes | None = None,
    ) -> None:
        self.path = Path(path)
        self.engagement_id = engagement_id
        self.operator = operator
        self._hmac_key = hmac_key
        self._entries: list[AuditEntry] = []
        if self.path.exists():
            self._load_and_verify()

    # -- persistence -------------------------------------------------------

    def _load_and_verify(self) -> None:
        entries: list[AuditEntry] = []
        for lineno, raw in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                entries.append(AuditEntry.from_json(raw))
            except IntegrityError as exc:
                raise IntegrityError(f"{self.path}:{lineno}: {exc}") from exc
        self._entries = entries
        self.verify()

    def _sign(self, entry_hash: str) -> str | None:
        if self._hmac_key is None:
            return None
        return hmac.new(self._hmac_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

    # -- reading -----------------------------------------------------------

    @property
    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)

    def __iter__(self) -> Iterator[AuditEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def _last_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def verify(self) -> None:
        """Re-derive the hash chain and signatures; raise on any mismatch."""
        prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.seq != idx:
                raise IntegrityError(f"entry {idx} has out-of-order seq {entry.seq}")
            if entry.prev_hash != prev:
                raise IntegrityError(f"entry {entry.seq} breaks the hash chain")
            expected = entry.compute_hash()
            if entry.entry_hash != expected:
                raise IntegrityError(f"entry {entry.seq} content hash does not match (tampered?)")
            if self._hmac_key is not None:
                expected_sig = self._sign(entry.entry_hash)
                if entry.signature is None or not hmac.compare_digest(entry.signature, expected_sig):
                    raise IntegrityError(f"entry {entry.seq} has an invalid signature")
            prev = entry.entry_hash

    # -- writing -----------------------------------------------------------

    def record(
        self,
        *,
        action: str,
        technique: str,
        target: str,
        before: Any = None,
        after: Any = None,
        status: str = STATUS_APPLIED,
        reverts_seq: int | None = None,
    ) -> AuditEntry:
        """Append one entry and flush it to disk; returns the stored entry."""
        seq = len(self._entries)
        draft = AuditEntry(
            seq=seq,
            timestamp=_now_iso(),
            engagement_id=self.engagement_id,
            operator=self.operator,
            action=action,
            technique=technique,
            target=target,
            status=status,
            before=before,
            after=after,
            prev_hash=self._last_hash,
            reverts_seq=reverts_seq,
        )
        entry_hash = draft.compute_hash()
        entry = AuditEntry(
            **{**asdict(draft), "entry_hash": entry_hash, "signature": self._sign(entry_hash)}
        )
        self._append_line(entry)
        self._entries.append(entry)
        return entry

    def _append_line(self, entry: AuditEntry) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(entry.to_json() + "\n")

    def reverted_seqs(self) -> set[int]:
        """Sequence numbers of applied entries that already have a revert entry."""
        return {e.reverts_seq for e in self._entries if e.status == STATUS_REVERTED and e.reverts_seq is not None}

    def pending_applied(self) -> list[AuditEntry]:
        """Applied entries that have not yet been reverted, newest first."""
        done = self.reverted_seqs()
        pending = [e for e in self._entries if e.status == STATUS_APPLIED and e.seq not in done]
        return sorted(pending, key=lambda e: e.seq, reverse=True)


# A reverter restores the target described by an entry to the entry's ``before``
# state. Offensive modules register one per action type they emit.
Reverter = Callable[[AuditEntry], None]


@dataclass
class ReverterRegistry:
    """Maps an action name to the function that can undo it."""

    _handlers: dict[str, Reverter] = field(default_factory=dict)

    def register(self, action: str, handler: Reverter) -> None:
        self._handlers[action] = handler

    def get(self, action: str) -> Reverter | None:
        return self._handlers.get(action)


@dataclass
class RevertResult:
    reverted: list[int] = field(default_factory=list)
    failed: dict[int, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failed


class RevertEngine:
    """Rolls back applied actions in reverse order using registered reverters."""

    def __init__(self, journal: AuditJournal, registry: ReverterRegistry) -> None:
        self.journal = journal
        self.registry = registry

    def revert_all(self, *, strict: bool = True) -> RevertResult:
        """Revert every pending applied action, newest first.

        With ``strict`` (the default) the first failure aborts and raises, so a
        half-reverted engagement is surfaced loudly. With ``strict=False`` the
        engine continues and reports per-entry failures in the result.
        """
        result = RevertResult()
        for entry in self.journal.pending_applied():
            handler = self.registry.get(entry.action)
            if handler is None:
                msg = f"no reverter registered for action {entry.action!r}"
                if strict:
                    raise RevertError(f"cannot revert entry {entry.seq}: {msg}")
                result.failed[entry.seq] = msg
                continue
            try:
                handler(entry)
            except Exception as exc:  # noqa: BLE001 - reverter failures must be captured, not leaked
                if strict:
                    raise RevertError(f"reverter for entry {entry.seq} failed: {exc}") from exc
                result.failed[entry.seq] = str(exc)
                self.journal.record(
                    action=entry.action,
                    technique=entry.technique,
                    target=entry.target,
                    before=entry.before,
                    after=entry.after,
                    status=STATUS_FAILED,
                    reverts_seq=entry.seq,
                )
                continue
            self.journal.record(
                action=entry.action,
                technique=entry.technique,
                target=entry.target,
                before=entry.after,
                after=entry.before,
                status=STATUS_REVERTED,
                reverts_seq=entry.seq,
            )
            result.reverted.append(entry.seq)
        return result
