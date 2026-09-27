"""Engagement context: the single backbone every action runs through.

An :class:`EngagementContext` binds an :class:`~src.engagement.EngagementProfile`
to an :class:`~src.audit.AuditJournal` and a
:class:`~src.audit.ReverterRegistry`. Modules do not touch the target directly;
they go through the context, which:

1. checks the engagement is active and running on an authorized host,
2. authorizes the technique and the specific target (file path or registry key),
3. records the change to the tamper-evident journal (or records a planned entry
   in dry-run mode without applying anything),
4. drives a guaranteed revert of everything applied.

This is what separates an authorized adversary-emulation run from an untracked
one: nothing happens that was not scoped, and everything that happens is logged
and reversible.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .audit import (
    STATUS_APPLIED,
    STATUS_FAILED,
    STATUS_PLANNED,
    AuditEntry,
    AuditJournal,
    ReverterRegistry,
    RevertEngine,
    RevertResult,
)
from .engagement import EngagementProfile

TargetKind = str  # "path" or "registry"


class EngagementContext:
    def __init__(
        self,
        profile: EngagementProfile,
        journal: AuditJournal,
        registry: ReverterRegistry | None = None,
        *,
        dry_run: bool | None = None,
    ) -> None:
        self.profile = profile
        self.journal = journal
        self.registry = registry or ReverterRegistry()
        self.dry_run = profile.dry_run_default if dry_run is None else dry_run
        # Host is fixed for the life of a run; fail fast if it is wrong.
        self.profile.assert_host()

    @classmethod
    def open(
        cls,
        profile_path: str | Path,
        journal_path: str | Path,
        *,
        hmac_key: bytes | None = None,
        registry: ReverterRegistry | None = None,
        dry_run: bool | None = None,
    ) -> "EngagementContext":
        profile = EngagementProfile.load(profile_path)
        journal = AuditJournal(
            journal_path,
            engagement_id=profile.engagement_id,
            operator=profile.operator,
            hmac_key=hmac_key,
        )
        return cls(profile, journal, registry, dry_run=dry_run)

    # -- authorization -----------------------------------------------------

    def authorize(
        self,
        *,
        technique: str,
        target: str,
        target_kind: TargetKind,
        now: datetime | None = None,
    ) -> None:
        """Run every gate for a single action; raise on the first failure."""
        self.profile.assert_active(now)
        self.profile.assert_technique(technique)
        if target_kind == "path":
            self.profile.scope.check_path(target)
        elif target_kind == "registry":
            self.profile.scope.check_registry_key(target)
        else:
            raise ValueError(f"unknown target_kind {target_kind!r}")

    # -- action execution --------------------------------------------------

    def perform(
        self,
        *,
        action: str,
        technique: str,
        target: str,
        target_kind: TargetKind,
        capture_before: Callable[[], Any],
        apply: Callable[[], Any],
        reverter=None,
        now: datetime | None = None,
    ) -> AuditEntry:
        """Authorize, then apply (or plan) one reversible action and journal it.

        ``capture_before`` snapshots the target's current state so it can be
        restored later; it is called even in dry-run mode so the journal shows
        what *would* have changed. ``apply`` performs the change and returns the
        resulting ("after") state. ``reverter``, if given, is registered for this
        action so :meth:`revert` can undo it.
        """
        self.authorize(technique=technique, target=target, target_kind=target_kind, now=now)
        if reverter is not None:
            self.registry.register(action, reverter)

        before = capture_before()
        if self.dry_run:
            return self.journal.record(
                action=action,
                technique=technique,
                target=target,
                before=before,
                after=None,
                status=STATUS_PLANNED,
            )
        try:
            after = apply()
        except Exception as exc:
            self.journal.record(
                action=action,
                technique=technique,
                target=target,
                before=before,
                after={"error": str(exc)},
                status=STATUS_FAILED,
            )
            raise
        return self.journal.record(
            action=action,
            technique=technique,
            target=target,
            before=before,
            after=after,
            status=STATUS_APPLIED,
        )

    # -- rollback ----------------------------------------------------------

    def revert(self, *, strict: bool = True) -> RevertResult:
        """Roll back every applied action recorded in the journal."""
        return RevertEngine(self.journal, self.registry).revert_all(strict=strict)
