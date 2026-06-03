"""Shared remediation-approval core -- the CLI verbs and the chat listener both call here.

Approving rebuilds the source + executor from what the suggesting scan recorded, re-collects
to match the *live* drift by fingerprint (so the executor's snapshot/verify run against
reality, and an already-cleared drift is a clean no-op), then applies under the usual
guardrails. Decline marks it so a re-scan won't re-offer it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..sources import build_drift_source
from ..state import (
    APPLIED,
    APPROVED,
    DECLINED,
    FAILED,
    NOOP,
    PENDING,
    VERIFIED,
    AuditEntry,
    PendingAction,
    StateStore,
)
from . import build_executor
from .base import RemediationResult
from .cleanup import CLEANUP_SOURCE, run_cleanup
from .execute import CATALOG_SOURCE, run_catalog_action


def _audit(
    action: PendingAction, actor: str, decision: str, outcome: str, detail: str | None
) -> AuditEntry:
    """Build the append-only audit record for a decision on ``action``."""
    return AuditEntry(
        fingerprint=action.fingerprint,
        source=action.source,
        drift_identity=action.drift_identity,
        actor=actor,
        decision=decision,
        outcome=outcome,
        environment=action.environment,
        detail=detail,
    )


def apply_pending(
    store: StateStore, fingerprint: str, actor: str, now: datetime | None = None
) -> tuple[str, RemediationResult | None]:
    """Approve + run the pending remediation for ``fingerprint``. Returns a human message and
    the RemediationResult when one ran (None when there was nothing to do). Every decision that
    reaches a real remediation point is recorded to the append-only audit log."""
    now = now or datetime.now(UTC)
    action = store.get_pending(fingerprint)
    if action is None or action.status != PENDING:
        return "no pending remediation for that fingerprint.", None
    if action.source in (CLEANUP_SOURCE, CATALOG_SOURCE):  # a direct, re-validated catalog command
        # Claim before the irreversible step (same race guard as the drift path), then run the
        # allow-listed command and audit it. No drift source/executor -- the command is it. Both
        # the evicted cleanup and the general `fix`/`run` actions route here through the same gate.
        if not store.claim_pending(fingerprint, PENDING, APPROVED, actor):
            return "no pending remediation for that fingerprint.", None
        result = (
            run_cleanup(action) if action.source == CLEANUP_SOURCE else run_catalog_action(action)
        )
        outcome = VERIFIED if result.verified else APPLIED if result.applied else FAILED
        store.record_audit(_audit(action, actor, APPROVED, outcome, result.detail), now)
        return result.detail, result
    executor = build_executor(action.source, Path(action.path))
    if executor is None:
        return f"source '{action.source}' is observe-only; cannot remediate.", None
    # Atomically claim the action (pending -> approved) BEFORE anything irreversible. Two approvers
    # racing the same fingerprint (two chat users) both read PENDING above; the conditional UPDATE
    # lets exactly one win -- the loser bails here, so the remediation runs at most once.
    if not store.claim_pending(fingerprint, PENDING, APPROVED, actor):
        return "no pending remediation for that fingerprint.", None
    drifts = build_drift_source(action.source, Path(action.path)).collect_drift()
    drift = next((d for d in drifts if d.fingerprint == fingerprint), None)
    if drift is None:
        store.record_audit(_audit(action, actor, APPROVED, NOOP, "drift no longer present"), now)
        return "drift no longer present; nothing to do.", None
    result = executor.remediate(drift, confirm=True)
    outcome = VERIFIED if result.verified else APPLIED if result.applied else FAILED
    store.record_audit(_audit(action, actor, APPROVED, outcome, result.detail), now)
    return result.detail, result


def decline_pending(
    store: StateStore, fingerprint: str, actor: str, now: datetime | None = None
) -> str:
    """Decline the pending remediation for ``fingerprint``. Returns a human message."""
    now = now or datetime.now(UTC)
    action = store.get_pending(fingerprint)
    if action is None:
        return "no pending remediation for that fingerprint."
    store.set_pending_status(fingerprint, DECLINED, actor)
    store.record_audit(_audit(action, actor, DECLINED, DECLINED, None), now)
    return f"declined {fingerprint}"
