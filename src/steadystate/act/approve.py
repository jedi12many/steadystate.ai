"""Shared remediation-approval core -- the CLI verbs and the chat listener both call here.

Approving rebuilds the source + executor from what the suggesting scan recorded, re-collects
to match the *live* drift by fingerprint (so the executor's snapshot/verify run against
reality, and an already-cleared drift is a clean no-op), then applies under the usual
guardrails. Decline marks it so a re-scan won't re-offer it.
"""

from __future__ import annotations

from pathlib import Path

from ..sources import build_drift_source
from ..state import APPROVED, DECLINED, PENDING, StateStore
from . import build_executor
from .base import RemediationResult


def apply_pending(
    store: StateStore, fingerprint: str, actor: str
) -> tuple[str, RemediationResult | None]:
    """Approve + run the pending remediation for ``fingerprint``. Returns a human message and
    the RemediationResult when one ran (None when there was nothing to do)."""
    action = store.get_pending(fingerprint)
    if action is None or action.status != PENDING:
        return "no pending remediation for that fingerprint.", None
    executor = build_executor(action.source, Path(action.path))
    if executor is None:
        return f"source '{action.source}' is observe-only; cannot remediate.", None
    drifts = build_drift_source(action.source, Path(action.path)).collect_drift()
    drift = next((d for d in drifts if d.fingerprint == fingerprint), None)
    if drift is None:
        store.set_pending_status(fingerprint, APPROVED, actor)
        return "drift no longer present; nothing to do.", None
    result = executor.remediate(drift, confirm=True)
    store.set_pending_status(fingerprint, APPROVED, actor)
    return result.detail, result


def decline_pending(store: StateStore, fingerprint: str, actor: str) -> str:
    """Decline the pending remediation for ``fingerprint``. Returns a human message."""
    if store.get_pending(fingerprint) is None:
        return "no pending remediation for that fingerprint."
    store.set_pending_status(fingerprint, DECLINED, actor)
    return f"declined {fingerprint}"
