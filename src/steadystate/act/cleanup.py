"""Evicted-pod cleanup: a guardrailed, command-based remediation for a health Symptom.

A drift remediation rebuilds an executor and reconciles declared vs observed. An evicted-pod
cleanup is different: there is no declared/observed divergence, just dead tombstones to delete --
so the kubectl probe already composed the exact, safe `kubectl delete` (see kubectl._fix_for). We
record it as a PendingAction with a sentinel ``source`` and run it through the SAME approve
guardrail every drift remediation uses: claimed once (no double-run), recorded to the append-only
audit log, and -- crucially -- **re-validated against a strict allow-pattern at run time**, so the
tool can only ever delete pods a human approved, and only with the one cleanup shape we generate
(never an arbitrary command, even if the stored action were tampered with).
"""

from __future__ import annotations

import re
import shlex
import subprocess
from datetime import datetime

from ..state import PendingAction, StateStore
from .base import RemediationResult
from .bounds import Envelope, Impact, Reversibility
from .plan import RemediationPlan, Risk

# The evicted-pod cleanup's envelope: it deletes already-dead (Evicted/Failed) pods in one
# namespace -- nothing of value is destroyed (lossless), and the blast radius is one tenant. The
# bound (act/bounds.py) reads this; the SAME calculus governs it as governs a terraform apply.
CLEANUP_ENVELOPE = Envelope(Reversibility.LOSSLESS, Impact.TENANT)

# The sentinel ``source`` that marks a PendingAction as a direct cleanup command rather than a
# drift remediation -- ``apply_pending`` routes on it. Not a real DriftSource (no executor).
CLEANUP_SOURCE = "kubectl-cleanup"

# The ONE command shape we will execute: the evicted/Failed-phase pod cleanup the probe composes.
# Anchored + character-classed so no shell metacharacter or alternate verb can slip through -- the
# namespace and context are k8s-validated names. Re-checked at run time (defense in depth).
_SAFE_CLEANUP = re.compile(
    r"^kubectl delete pods(?: -n [\w.-]+)? "
    r"--field-selector=status\.phase=Failed(?: --context [\w.@:/-]+)?$"
)


def is_safe_cleanup(command: str) -> bool:
    """True iff ``command`` is exactly the evicted-pod cleanup we generate -- the only thing approve
    will run on the cleanup path. Pure; the security gate for command execution."""
    return bool(_SAFE_CLEANUP.match(command.strip()))


def record_cleanups(store: StateStore, report, now: datetime) -> int:
    """Record an approvable cleanup (a PendingAction keyed by the symptom's fingerprint) for every
    evicted Symptom that carries a safe fix -- so it shows in `pending` and `approve <fp>` runs it.
    Idempotent (record_pending upserts by fingerprint). Returns how many were recorded.

    Never auto-runs: it only *offers* the cleanup. (The `--autonomy auto` path applies eligible
    *drift* fingerprints, which this is not -- so a cleanup always waits for an approve.)"""
    recorded = 0
    for alert in report.alerts:
        for symptom in alert.symptoms:
            action = symptom.recommended_action
            if action and is_safe_cleanup(action):
                store.record_pending(
                    PendingAction(
                        fingerprint=symptom.fingerprint,
                        source=CLEANUP_SOURCE,
                        path="",
                        drift_identity=symptom.identity,
                        command=action,
                    ),
                    now,
                )
                recorded += 1
    return recorded


def run_cleanup(action: PendingAction, *, timeout: float = 30.0) -> RemediationResult:
    """Run an approved evicted-pod cleanup. Re-validates the command against the allow-pattern first
    (refuses anything else), then runs it as an argv list (no shell), with a timeout. Returns a
    RemediationResult the audit log records. Best-effort: a failed delete is reported, not raised.
    """
    plan = RemediationPlan(
        drift_identity=action.drift_identity,
        eligible=True,
        risk=Risk.LOW,  # deleting dead (Evicted/Failed) tombstones -- nothing running is touched
        reason="evicted-pod cleanup",
        command=shlex.split(action.command),
        blast_radius="deletes Failed-phase (evicted) pods in the namespace",
        revert="none -- the deleted pods were already dead (Evicted)",
        envelope=CLEANUP_ENVELOPE,
    )
    if not is_safe_cleanup(action.command):  # defense in depth: never run an unrecognized command
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"refused: not a recognized cleanup command ({action.command!r}).",
        )
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list (no shell), command allow-pattern-validated
            plan.command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RemediationResult(
            plan=plan, applied=False, verified=False, detail=f"cleanup failed: {exc}"
        )
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout or "").strip()[:200]
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"cleanup failed (exit {proc.returncode}): {why}",
        )
    out = (proc.stdout or "").strip()[:200]
    return RemediationResult(
        plan=plan, applied=True, verified=True, detail=f"cleaned up evicted pods. {out}".strip()
    )
