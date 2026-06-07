"""Run an authored SOLUTION (from the wall's runbook) as a guardrailed remediation.

When a finding matches a solution that carries a runnable command, it's offered as a PendingAction
-- so `pending` lists it and `approve <fp>` runs it through the SAME gate every remediation uses:
claimed once (no double-run) and recorded to the append-only audit log (with the author, so
`history` shows who vouched for the fix and who approved it).

The trust model is the open-body one (see ``probe/solutions.py``): a check runs unattended, so its
schema is strict; a solution is **operator-vouched**, so -- unlike the evicted-pod cleanup -- there
is NO content allow-pattern here. The runbook is IaC-grade intent (version-controlled, reviewed),
and the gate is **approval + the bound + the audit**, not a restriction on the command. It runs as
an argv list (``shlex.split``, **no shell**) with a timeout. A solution with no runnable command
(e.g. a bare ``reboot`` target) is surfaced in `show` for a human, never offered as an auto-runnable
action. This slice is **approve-only** -- like the cleanup, it offers and never auto-runs; the bound
it records (from impact/reversibility) is what a future auto path will read.
"""

from __future__ import annotations

import re
import shlex
import subprocess  # noqa: S404 -- argv list (no shell); the operator authored + vouched for the command
from datetime import datetime

from ..probe.solutions import Solution, load_solutions, solutions_for
from ..state import PendingAction, StateStore
from .base import RemediationResult
from .bounds import Envelope, Impact, Reversibility
from .plan import RemediationPlan, Risk

# The sentinel ``source`` marking a PendingAction as an authored-solution command (apply_pending
# routes on it). Not a real DriftSource -- the stored command is the whole action.
SOLUTION_SOURCE = "solution"

_PLACEHOLDER = re.compile(r"\{(\w+)\}")  # {namespace} / {workload} -- filled from the finding

# A solution's impact/reversibility -> the generic Envelope the bound reads (display now; the auto
# gate later). Conservative: a low/high pairing still sits below the autonomous ceiling.
_REVERSIBILITY = {
    "high": Reversibility.SELF_HEALING,
    "medium": Reversibility.RECOVERABLE,
    "low": Reversibility.IRREVERSIBLE,
}
_IMPACT = {"low": Impact.SERVICE, "medium": Impact.TENANT, "high": Impact.NODE}
_RISK = {"low": Risk.LOW, "medium": Risk.MEDIUM, "high": Risk.HIGH}


def _fill(template: str, context: dict[str, str]) -> str:
    """Fill ``{key}`` from the finding's evidence (namespace, workload, ...); an unknown key is left
    as-is, so the caller can detect an unfilled command and decline to offer a broken one."""
    return _PLACEHOLDER.sub(lambda m: context.get(m.group(1)) or m.group(0), template)


def _envelope(sol: Solution) -> Envelope:
    return Envelope(
        _REVERSIBILITY.get(sol.reversibility, Reversibility.RECOVERABLE),
        _IMPACT.get(sol.impact, Impact.TENANT),
    )


def record_solution_remediations(
    store: StateStore, report, now: datetime, *, solutions: list[Solution] | None = None
) -> int:
    """For every malfunction (Symptom) that matches an authored solution with a runnable command,
    record a PendingAction (keyed by the symptom's fingerprint) so it shows in `pending` and
    `approve <fp>` runs it. The author rides in ``drift_identity`` -> the audit. Idempotent
    (record_pending upserts). A solution with no `run`, or whose placeholders don't fill, is
    skipped (surfaced in `show`, not offered). Never auto-runs -- it offers; approve is the gate."""
    sols = solutions if solutions is not None else load_solutions()
    if not sols:
        return 0
    recorded = 0
    for alert in report.alerts:
        for symptom in alert.symptoms:
            matches = solutions_for(symptom.category, symptom.title, sols)
            runnable = next((s for s in matches if s.run), None)
            if runnable is None:
                continue
            command = _fill(runnable.run, symptom.evidence)
            if _PLACEHOLDER.search(
                command
            ):  # an unfilled {placeholder} -> don't offer a broken cmd
                continue
            store.record_pending(
                PendingAction(
                    fingerprint=symptom.fingerprint,
                    source=SOLUTION_SOURCE,
                    path="",
                    drift_identity=f"{runnable.name} (author: {runnable.author})",
                    command=command,
                ),
                now,
            )
            recorded += 1
    return recorded


def run_solution(
    action: PendingAction, sol: Solution | None = None, *, timeout: float = 300.0
) -> RemediationResult:
    """Run an approved authored-solution command as an argv list (no shell), with a timeout. No
    content allow-pattern -- the operator authored + vouched for it; the gate is approval + audit.
    ``sol`` (the matching runbook entry, when resolvable) sets the bound the plan records; without
    it, a conservative default. Best-effort: a failed/timed-out command is reported, not raised."""
    envelope = (
        _envelope(sol) if sol is not None else Envelope(Reversibility.RECOVERABLE, Impact.TENANT)
    )
    risk = _RISK.get(sol.impact, Risk.MEDIUM) if sol is not None else Risk.MEDIUM
    plan = RemediationPlan(
        drift_identity=action.drift_identity,
        eligible=True,
        risk=risk,
        reason=f"authored solution: {action.drift_identity}",
        command=shlex.split(action.command),
        blast_radius="runs the authored runbook command (operator-vouched)",
        revert="per the runbook entry -- a human authored this fix",
        envelope=envelope,
    )
    if not plan.command:  # an empty/blank command -- nothing to run
        return RemediationResult(
            plan=plan, applied=False, verified=False, detail="empty solution command."
        )
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list (no shell); operator-authored command
            plan.command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return RemediationResult(
            plan=plan, applied=False, verified=False, detail=f"solution failed: {exc}"
        )
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout or "").strip()[:200]
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"solution returned {proc.returncode}: {why}",
        )
    out = (proc.stdout or "").strip()[:200]
    return RemediationResult(
        plan=plan,
        applied=True,
        verified=False,
        detail=f"solution applied -- {out}" if out else "solution applied.",
    )


def solution_named(name: str, path: str = "") -> Solution | None:
    """Resolve a stored solution by its name (the bit before ' (author:' in ``drift_identity``), so
    ``apply_pending`` can recover the bound for the plan. None if the runbook no longer has it."""
    base = name.split(" (author:", 1)[0].strip()
    return next((s for s in load_solutions(path) if s.name == base), None)
