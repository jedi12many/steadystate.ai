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

import os
import re
import shlex
import subprocess  # noqa: S404 -- argv list (no shell); the operator authored + vouched for the command
from datetime import datetime

from ..probe.solutions import Solution, load_solutions, solutions_for
from ..state import APPLIED, APPROVED, FAILED, VERIFIED, AuditEntry, PendingAction, StateStore
from .base import RemediationResult
from .bounds import BoundPolicy, Envelope, Impact, Reversibility, bound_from_env, within_bounds
from .plan import RemediationPlan, Risk

# The sentinel ``source`` marking a PendingAction as an authored-solution command (apply_pending
# routes on it). Not a real DriftSource -- the stored command is the whole action.
SOLUTION_SOURCE = "solution"

# The opt-in to AUTO-APPLY matched solutions (off by default). Even on, only a solution WITHIN THE
# BOUND auto-runs -- so a reboot / anything not low-impact-and-reversible always waits for a human.
# Distinct from the drift/decider autonomy on purpose: auto-running an authored command is its own
# explicit trust decision, never enabled as a side effect of turning on drift auto-apply.
_SOLUTION_AUTO_ENV = "STEADYSTATE_SOLUTION_AUTO"
_TRUTHY = frozenset({"1", "true", "yes", "on"})

# Open-content kinds: the `run` is an arbitrary operator-authored command with NO allow-pattern. A
# solution's declared impact/reversibility is the AUTHOR's word, not a trusted envelope -- so these
# can never auto-apply on that word alone. They ALWAYS escalate to a human approve, no matter the
# bound they claim. (A safe auto path returns once a solution is vouched through a trusted channel
# -- committed to main, or SSO-vouched in chat -- see issue #253; the self-declared envelope never
# widens its own blast radius.)
_ARBITRARY_KINDS = frozenset({"command", "playbook"})

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


def _solution_auto_enabled() -> bool:
    return (os.environ.get(_SOLUTION_AUTO_ENV) or "").strip().lower() in _TRUTHY


def _auto_eligible(sol: Solution, policy: BoundPolicy) -> bool:
    """Whether a matched solution may run UNATTENDED. An open-content kind (`command`/`playbook`)
    ALWAYS escalates -- its `run` has no allow-pattern and its declared bound is the author's word,
    so the self-declared envelope can never grant auto-apply. Any other kind is gated on the bound
    as before. The HIGH-severity cap from the June 2026 audit (issue #253)."""
    if sol.kind in _ARBITRARY_KINDS:
        return False
    return within_bounds(_envelope(sol), policy)


def record_solution_remediations(
    store: StateStore,
    report,
    now: datetime,
    *,
    solutions: list[Solution] | None = None,
    auto: bool | None = None,
) -> int:
    """For every malfunction (Symptom) matching an authored solution with a runnable command, OFFER
    it as a PendingAction (keyed by the symptom's fingerprint) so `pending` lists it and `approve
    <fp>` runs it. The author rides in ``drift_identity`` -> the audit. A solution with no `run`, or
    whose placeholders don't fill, is skipped (surfaced in `show`, not offered).

    With ``auto`` (default: ``STEADYSTATE_SOLUTION_AUTO``) AND the solution AUTO-ELIGIBLE
    (`_auto_eligible`), it's RUN immediately and audited as ``auto`` instead of offered -- once per
    fingerprint (already-acted ones are left, so a persisting symptom never loops). But an
    open-content `command`/`playbook` is NEVER auto-eligible on its self-declared bound -- it always
    escalates to a human (the audit's HIGH cap, issue #253); everything else falls through to the
    pending offer. Returns the count offered-or-auto-applied."""
    sols = solutions if solutions is not None else load_solutions()
    if not sols:
        return 0
    auto = _solution_auto_enabled() if auto is None else auto
    policy = bound_from_env()
    already = store.acted_fingerprints() if auto else set()
    recorded = 0
    for alert in report.alerts:
        for symptom in alert.symptoms:
            matches = solutions_for(symptom.category, symptom.title, sols)
            runnable = next((s for s in matches if s.run), None)
            if runnable is None:
                continue
            command = _fill(runnable.run, symptom.evidence)
            if _PLACEHOLDER.search(command):  # an unfilled {placeholder} -> skip a broken command
                continue
            action = PendingAction(
                fingerprint=symptom.fingerprint,
                source=SOLUTION_SOURCE,
                path="",
                drift_identity=f"{runnable.name} (author: {runnable.author})",
                command=command,
            )
            if auto and symptom.fingerprint not in already and _auto_eligible(runnable, policy):
                _auto_apply(store, action, runnable, now)
            else:
                store.record_pending(action, now)
            recorded += 1
    return recorded


def _auto_apply(store: StateStore, action: PendingAction, sol: Solution, now: datetime) -> None:
    """Run a within-bound matched solution unattended and audit it as ``auto`` -- the autonomy path,
    reached only with the opt-in on AND the bound satisfied. Best-effort: a failure is audited, not
    raised (a wedged command never sinks the scan)."""
    result = run_solution(action, sol)
    outcome = VERIFIED if result.verified else APPLIED if result.applied else FAILED
    store.record_audit(
        AuditEntry(
            fingerprint=action.fingerprint,
            source=SOLUTION_SOURCE,
            drift_identity=action.drift_identity,
            actor="auto",
            decision=APPROVED,
            outcome=outcome,
            detail=result.detail,
        ),
        now,
    )


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
