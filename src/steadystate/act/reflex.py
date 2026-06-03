"""Reflexes: the control-loop layer that turns *detection* into *self-maintenance*.

A monitor detects and waits for a human -- and the only difference between a fleet that
recovers in seconds and one that smolders for an hour is whether the human who got paged knew
what to do. The failure catalog is finite and known; the variance is the responder. A homeostat
removes that variance: for a *known* malfunction it knows the response, applies it within a
blast-radius budget, and escalates to a human only the novel or out-of-envelope.

A ``Reflex`` binds a known stimulus (a Symptom category) to the autonomy it has *earned*. The
response itself is not re-invented here: it's the safe action the prober already composed
(``Symptom.recommended_action``), re-validated at run time on the SAME approve guardrail every
remediation uses (see act/approve.py + act/cleanup.py). So a reflex never widens what the tool
*can* do -- it only governs whether a human has to be in the loop for something already safe.

Slice 1 seeds ONE reflex we fully possess -- evicted-pod cleanup -- and ships it at ``propose``
(dry-run), so an operator watches it be right before promoting it to ``auto`` (via
``STEADYSTATE_REFLEX_AUTO``, no code change). The hard, defensible part isn't acting on the known;
it's *declining* to act when the situation leaves the envelope: a single finding with an abnormal
pod count, or a fleet-wide storm of the same finding, is escalated to a human, never autonomously
executed. Knowing when NOT to act is the whole reason this is safe enough to act at all.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from ..reason.report import Report
from ..state import StateStore
from .approve import apply_pending
from .base import RemediationResult
from .cleanup import is_safe_cleanup

# A reflex's earned autonomy, lowest to highest. ``observe`` is the dormant default a brand-new or
# distrusted reflex sits at; ``propose`` is the watch mode (show what it *would* do, touch nothing);
# ``auto`` is the only level that acts -- and only within blast-radius.
OBSERVE = "observe"
PROPOSE = "propose"
AUTO = "auto"

# A hold tick's verdict per actionable finding.
ACT = "act"  # an auto reflex, within blast-radius -> hold will execute it
WATCH = "watch"  # a reflex matches but isn't at auto -> dry-run, shown, never executed
ESCALATE = "escalate"  # over blast-radius, or no reflex -> left as pending for a human


@dataclass(frozen=True)
class Reflex:
    """A known stimulus bound to the autonomy it has earned. The response is the prober's own
    safe action; this only governs *who* applies it (the tool autonomously vs. a paged human) and
    *how much* it may touch before it must stop and escalate."""

    name: str
    category: str  # the Symptom category it answers (e.g. "Evicted")
    autonomy: str  # observe | propose | auto
    max_per_action: int  # escalate a single finding that would touch more resources than this
    max_per_tick: int  # escalate the whole batch when more than this many match at once (storm)
    description: str

    def matches(self, category: str) -> bool:
        return category == self.category


# The seed set. One reflex, for the one stimulus whose response we fully possess and have proven
# safe (the evicted-pod cleanup the kubectl prober composes + act/cleanup re-validates). It ships
# at PROPOSE on purpose: out of the box `hold` holds *nothing* -- you watch it, then promote it.
_BUILTIN_REFLEXES: tuple[Reflex, ...] = (
    Reflex(
        name="reclaim-evicted",
        category="Evicted",
        autonomy=PROPOSE,
        max_per_action=50,  # a namespace with >50 evicted tombstones is abnormal -> a human looks
        max_per_tick=10,  # >10 namespaces evicting at once is systemic (node/capacity) -> escalate
        description="reclaim Evicted (Failed-phase) pod tombstones via the prober's safe cleanup",
    ),
)


def reflexes() -> tuple[Reflex, ...]:
    """The active reflexes, with the autonomy overlay applied. ``STEADYSTATE_REFLEX_AUTO`` is a
    comma list of reflex names promoted to ``auto`` -- the graduation knob: an operator flips a
    reflex from watch (propose) to act (auto) AFTER watching it be right, with no code change. With
    the var unset, every reflex stays at its built-in level (all ``propose`` today), so the default
    posture is: hold holds nothing until you say so."""
    raw = os.environ.get("STEADYSTATE_REFLEX_AUTO", "")
    promoted = {n.strip() for n in raw.split(",") if n.strip()}
    return tuple(replace(r, autonomy=AUTO) if r.name in promoted else r for r in _BUILTIN_REFLEXES)


@dataclass(frozen=True)
class ReflexDecision:
    """What a hold tick decided for one actionable finding, and why -- the audit-friendly unit the
    plan is made of. ``reason`` carries the blast-radius / escalation rationale verbatim."""

    fingerprint: str
    identity: str
    category: str
    decision: str  # ACT | WATCH | ESCALATE
    reflex: str | None  # the matching reflex's name, or None when nothing matched
    reason: str
    command: str  # the safe action that would run (display)


@dataclass(frozen=True)
class HoldPlan:
    """A hold tick's full reckoning over the current findings: every actionable one classified
    into act / watch / escalate. Pure -- nothing here has touched the cluster yet."""

    decisions: tuple[ReflexDecision, ...] = ()

    @property
    def to_act(self) -> tuple[ReflexDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == ACT)

    @property
    def watched(self) -> tuple[ReflexDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == WATCH)

    @property
    def escalated(self) -> tuple[ReflexDecision, ...]:
        return tuple(d for d in self.decisions if d.decision == ESCALATE)


def plan_hold(report: Report, active: tuple[Reflex, ...]) -> HoldPlan:
    """Decide, per actionable finding, whether a reflex acts, watches, or escalates -- the control
    loop's whole judgement, with NO side effects (so it's exhaustively testable and a dry `hold`
    is just this).

    An *actionable* finding is a Symptom carrying a safe, re-validated remediation
    (``recommended_action`` that passes ``is_safe_cleanup`` -- the same gate approve enforces). For
    each: no matching reflex -> ESCALATE (a human owns the unknown); over the per-action
    blast-radius, or part of a storm past the per-tick budget -> ESCALATE (out of envelope);
    a matching ``auto`` reflex within budget -> ACT; anything else (observe/propose) -> WATCH."""
    by_category = {r.category: r for r in active}
    actionable = [
        s
        for alert in report.alerts
        for s in alert.symptoms
        if s.recommended_action and is_safe_cleanup(s.recommended_action)
    ]
    # Storm guard: how many findings each reflex is being asked to handle this single tick.
    matched_per_category = Counter(s.category for s in actionable if s.category in by_category)
    decisions: list[ReflexDecision] = []
    for symptom in actionable:
        reflex = by_category.get(symptom.category)
        command = symptom.recommended_action or ""
        base = {
            "fingerprint": symptom.fingerprint,
            "identity": symptom.identity,
            "category": symptom.category,
            "command": command,
        }
        if reflex is None:
            decisions.append(
                ReflexDecision(
                    **base, decision=ESCALATE, reflex=None, reason="no reflex for this category"
                )
            )
            continue
        size = _action_size(symptom.evidence)
        if size > reflex.max_per_action:
            reason = (
                f"{size} resources exceeds blast-radius {reflex.max_per_action} -- a human looks"
            )
            decisions.append(
                ReflexDecision(**base, decision=ESCALATE, reflex=reflex.name, reason=reason)
            )
        elif matched_per_category[symptom.category] > reflex.max_per_tick:
            seen = matched_per_category[symptom.category]
            reason = f"{seen} findings this tick exceeds {reflex.max_per_tick} -- looks systemic"
            decisions.append(
                ReflexDecision(**base, decision=ESCALATE, reflex=reflex.name, reason=reason)
            )
        elif reflex.autonomy == AUTO:
            decisions.append(
                ReflexDecision(
                    **base, decision=ACT, reflex=reflex.name, reason="within blast-radius"
                )
            )
        else:  # observe | propose -- a reflex that doesn't (yet) act: show it, touch nothing
            reason = (
                f"reflex '{reflex.name}' is {reflex.autonomy} (dry-run) -- promote to auto to act"
            )
            decisions.append(
                ReflexDecision(**base, decision=WATCH, reflex=reflex.name, reason=reason)
            )
    return HoldPlan(decisions=tuple(decisions))


def _action_size(evidence: dict[str, str]) -> int:
    """How many resources a finding's cleanup would plausibly touch, from its evidence -- the
    number the blast-radius budget is checked against. ``unhealthy_pods`` is what the kubectl
    prober records; 0 (don't escalate on size) when it's absent or unparseable."""
    raw = evidence.get("unhealthy_pods", "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


@dataclass(frozen=True)
class HoldOutcome:
    """The result of a hold tick: the plan it reckoned, plus what it actually applied (empty on a
    dry run). ``applied`` pairs each acted decision with the remediation result the audit got."""

    plan: HoldPlan
    applied: tuple[tuple[ReflexDecision, RemediationResult | None], ...] = ()
    did_apply: bool = False  # whether this tick was allowed to act at all (--apply)

    @property
    def held(self) -> int:
        """How many findings a reflex successfully held (applied + verified/applied)."""
        return sum(1 for _, result in self.applied if result is not None and result.applied)


def run_hold(
    store: StateStore,
    report: Report,
    *,
    apply: bool,
    actor: str = "hold",
    now: datetime | None = None,
) -> HoldOutcome:
    """Run one hold tick against ``report`` (the prober's current verdict) and the store. Builds
    the plan; when ``apply`` is set, executes the ACT decisions through the EXACT approve guardrail
    a human ``approve`` uses (claim-once + re-validate + run + audit), recorded under actor
    ``hold`` so the audit log distinguishes an autonomous hold from a human decision. WATCH and
    ESCALATE decisions are never executed -- the escalated ones stay pending for a human.

    The pending action ``apply_pending`` runs must already be recorded (the caller records cleanups
    from this same report first); a finding with no recorded pending is skipped, not invented."""
    now = now or datetime.now(UTC)
    plan = plan_hold(report, reflexes())
    applied: list[tuple[ReflexDecision, RemediationResult | None]] = []
    if apply:
        for decision in plan.to_act:
            if store.get_pending(decision.fingerprint) is None:
                continue  # nothing recorded to approve (e.g. already claimed) -- don't fabricate
            _, result = apply_pending(store, decision.fingerprint, actor, now)
            applied.append((decision, result))
    return HoldOutcome(plan=plan, applied=tuple(applied), did_apply=apply)
