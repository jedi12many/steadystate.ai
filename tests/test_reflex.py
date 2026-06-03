"""Reflexes + the hold control loop: the homeostat layer. These pin the part that makes acting
autonomously *safe* -- it acts only on a known stimulus whose reflex is at `auto` AND within
blast-radius, and ESCALATES (never executes) anything novel or out of envelope (an abnormal pod
count, a fleet-wide storm). Plus: a reflex ships dormant (propose), a dry hold touches nothing,
and an applied hold goes through the exact approve guardrail + audit."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.act.cleanup import record_cleanups
from steadystate.act.reflex import (
    ACT,
    AUTO,
    ESCALATE,
    PROPOSE,
    WATCH,
    Reflex,
    plan_hold,
    reflexes,
    run_hold,
)
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report

_NOW = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)


def _fix(namespace: str) -> str:
    return f"kubectl delete pods -n {namespace} --field-selector=status.phase=Failed"


def _evicted(namespace: str, *, pods: int = 3, category: str = "Evicted") -> Symptom:
    return Symptom(
        identity=f"apps/Deployment/{namespace}/web",
        kind="Deployment",
        category=category,
        severity=Severity.MEDIUM,
        title=f"web is {category} in {namespace}",
        detail=f"{pods} pods",
        provenance=Provenance(source="kubernetes", address=namespace),
        evidence={"unhealthy_pods": str(pods)},
        recommended_action=_fix(namespace),
    )


def _report(*symptoms: Symptom) -> Report:
    alerts = [
        Alert(
            title=s.title,
            severity=s.severity,
            drifts=[],
            why_it_matters="x",
            layer=Layer.ALERT,
            symptoms=[s],
            recommended_action=s.recommended_action,
        )
        for s in symptoms
    ]
    return Report(items=alerts)


def _reflex(autonomy: str = AUTO, **kw) -> tuple[Reflex, ...]:
    base = dict(
        name="reclaim-evicted",
        category="Evicted",
        autonomy=autonomy,
        max_per_action=50,
        max_per_tick=10,
        description="x",
    )
    base.update(kw)
    return (Reflex(**base),)


# -- the plan (pure judgement) --------------------------------------------------


def test_a_propose_reflex_only_watches_it_never_acts():
    plan = plan_hold(_report(_evicted("prod")), _reflex(PROPOSE))
    [decision] = plan.decisions
    assert decision.decision == WATCH and decision.reflex == "reclaim-evicted"
    assert not plan.to_act


def test_an_auto_reflex_within_blast_radius_acts():
    plan = plan_hold(_report(_evicted("prod", pods=3)), _reflex(AUTO))
    [decision] = plan.decisions
    assert decision.decision == ACT and decision.command == _fix("prod")


def test_an_oversized_finding_escalates_instead_of_acting():
    # 80 evicted pods in one namespace exceeds the per-action blast-radius (50) -> a human looks.
    plan = plan_hold(_report(_evicted("prod", pods=80)), _reflex(AUTO, max_per_action=50))
    [decision] = plan.decisions
    assert decision.decision == ESCALATE and "blast-radius" in decision.reason
    assert not plan.to_act


def test_a_fleetwide_storm_escalates_the_whole_batch():
    # The same finding in 4 namespaces with a per-tick budget of 3 looks systemic -> escalate all,
    # autonomously delete nothing (a node/capacity problem, not a routine cleanup).
    storm = _report(*[_evicted(ns, pods=2) for ns in ("a", "b", "c", "d")])
    plan = plan_hold(storm, _reflex(AUTO, max_per_tick=3))
    assert len(plan.escalated) == 4 and not plan.to_act
    assert all("systemic" in d.reason for d in plan.escalated)


def test_an_actionable_finding_with_no_reflex_escalates():
    # A safe cleanup command but a category no reflex answers -> the unknown goes to a human.
    orphan = _evicted("prod", category="Failed")  # safe command shape, but category != Evicted
    plan = plan_hold(_report(orphan), _reflex(AUTO))  # reflex is for Evicted only
    [decision] = plan.decisions
    assert decision.decision == ESCALATE and decision.reflex is None


def test_a_symptom_with_no_safe_action_is_not_actionable():
    crash = Symptom(
        identity="apps/Deployment/prod/api",
        kind="Deployment",
        category="CrashLoopBackOff",
        severity=Severity.HIGH,
        title="api crashlooping",
        detail="x",
        provenance=Provenance(source="kubernetes", address="api"),
        recommended_action=None,  # no one-shot fix -> hold never considers it
    )
    assert plan_hold(_report(crash), _reflex(AUTO)).decisions == ()


# -- the env autonomy overlay (the graduation knob) -----------------------------


def test_reflexes_ship_dormant_at_propose(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_REFLEX_AUTO", raising=False)
    assert all(r.autonomy == PROPOSE for r in reflexes())


def test_reflex_auto_env_promotes_a_named_reflex(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_REFLEX_AUTO", "reclaim-evicted")
    assert reflexes()[0].autonomy == AUTO


# -- run_hold (the side-effecting tick) -----------------------------------------


def test_a_dry_hold_touches_nothing_even_with_an_acting_reflex(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_REFLEX_AUTO", "reclaim-evicted")
    from steadystate.state import StateStore

    store = StateStore()
    report = _report(_evicted("prod"))
    record_cleanups(store, report, _NOW)
    with mock.patch("steadystate.act.cleanup.subprocess.run") as run:
        outcome = run_hold(store, report, apply=False, now=_NOW)
    run.assert_not_called()  # apply=False -> never executes
    assert outcome.plan.to_act and outcome.applied == () and outcome.held == 0


def test_an_applied_hold_reclaims_through_the_approve_guardrail_and_audits(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_REFLEX_AUTO", "reclaim-evicted")
    from steadystate.state import StateStore

    store = StateStore()
    report = _report(_evicted("prod"))
    record_cleanups(store, report, _NOW)  # the pending the hold will approve
    proc = mock.Mock(returncode=0, stdout="deleted", stderr="")
    with mock.patch("steadystate.act.cleanup.subprocess.run", return_value=proc) as run:
        outcome = run_hold(store, report, apply=True, now=_NOW)
    run.assert_called_once()
    assert outcome.held == 1
    # audited under the autonomous actor "hold", not a human -- the accountability trail.
    [entry] = store.audit_log(limit=5)
    assert entry.actor == "hold" and entry.outcome == "verified"


def test_an_escalated_finding_is_never_executed_by_a_hold(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_REFLEX_AUTO", "reclaim-evicted")
    from steadystate.state import StateStore

    store = StateStore()
    report = _report(_evicted("prod", pods=999))  # way over blast-radius -> escalate
    record_cleanups(store, report, _NOW)
    with mock.patch("steadystate.act.cleanup.subprocess.run") as run:
        outcome = run_hold(store, report, apply=True, now=_NOW)
    run.assert_not_called()  # even with --apply, an out-of-envelope finding is left for a human
    assert outcome.plan.escalated and outcome.held == 0
