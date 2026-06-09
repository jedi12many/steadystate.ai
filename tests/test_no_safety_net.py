"""STEADYSTATE_NO_SAFETY_NET -- the operator's risk dial (issue #253 phase 4). Off by default, the
#253 solution gates hold: a DRAFT isn't offered, and an open command never auto-applies on its self-
declared bound. On, the operator lifts both -- a draft is offerable and an open command is auto-
eligible (still within the bound) -- and every action it permits is audited `[no-safety-net]`.
Surfaced in `posture` so the lifted net is never silent."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.act.solution_remedy import record_solution_remediations
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.probe.solutions import load_solutions
from steadystate.reason.alert import Severity
from steadystate.state import StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
# a VOUCHED open command (no `proposed` key -> vouched); low/high -> within the autonomous bound
_VOUCHED = {
    "name": "ok-fix",
    "for": "Evicted",
    "solution": {"kind": "command", "run": "python -c \"print('ok')\""},
    "impact": "low",
    "reversibility": "high",
    "author": "ops",
}
_DRAFT = {**_VOUCHED, "name": "draft-fix", "proposed": True}


def _sym(category: str, title: str) -> Symptom:
    return Symptom(
        identity=f"default/{title}",
        kind="Pod",
        category=category,
        severity=Severity.MEDIUM,
        title=title,
        detail="d",
        provenance=Provenance(source="k8s"),
        evidence={},
    )


class _Alert:
    def __init__(self, *symptoms: Symptom) -> None:
        self.symptoms = list(symptoms)


class _Report:
    def __init__(self, *alerts: _Alert) -> None:
        self.alerts = list(alerts)


def _record(tmp_path, entries):
    """Run the runbook against an Evicted symptom; return (offered pendings, audit rows)."""
    path = tmp_path / "solutions.json"
    path.write_text(json.dumps(entries))
    report = _Report(_Alert(_sym("Evicted", "web Evicted")))
    with StateStore(":memory:") as store:
        record_solution_remediations(store, report, _NOW, solutions=load_solutions(str(path)))
        pending = [p.drift_identity for p in store.all_pending()]
        audit = [(a.actor, a.detail) for a in store.audit_log()]
    return pending, audit


def test_off_by_default_a_draft_is_not_offered(monkeypatch, tmp_path):
    monkeypatch.delenv("STEADYSTATE_NO_SAFETY_NET", raising=False)
    monkeypatch.delenv("STEADYSTATE_SOLUTION_AUTO", raising=False)
    pending, audit = _record(tmp_path, [_DRAFT])
    assert pending == [] and audit == []  # the #253 draft gate holds


def test_lifting_the_net_makes_a_draft_offerable(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_NO_SAFETY_NET", "1")
    monkeypatch.delenv("STEADYSTATE_SOLUTION_AUTO", raising=False)
    pending, audit = _record(tmp_path, [_DRAFT])
    assert pending == ["draft-fix (author: ops)"] and audit == []  # offered (auto is off)


def test_an_open_command_auto_runs_only_under_the_lifted_net_and_is_audited(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_SOLUTION_AUTO", "1")
    # net OFF: a vouched open command is NOT auto-eligible (arbitrary always escalates) -> offered
    monkeypatch.delenv("STEADYSTATE_NO_SAFETY_NET", raising=False)
    pending, audit = _record(tmp_path, [_VOUCHED])
    assert pending == ["ok-fix (author: ops)"] and audit == []
    # net ON: it auto-applies (the operator owns the risk), and the audit marks the override
    monkeypatch.setenv("STEADYSTATE_NO_SAFETY_NET", "1")
    pending, audit = _record(tmp_path, [_VOUCHED])
    assert pending == []  # auto-ran, not offered
    assert len(audit) == 1 and audit[0][0] == "auto" and "[no-safety-net]" in audit[0][1]


def test_posture_surfaces_the_lifted_net(monkeypatch):
    from steadystate.verbs import _render_posture

    monkeypatch.delenv("STEADYSTATE_NO_SAFETY_NET", raising=False)
    assert "safety net ON" in _render_posture()
    monkeypatch.setenv("STEADYSTATE_NO_SAFETY_NET", "1")
    assert "SAFETY NET OFF" in _render_posture()
