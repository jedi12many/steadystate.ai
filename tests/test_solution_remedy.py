"""Authored solutions as guardrailed remediations: a matched, runnable solution is offered as a
PendingAction, `approve` runs it (no shell) and audits it with BOTH the author (who vouched) and the
approver (who ran). Reboot-only / unfilled solutions are not offered. The gate is approval + audit;
the open body means no content allow-pattern -- so the tests pin the flow and the accountability."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.act.approve import apply_pending
from steadystate.act.solution_remedy import (
    SOLUTION_SOURCE,
    record_solution_remediations,
    run_solution,
    solution_named,
)
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Severity
from steadystate.state import PendingAction, StateStore


def _sym(category: str, title: str, evidence: dict | None = None) -> Symptom:
    return Symptom(
        identity=f"default/{title}",
        kind="Pod",
        category=category,
        severity=Severity.MEDIUM,
        title=title,
        detail="d",
        provenance=Provenance(source="k8s"),
        evidence=evidence or {},
    )


class _Alert:
    def __init__(self, *symptoms: Symptom) -> None:
        self.symptoms = list(symptoms)


class _Report:
    def __init__(self, *alerts: _Alert) -> None:
        self.alerts = list(alerts)


def _runbook(tmp_path, entries) -> str:
    path = tmp_path / "solutions.json"
    path.write_text(json.dumps(entries))
    return str(path)


_EVICTED = {
    "name": "reclaim-evicted",
    "for": "Evicted",
    "solution": {"kind": "command", "run": "python -c \"print('ok')\""},
    "impact": "low",
    "reversibility": "high",
    "author": "jeff",
}


def test_offers_a_runnable_match_and_skips_reboot_only(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "STEADYSTATE_SOLUTIONS",
        _runbook(
            tmp_path,
            [
                _EVICTED,
                {  # no `run` -> a manual reboot instruction, surfaced in show, never offered here
                    "name": "reboot-gw",
                    "for": "Hung",
                    "solution": {"kind": "reboot", "target": "gw"},
                    "author": "jeff",
                },
            ],
        ),
    )
    report = _Report(_Alert(_sym("Evicted", "web Evicted")), _Alert(_sym("Hung", "gw hung")))
    with StateStore(":memory:") as store:
        n = record_solution_remediations(store, report, datetime.now(UTC))
        pending = store.all_pending()
    assert n == 1  # only the runnable Evicted match
    assert pending[0].source == SOLUTION_SOURCE
    assert pending[0].drift_identity == "reclaim-evicted (author: jeff)"  # author carried for audit


def test_placeholders_fill_from_evidence_and_an_unfilled_one_is_not_offered(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "STEADYSTATE_SOLUTIONS",
        _runbook(
            tmp_path,
            [
                {
                    "name": "scoped",
                    "for": "Evicted",
                    "solution": {"kind": "command", "run": "kubectl delete pod -n {namespace}"},
                    "author": "jeff",
                }
            ],
        ),
    )
    filled = _Alert(_sym("Evicted", "web Evicted", {"namespace": "prod"}))
    unfilled = _Alert(_sym("Evicted", "api Evicted", {}))  # no namespace -> {namespace} can't fill
    with StateStore(":memory:") as store:
        record_solution_remediations(store, _Report(filled, unfilled), datetime.now(UTC))
        pending = store.all_pending()
    assert len(pending) == 1 and pending[0].command == "kubectl delete pod -n prod"


def test_approve_runs_the_command_and_audits_author_and_approver(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", _runbook(tmp_path, [_EVICTED]))
    sym = _sym("Evicted", "web Evicted")
    now = datetime.now(UTC)
    with StateStore(":memory:") as store:
        record_solution_remediations(store, _Report(_Alert(sym)), now)
        msg, result = apply_pending(store, sym.fingerprint, actor="dana", now=now)
        audit = store.audit_log()
    assert result is not None and result.applied and "ok" in msg
    entry = audit[-1]
    assert entry.actor == "dana" and entry.outcome == "applied"  # who approved
    assert entry.drift_identity == "reclaim-evicted (author: jeff)"  # who authored, in the trail


def test_run_solution_reports_a_nonzero_command_without_raising():
    action = PendingAction(
        fingerprint="f" * 64,
        source=SOLUTION_SOURCE,
        path="",
        drift_identity="boom (author: jeff)",
        command='python -c "import sys; sys.exit(3)"',
    )
    result = run_solution(action)
    assert not result.applied and "returned 3" in result.detail  # failure surfaced, not raised


def test_run_solution_reports_a_missing_binary_without_raising():
    action = PendingAction(
        fingerprint="f" * 64,
        source=SOLUTION_SOURCE,
        path="",
        drift_identity="x (author: jeff)",
        command="definitely-not-a-real-binary-xyz --do-it",
    )
    result = run_solution(action)
    assert not result.applied and "failed" in result.detail


def test_solution_named_resolves_the_bound_for_the_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_SOLUTIONS", _runbook(tmp_path, [_EVICTED]))
    sol = solution_named("reclaim-evicted (author: jeff)")
    assert sol is not None and sol.impact == "low" and sol.reversibility == "high"
    assert solution_named("nonexistent (author: x)") is None
