"""The decider becomes a bounded operator -- rung 1: propose-to-pending, plus grounding. The LLM
drives WHAT (constrained to the catalog, gated by the bound); a human stays the trigger (approve);
and the model is grounded in how THIS fleet handled the category before. These pin: AUTHORIZED
proposals become approvable pendings, ESCALATE stays advisory, the recorded pending actually runs on
approve, and the grounding reaches the prompt."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest import mock

from steadystate.act.decide import (
    AUTHORIZED,
    ESCALATE,
    REJECTED,
    GatedProposal,
    LLMDecider,
    ProposedAction,
    environment_context,
    record_proposals,
)
from steadystate.act.execute import CATALOG_SOURCE
from steadystate.inbound.base import Command
from steadystate.inbound.server import run_command
from steadystate.state import RESOLVED, Finding, StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
_T0 = _NOW.isoformat()
_RESTART = "kubectl rollout restart deployment/web -n prod"


def _gated(verdict: str, *, action="rollout-restart-workload", command=_RESTART, proposer="llm"):
    p = ProposedAction(action, command, "apps/Deployment/prod/web", "a" * 64, "why", proposer)
    return GatedProposal(p, verdict, "reason", None)


# -- record_proposals: the propose -> pending wiring ------------------------------------------


def test_record_proposals_records_authorized_advises_escalate_drops_rejected():
    store = StateStore()
    gated = [
        _gated(AUTHORIZED),
        _gated(ESCALATE, action="delete-node", command="kubectl delete node n1"),
        _gated(REJECTED, action="bogus", command="kubectl rm -rf"),
    ]
    recorded, advised, dropped = record_proposals(store, gated, _NOW)
    assert len(recorded) == 1 and len(advised) == 1 and len(dropped) == 1
    [pending] = store.all_pending()  # only the AUTHORIZED one is recorded
    assert pending.source == CATALOG_SOURCE  # a normal approvable pending -- `approve <fp>` runs it
    assert pending.command == _RESTART


def test_a_recorded_proposal_is_approvable_and_audited():
    # the loop closes: the model populates `pending`, a human `approve`s, it runs + is audited.
    store = StateStore()
    record_proposals(store, [_gated(AUTHORIZED)], _NOW)
    proc = mock.Mock(returncode=0, stdout="deployment.apps/web restarted", stderr="")
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=proc) as run:
        from steadystate.act.approve import apply_pending

        message, result = apply_pending(store, "a" * 64, "amy", _NOW)
    run.assert_called_once()
    assert result is not None and result.applied and "restarted" in message
    [entry] = store.audit_log(limit=5)
    assert entry.actor == "amy"  # the human approver on the audit trail


# -- grounding: the model reasons from THIS fleet's history -----------------------------------


def _resolved(fp: str, category: str) -> Finding:
    return Finding(
        fp, _T0, _T0, "medium", f"web is {category}", RESOLVED, details={"category": category}
    )


def test_environment_context_grounds_from_learned_lessons():
    # two out-of-band resolutions of a category -> a lesson -> grounding text for that category.
    findings = [_resolved("a" * 64, "CrashLoopBackOff"), _resolved("b" * 64, "CrashLoopBackOff")]
    ctx = environment_context(findings, set(), "CrashLoopBackOff")
    assert ctx and "CrashLoopBackOff" in ctx  # the fleet's pattern for this category
    assert environment_context(findings, set(), "Erroring") == ""  # no history for another category


def test_llm_decider_folds_the_grounding_into_the_prompt():
    seen: dict = {}

    def complete(system, user, caller):
        seen["user"] = user
        return json.dumps(
            {"action": "rollout-restart-workload", "command": _RESTART, "rationale": "x"}
        )

    decider = LLMDecider(
        complete, context_for=lambda s: "- this category usually self-heals in ~4m"
    )
    from steadystate.model import Provenance
    from steadystate.probe.base import Symptom
    from steadystate.reason.alert import Severity

    sym = Symptom(
        identity="apps/Deployment/prod/web",
        kind="Deployment",
        category="CrashLoopBackOff",
        severity=Severity.HIGH,
        title="web crashlooping",
        detail="x",
        provenance=Provenance(source="kubernetes", address="web"),
    )
    decider.propose(sym)
    assert "How THIS fleet has handled this before" in seen["user"]
    assert "self-heals in ~4m" in seen["user"]


# -- end to end through the chat: propose records, pending shows it, approve runs it ----------


def test_chat_approve_runs_a_decider_recorded_pending(tmp_path):
    db = tmp_path / "s.db"
    fp = "a" * 64
    with StateStore(str(db)) as store:
        record_proposals(store, [_gated(AUTHORIZED)], _NOW)
    proc = mock.Mock(returncode=0, stdout="restarted", stderr="")
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=proc) as run:
        msg = run_command(Command(verb="approve", actor="amy", argument=fp), str(db))
    run.assert_called_once()
    assert "restarted" in msg
