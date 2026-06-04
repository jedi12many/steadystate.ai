"""The decider as a bounded operator -- autonomy is GRANTED, not earned. STEADYSTATE_DECIDER_AUTO
is the access grant (like promoting a reflex); with it set, ``act_on_proposals`` runs the
within-bound proposals through the exact human-approve guardrail, audited as ``decider``. These pin:
the grant reads the env, an AUTHORIZED proposal actually runs + is audited as the autonomous actor,
and an out-of-bound (ESCALATE) proposal never auto-runs no matter the grant."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest import mock

from steadystate.act.decide import (
    AUTHORIZED,
    ESCALATE,
    REJECTED,
    GatedProposal,
    ProposedAction,
    act_on_proposals,
    decider_auto_enabled,
)
from steadystate.state import APPROVED, StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
_RESTART = "kubectl rollout restart deployment/web -n prod"


def _gated(verdict: str, *, action="rollout-restart-workload", command=_RESTART, proposer="llm"):
    p = ProposedAction(action, command, "apps/Deployment/prod/web", "a" * 64, "why", proposer)
    return GatedProposal(p, verdict, "reason", None)


# -- the access grant -------------------------------------------------------------------------


def test_decider_auto_enabled_reads_the_grant(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_DECIDER_AUTO", raising=False)
    assert decider_auto_enabled() is False  # default OFF -- the decider only proposes
    monkeypatch.setenv("STEADYSTATE_DECIDER_AUTO", "off")
    assert decider_auto_enabled() is False  # an explicit falsey word is still off
    monkeypatch.setenv("STEADYSTATE_DECIDER_AUTO", "1")
    assert decider_auto_enabled() is True  # the operator granted access


# -- acting within the bound, audited as the autonomous actor ---------------------------------


def test_act_on_proposals_runs_authorized_advises_escalate_drops_rejected():
    # the within-bound one RUNS (no human trigger); the out-of-bound one never does, it's advisory.
    store = StateStore()
    gated = [
        _gated(AUTHORIZED),
        _gated(ESCALATE, action="delete-node", command="kubectl delete node n1"),
        _gated(REJECTED, action="bogus", command="kubectl rm -rf"),
    ]
    proc = mock.Mock(returncode=0, stdout="deployment.apps/web restarted", stderr="")
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=proc) as run:
        acted, advised, dropped = act_on_proposals(store, gated, _NOW)
    assert len(acted) == 1 and len(advised) == 1 and len(dropped) == 1
    run.assert_called_once()  # ONLY the authorized one ran -- the out-of-bound one never executed
    _, result = acted[0]
    assert result is not None and result.applied and "restarted" in result.detail


def test_an_auto_acted_fix_is_audited_as_the_decider():
    store = StateStore()
    proc = mock.Mock(returncode=0, stdout="deployment.apps/web restarted", stderr="")
    with mock.patch("steadystate.act.execute.subprocess.run", return_value=proc):
        act_on_proposals(store, [_gated(AUTHORIZED)], _NOW)
    [entry] = store.audit_log(limit=5)
    assert entry.actor == "decider"  # the autonomous actor on the accountability trail
    assert entry.decision == APPROVED  # ran through the same approve guardrail a human uses
