"""The decider seam: an LLM (or a deterministic decider) proposes a bounded action; the gate
authorizes it. The whole safety case is here -- the gate is blind to WHO proposed, the envelope is
the catalog's not the proposer's, and a model can only ever name a vetted action with a re-validated
command. These pin exactly that: a hallucinated action, an un-vetted command, and an out-of-bounds
action are all stopped, and an LLM reply is constrained to the catalog before the gate sees it."""

from __future__ import annotations

import json

from steadystate.act.bounds import DEFAULT_BOUND, Impact, Reversibility
from steadystate.act.decide import (
    AUTHORIZED,
    ESCALATE,
    REJECTED,
    CatalogDecider,
    LLMDecider,
    ProposedAction,
    gate_proposal,
    propose_for,
)
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report

_FIX = "kubectl delete pods -n prod --field-selector=status.phase=Failed"


def _symptom(category: str = "Evicted", *, action: str | None = _FIX) -> Symptom:
    return Symptom(
        identity="apps/Deployment/prod/web",
        kind="Deployment",
        category=category,
        severity=Severity.MEDIUM,
        title=f"web is {category} in prod",
        detail="x",
        provenance=Provenance(source="kubernetes", address="web"),
        evidence={"namespace": "prod", "unhealthy_pods": "3"},
        recommended_action=action,
    )


def _proposal(action: str, command: str) -> ProposedAction:
    return ProposedAction(action, command, "apps/Deployment/prod/web", "f" * 64, "why", "test")


# -- the gate: the safety case (blind to who proposed) --------------------------


def test_gate_authorizes_a_vetted_action_within_bounds():
    gated = gate_proposal(_proposal("reclaim-evicted-pods", _FIX))
    assert gated.verdict == AUTHORIZED
    # the envelope it judged on came from the CATALOG, not the proposal.
    assert gated.envelope is not None and gated.envelope.reversibility == Reversibility.LOSSLESS


def test_gate_rejects_an_action_not_in_the_catalog():
    # a proposer (LLM or otherwise) inventing an action -> rejected, never run.
    gated = gate_proposal(_proposal("delete-the-database", "kubectl delete pvc data -n prod"))
    assert gated.verdict == REJECTED and "not a catalog action" in gated.reason


def test_gate_rejects_a_vetted_action_with_an_unvetted_command():
    # the right action name but an injected/malformed command -> the allow-pattern stops it.
    gated = gate_proposal(
        _proposal("reclaim-evicted-pods", "kubectl delete pods -n prod; rm -rf /")
    )
    assert gated.verdict == REJECTED and "allow-pattern" in gated.reason


def test_gate_escalates_when_the_catalog_envelope_is_outside_the_bound():
    # A policy that forbids even lossless/tenant -> the SAME vetted action now escalates. Proves the
    # bound (a human's, here tightened) governs, and the proposer can't talk its way past it.
    strict = {**DEFAULT_BOUND, Reversibility.LOSSLESS: Impact.SERVICE}
    gated = gate_proposal(_proposal("reclaim-evicted-pods", _FIX), strict)
    assert gated.verdict == ESCALATE and "outside the bound" in gated.reason


# -- the deterministic decider --------------------------------------------------


def test_catalog_decider_proposes_the_matching_vetted_action():
    proposal = CatalogDecider().propose(_symptom())
    assert proposal is not None and proposal.action == "reclaim-evicted-pods"
    assert proposal.proposer == "catalog"


def test_catalog_decider_proposes_nothing_without_a_safe_action():
    assert CatalogDecider().propose(_symptom(action=None)) is None
    assert CatalogDecider().propose(_symptom(action="kubectl delete pvc data")) is None


# -- the LLM decider: constrained to the catalog --------------------------------


def _stub(reply: str | None):
    def complete(system: str, user: str, caller: str) -> str | None:
        return reply

    return complete


def test_llm_decider_proposes_when_the_model_names_a_vetted_action():
    reply = json.dumps({"action": "reclaim-evicted-pods", "command": _FIX, "rationale": "evicted"})
    proposal = LLMDecider(_stub(reply)).propose(_symptom())
    assert proposal is not None and proposal.action == "reclaim-evicted-pods"
    assert proposal.proposer == "llm"
    # and it sails through the gate, judged on the catalog envelope.
    assert gate_proposal(proposal).verdict == AUTHORIZED


def test_llm_decider_drops_a_hallucinated_action_before_the_gate():
    # the model names something not on the menu -> dropped here, never reaches the gate.
    reply = json.dumps({"action": "nuke-everything", "command": "kubectl delete ns prod"})
    assert LLMDecider(_stub(reply)).propose(_symptom()) is None


def test_llm_decider_degrades_to_none_when_no_model_is_configured():
    # complete() returns None (no provider / egress declined / failure) -> honest degrade.
    assert LLMDecider(_stub(None)).propose(_symptom()) is None
    # ...and a non-JSON reply is dropped rather than trusted.
    assert LLMDecider(_stub("I think you should delete some pods")).propose(_symptom()) is None


# -- propose_for: only findings hold can't already handle ------------------------


def _report(*symptoms: Symptom) -> Report:
    return Report(
        items=[
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
    )


def test_propose_for_skips_findings_that_already_have_a_reflex():
    # Evicted HAS a reflex (hold owns it) -> the decider stays out of it.
    assert propose_for(_report(_symptom("Evicted")), CatalogDecider()) == []
