"""The decider seam: a proposer suggests a bounded action for a finding; the gate authorizes it.

This is where an LLM finally becomes a *decider* without becoming a *risk*. The trick is to split
two things the industry usually fuses:

  * WHO proposes -- a deterministic decider today, an LLM tomorrow. This is the creative, fallible
    part: "for this novel finding, the right move is *reclaim-evicted-pods* with this command."
  * WHETHER it's allowed -- entirely deterministic, and blind to who proposed. The action must be
    in the trusted catalog, its command must pass that catalog entry's validator, and the catalog's
    (never the proposer's) envelope must be within the human's bound.

So putting an LLM in the loop changes *nothing* about safety. It can only name vetted actions; the
gate re-validates the command and reads the trusted envelope; a hallucinated action, an
out-of-bounds one, or a malformed command is rejected, not run. The model decides *what to do*; the
bound -- a human's, set once -- decides *how much it is ever allowed to break*.

This module is read-only: a decider *proposes*, and the gate *authorizes or not*. Actually running
an authorized proposal is a later graduation -- exactly the propose->watch->auto path the reflexes
took -- so an LLM's first job is to be *right on paper*, watched, before it is ever trusted to act.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..probe.base import Symptom
from .bounds import DEFAULT_BOUND, BoundPolicy, Envelope, within_bounds
from .catalog import ACTIONS, catalog_action, catalog_menu

# A gated proposal's verdict.
AUTHORIZED = "authorized"  # in the catalog, command valid, envelope within the bound -> may act
REJECTED = "rejected"  # not a catalog action, or its command failed the allow-pattern -> discard
ESCALATE = "escalate"  # a real, valid action but its envelope is outside the bound -> a human


@dataclass(frozen=True)
class ProposedAction:
    """A decider's suggestion: a catalog action + the concrete command to run it. ``proposer`` is
    recorded for the audit trail and observability -- it is NEVER consulted for safety (the gate
    treats an LLM proposal exactly as a deterministic one)."""

    action: str  # the catalog action name
    command: str  # the concrete command
    identity: str  # the resource it concerns
    fingerprint: str  # the finding it answers
    rationale: str  # why the decider chose it (the model's reasoning, or a deterministic note)
    proposer: str  # "catalog" | "llm" -- observability only


@dataclass(frozen=True)
class GatedProposal:
    """A proposal run through the deterministic gate: the verdict, why, and the TRUSTED envelope
    (from the catalog, not the proposer) the verdict was based on."""

    proposal: ProposedAction
    verdict: str  # AUTHORIZED | REJECTED | ESCALATE
    reason: str
    envelope: Envelope | None  # the catalog envelope (None when the action isn't in the catalog)


def gate_proposal(proposal: ProposedAction, policy: BoundPolicy = DEFAULT_BOUND) -> GatedProposal:
    """The deterministic gate every proposal passes through, blind to who proposed it. Rejects a
    proposal that names no catalog action or whose command fails that action's allow-pattern;
    escalates one whose (trusted, catalog) envelope is outside the bound; authorizes the rest.
    Pure -- the whole safety case for an LLM decider is that this function never sees the model."""
    action = catalog_action(proposal.action)
    if action is None:  # a proposer can only choose from the vetted menu -- never invent an action
        return GatedProposal(
            proposal, REJECTED, f"'{proposal.action}' is not a catalog action", None
        )
    if not action.validate(proposal.command):  # re-validate the command shape (anti-injection)
        return GatedProposal(
            proposal, REJECTED, "command failed the action's allow-pattern", action.envelope
        )
    if not within_bounds(
        action.envelope, policy
    ):  # the bound reads the catalog envelope, not the proposer
        reason = f"envelope {action.envelope.label} is outside the bound -- a human approves"
        return GatedProposal(proposal, ESCALATE, reason, action.envelope)
    return GatedProposal(
        proposal, AUTHORIZED, f"within bound ({action.envelope.label})", action.envelope
    )


@runtime_checkable
class Decider(Protocol):
    """Proposes a bounded action for a finding, or None when it has no answer. The seam an LLM
    plugs into without touching the gate."""

    name: str

    def propose(self, symptom: Symptom) -> ProposedAction | None: ...


class CatalogDecider:
    """The deterministic baseline (and the no-LLM fallback): propose the catalog action whose
    validator accepts the symptom's prober-composed ``recommended_action``. No model -- so it's the
    testable reference the gate's safety is pinned against, and what runs when no model is set."""

    name = "catalog"

    def propose(self, symptom: Symptom) -> ProposedAction | None:
        command = symptom.recommended_action
        if not command:
            return None
        for action in ACTIONS.values():
            if action.validate(command):
                return ProposedAction(
                    action=action.name,
                    command=command,
                    identity=symptom.identity,
                    fingerprint=symptom.fingerprint,
                    rationale=f"command matches the vetted '{action.name}' action",
                    proposer="catalog",
                )
        return None


_SYSTEM = (
    "You are a Kubernetes SRE deciding the single safest remediation for one malfunctioning "
    "resource. You may ONLY choose from the vetted action menu you are given -- never invent an "
    "action or a command outside the stated shape. If no menu action fits, return action null. "
    'Reply with ONLY JSON: {"action": <menu name or null>, "command": <exact command string>, '
    '"rationale": <one sentence>}.'
)


def _user_prompt(symptom: Symptom) -> str:
    evidence = "\n".join(f"  {k}: {v}" for k, v in symptom.evidence.items())
    return (
        f"Finding: {symptom.title}\n"
        f"category: {symptom.category}\nidentity: {symptom.identity}\n"
        f"evidence:\n{evidence}\n\n"
        f"Vetted action menu:\n{catalog_menu()}\n\n"
        "Choose the one menu action that fixes this (or null), and the exact command."
    )


class LLMDecider:
    """An LLM proposer, constrained to the catalog. Given a finding, it asks the model to pick a
    menu action + the concrete command (or none). Whatever it returns goes through the SAME
    ``gate_proposal`` -- so a hallucinated action, an out-of-bounds one, or a malformed command is
    rejected, not run. It can only ever *name* a catalog action: a reply naming anything else is
    dropped here, before the gate even sees it. Degrades to None when no model is configured (the
    ``complete`` callable returns None), so the deterministic decider takes over -- never a crash.

    ``complete(system, user, caller) -> str | None`` is injected (an ``LLMAnalyst._complete`` in
    production, a stub in tests), so this carries no provider/egress logic of its own -- it rides
    the same egress gate, kill switch, honest-degrade, and cost accounting the analyst has."""

    name = "llm"

    def __init__(self, complete: Callable[[str, str, str], str | None]) -> None:
        self._complete = complete

    def propose(self, symptom: Symptom) -> ProposedAction | None:
        from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

        text = self._complete(_SYSTEM, _user_prompt(symptom), "decide")
        if not text:
            return None  # no model / egress declined / failure -> honest degrade
        data = _extract_json(text)
        if not data:
            return None
        action, command = data.get("action"), data.get("command")
        if not isinstance(action, str) or action not in ACTIONS:
            return None  # the model may ONLY name a vetted action; anything else is dropped here
        if not isinstance(command, str) or not command.strip():
            return None
        rationale = data.get("rationale")
        return ProposedAction(
            action=action,
            command=command.strip(),
            identity=symptom.identity,
            fingerprint=symptom.fingerprint,
            rationale=rationale if isinstance(rationale, str) else "(model gave no rationale)",
            proposer="llm",
        )


def propose_for(
    report, decider: Decider, policy: BoundPolicy = DEFAULT_BOUND
) -> list[GatedProposal]:
    """Run ``decider`` over every malfunction a report carries that hold has no reflex for, and gate
    each proposal -- the read-only 'what would an autonomous decider do here?' view. Pure given a
    pure decider; the CatalogDecider keeps it fully deterministic, an LLMDecider makes it advisory.
    Only findings WITHOUT a reflex are considered (those hold already handles, it handles)."""
    from .reflex import reflex_for_category

    gated: list[GatedProposal] = []
    for alert in report.alerts:
        for symptom in alert.symptoms:
            if reflex_for_category(symptom.category) is not None:
                continue  # hold owns this one -- the decider is for what hold can't answer
            proposal = decider.propose(symptom)
            if proposal is not None:
                gated.append(gate_proposal(proposal, policy))
    return gated
