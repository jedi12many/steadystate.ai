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

Acting on an authorized proposal is *granted*, not *earned*. A track record of right answers does
not retire the hallucination risk the guardrail exists for -- ten green runs leave the next call
exactly as fallible -- so we don't make the decider serve a probation to prove a risk away that it
can't. We grant access the way a team grants a new admin access: on day one, scoped to a role, with
mistakes priced in. Here the role is the **bound** + the catalog allow-list -- the guardrail that
keeps it *relatively* safe -- and the operator's disaster-recovery plan is the final backstop. So
``STEADYSTATE_DECIDER_AUTO`` is the grant (the same overlay knob that promotes a reflex to auto):
flip it on and ``propose --apply`` runs the within-bound proposals through the exact human-approve
guardrail, audited as ``decider``. Out-of-bound never auto-runs -- it still escalates to a human.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..probe.base import Symptom
from ..state import PendingAction, StateStore
from .base import RemediationResult
from .bounds import BoundPolicy, Envelope, bound_from_env, within_bounds
from .catalog import ACTIONS, catalog_action, catalog_menu
from .execute import CATALOG_SOURCE

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


def gate_proposal(proposal: ProposedAction, policy: BoundPolicy | None = None) -> GatedProposal:
    """The deterministic gate every proposal passes through, blind to who proposed it. Rejects a
    proposal that names no catalog action or whose command fails that action's allow-pattern;
    escalates one whose (trusted, catalog) envelope is outside the bound; authorizes the rest.
    Pure -- the whole safety case for an LLM decider is that this function never sees the model.
    ``policy`` defaults to the active bound (``bound_from_env``), so the decider honors the same
    ``STEADYSTATE_BOUND`` dial the reflexes and break-glass do."""
    policy = bound_from_env() if policy is None else policy
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
    "Build the command's resource (`<kind>/<name>`) and `-n <namespace>` from the explicit "
    "**name** and **namespace** fields given below -- NOT by parsing the identity string. Use the "
    "action's stated command shape; argument order need not be exact, but it must be that one "
    "action targeting THAT resource. "
    'Reply with ONLY JSON: {"action": <menu name or null>, "command": <exact command string>, '
    '"rationale": <one sentence>}.'
)


def _resource_fields(symptom: Symptom) -> tuple[str, str]:
    """The workload's name + namespace, given to the model explicitly so it never has to parse them
    out of the slash-joined identity (where it once read the namespace as the name). name = the last
    identity segment; namespace = the stored evidence, else the second-to-last segment."""
    parts = symptom.identity.split("/")
    name = parts[-1] if parts else ""
    namespace = symptom.evidence.get("namespace") or (parts[-2] if len(parts) >= 2 else "")
    return name, namespace


def _user_prompt(symptom: Symptom, context: str = "") -> str:
    evidence = "\n".join(f"  {k}: {v}" for k, v in symptom.evidence.items())
    grounding = f"How THIS fleet has handled this before:\n{context}\n\n" if context else ""
    name, namespace = _resource_fields(symptom)
    return (
        f"Finding: {symptom.title}\n"
        f"category: {symptom.category}\nidentity: {symptom.identity}\n"
        f"kind: {symptom.kind}\nname: {name}\nnamespace: {namespace}\n"
        f"evidence:\n{evidence}\n\n"
        f"{grounding}"
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

    def __init__(
        self,
        complete: Callable[[str, str, str], str | None],
        context_for: Callable[[Symptom], str] | None = None,
    ) -> None:
        self._complete = complete
        # Optional grounding: a function that returns "how this fleet has handled this category
        # before" for a finding, folded into the prompt -- so the model reasons from YOUR
        # operational history, not generic k8s. None = no grounding (prompt is catalog + finding).
        self._context_for = context_for

    def propose(self, symptom: Symptom) -> ProposedAction | None:
        from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

        context = self._context_for(symptom) if self._context_for is not None else ""
        text = self._complete(_SYSTEM, _user_prompt(symptom, context), "decide")
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


def propose_for(report, decider: Decider, policy: BoundPolicy | None = None) -> list[GatedProposal]:
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


def environment_context(findings: list, acted: set[str], category: str) -> str:
    """A compact 'how THIS fleet has handled <category> before', for grounding the LLM decider in
    your operational history instead of generic k8s knowledge -- the difference between a smart
    guess and an expert one. Built from the *learned lessons* (what resolved out-of-band, what
    self-heals) and the *recurrence* record (a category whose fixes didn't hold). '' when there's no
    history yet, so a cold store simply gives an un-grounded prompt. Pure given the store reads."""
    from .learn import learn
    from .reflex import reflex_for_category, reflex_recurrence

    lines = [
        f"- {lesson.recommendation}"
        for lesson in learn(findings, acted)
        if lesson.category == category
    ]
    reflex = reflex_for_category(category)
    if reflex is not None:
        recurred = reflex_recurrence(findings, acted).get(reflex.name, 0)
        if recurred:
            lines.append(
                f"- caution: {recurred} past '{reflex.name}' fix(es) recurred (didn't hold)"
            )
    return "\n".join(lines)


def record_proposals(
    store: StateStore, gated: list[GatedProposal], now: datetime
) -> tuple[list[GatedProposal], list[GatedProposal], list[GatedProposal]]:
    """Wire the read-only decider into the act loop at the safest rung -- "propose to pending". For
    each gated proposal: AUTHORIZED (within bound) -> record an approvable pending the operator
    confirms with `approve`/`fix` (the LLM drives *what*, the human stays the trigger); ESCALATE
    (out of bound) -> *advisory only*, never auto-recorded (a human initiates break-glass);
    REJECTED -> dropped. Returns ``(recorded, advised, dropped)`` -- the caller surfaces the
    proposer at record time, and the audit records the human who approves (decision = APPROVED)."""
    recorded: list[GatedProposal] = []
    advised: list[GatedProposal] = []
    dropped: list[GatedProposal] = []
    for g in gated:
        if g.verdict == AUTHORIZED:
            store.record_pending(
                PendingAction(
                    fingerprint=g.proposal.fingerprint,
                    source=CATALOG_SOURCE,
                    path="",
                    drift_identity=g.proposal.identity,
                    command=g.proposal.command,
                ),
                now,
            )
            recorded.append(g)
        elif g.verdict == ESCALATE:
            advised.append(g)
        else:
            dropped.append(g)
    return recorded, advised, dropped


def decider_auto_enabled() -> bool:
    """Whether the operator has GRANTED the decider standing permission to act on its own within the
    bound. The access grant, set once via ``STEADYSTATE_DECIDER_AUTO`` -- the same env-overlay knob
    that promotes a reflex (``STEADYSTATE_REFLEX_AUTO``). This is deliberately NOT an earned trust
    score: a track record doesn't retire the hallucination risk the guardrail exists for, so we
    grant access like a team grants a new admin's -- on day one, scoped to a role. The role here is
    the bound + the catalog allow-list (the guardrail), with the operator's DR plan the backstop.
    Out-of-bound actions never auto-run regardless of this grant. Pure but for the env read; any
    truthy value but the usual falsey words enables it (default OFF: the decider proposes only)."""
    raw = os.environ.get("STEADYSTATE_DECIDER_AUTO", "").strip().lower()
    return raw not in ("", "0", "false", "no", "off")


def act_on_proposals(
    store: StateStore, gated: list[GatedProposal], now: datetime, *, actor: str = "decider"
) -> tuple[
    list[tuple[GatedProposal, RemediationResult | None]],
    list[GatedProposal],
    list[GatedProposal],
]:
    """Auto-act on the within-bound proposals -- the decider as a bounded operator, no trigger.
    For each AUTHORIZED proposal: record the pending and immediately run it through the same approve
    guardrail a human ``approve`` uses (claim-once + re-validate against the catalog allow-pattern +
    within-bound re-check + audit), recorded under ``actor`` ("decider") so the trail tells an
    autonomous fix from a human one. ESCALATE (out of bound) is never auto-run -- it stays advisory
    for a human (break-glass). REJECTED is dropped. Returns ``(acted, advised, dropped)`` where each
    ``acted`` entry pairs the proposal with its RemediationResult (None if nothing ran).

    The guardrail is unchanged and supreme: the bound still gates every action (an out-of-bound one
    can't reach here, and the executor re-checks the bound at run time), and a stored/tampered
    command that no longer matches a vetted catalog shape is refused. Autonomy only moves a
    within-bound fix from 'a human triggers it' to 'it runs' -- never one inch past the bound."""
    from .approve import apply_pending

    acted: list[tuple[GatedProposal, RemediationResult | None]] = []
    advised: list[GatedProposal] = []
    dropped: list[GatedProposal] = []
    for g in gated:
        if g.verdict == AUTHORIZED:
            store.record_pending(
                PendingAction(
                    fingerprint=g.proposal.fingerprint,
                    source=CATALOG_SOURCE,
                    path="",
                    drift_identity=g.proposal.identity,
                    command=g.proposal.command,
                ),
                now,
            )
            _, result = apply_pending(store, g.proposal.fingerprint, actor, now)
            acted.append((g, result))
        elif g.verdict == ESCALATE:
            advised.append(g)
        else:
            dropped.append(g)
    return acted, advised, dropped
