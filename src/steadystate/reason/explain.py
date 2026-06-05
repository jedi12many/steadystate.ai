"""Explain a finding, or the current state, in plain language -- the LLM's grounded read at the CLI.

The chat ask-mode already answers free-form questions from live state; this is the same value
without opening a chat session: ``steadystate explain <fp>`` narrates one finding, ``explain`` (no
argument) synthesises the whole current picture. It reasons over ONLY the stored facts -- the
finding's captured evidence (the ``show`` fields: namespace, the failing pod's last log, ...) or a
snapshot of what's open + pending -- so it can't invent risk the data doesn't support. Rides the
analyst's ``_complete`` seam (provider selection, kill switch, honest degrade, cost accounting under
its own ``explain`` caller); with no model configured, the caller falls back to the raw facts.
"""

from __future__ import annotations

from collections.abc import Callable

from ..state import Finding

# `complete(system, user, caller) -> str | None` -- the analyst seam this module reasons through.
Complete = Callable[[str, str, str], str | None]

_FINDING_SYSTEM = (
    "You are steadystate's analyst. Explain ONE infrastructure finding to an operator in 2-4 plain "
    "sentences: what it is, why it matters, and one concrete next step. Use ONLY the facts given; "
    "never invent a cause or a detail the data doesn't support; be honest about uncertainty. "
    "Recommend the infrastructure fix only; do not speculate about what steadystate itself will or "
    "won't do."
)

_STATE_SYSTEM = (
    "You are steadystate's analyst. Summarise the cluster's current health for an operator in 2-5 "
    "plain sentences: the most important open problems, anything awaiting their approval, and what "
    "to look at first. Use ONLY the state given -- never invent; if it's empty, say things look "
    "clear. Be concise and concrete."
)


def finding_facts(finding: Finding) -> str:
    """A finding flattened to a plain-text fact block for the model -- identity, lifecycle, and the
    captured evidence (the ``show`` fields). No invention: exactly what's stored."""
    lines = [
        f"fingerprint: {finding.fingerprint}",
        f"severity: {finding.last_severity}",
        f"title: {finding.last_title}",
        f"status: {finding.status}",
        f"first seen: {finding.first_seen}",
        f"last seen: {finding.last_seen}",
    ]
    if finding.details:
        lines.append("evidence:")
        lines += [f"  {key}: {value}" for key, value in finding.details.items()]
    return "\n".join(lines)


def explain_finding(finding: Finding, complete: Complete) -> str | None:
    """The model's grounded narrative for one finding, or None if the model is unavailable (the
    caller then shows the raw facts). Records spend under the ``explain`` caller."""
    return complete(_FINDING_SYSTEM, finding_facts(finding), "explain")


def explain_state(snapshot: str, complete: Complete) -> str | None:
    """The model's synthesis of the current state (a ``state_snapshot``), or None if unavailable.
    Records spend under the ``explain`` caller."""
    grounding = snapshot.strip() or "No open findings or pending remediations."
    return complete(_STATE_SYSTEM, f"Current state:\n{grounding}", "explain")
