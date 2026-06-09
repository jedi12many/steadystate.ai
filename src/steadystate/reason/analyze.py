"""Grounded root-cause analysis -- turn a captured crash/panic finding into the vendor/support-ready
RCA a senior engineer would write, ANCHORED to the evidence steadystate captured.

The differentiator isn't the model -- anyone can paste a log into a chatbot. It's that the analysis
is grounded in evidence the tool captured (the stack trace, the restart status, the log retention)
and told, explicitly, to cite it and **never invent** a frame, a file, or a cause it can't see.
steadystate's job is to capture the right evidence and frame the question; the model reasons over
*that*, and says plainly what the evidence doesn't show. That's what makes the answer checkable.
"""

from __future__ import annotations

from collections.abc import Callable

from ..evidence import EvidenceKeys
from ..state import Finding

# The RCA prompt. It asks for the exact shape a senior on-call writes (and a vendor's support team
# needs), and -- the whole point -- it FORBIDS going beyond the captured evidence.
_RCA_SYSTEM = (
    "You are a senior SRE writing a root-cause analysis of a production incident, for an engineer "
    "and -- if it turns out to be a vendor's bug -- their support team. Use ONLY the captured "
    "evidence below. Do NOT invent a frame, a file, a line number, or a cause that isn't in it.\n\n"
    "Produce a tight RCA with these sections (include one only if the evidence supports it; if it "
    "doesn't, write 'not in the captured evidence'):\n"
    "  Root cause -- one line.\n"
    "  What was being done -- the operation in flight, if the evidence shows it.\n"
    "  Call chain -- if a stack trace is present, the frames leading to the failure, in order "
    "(function + file:line each), and point out the exact frame where it broke.\n"
    "  Smoking gun -- the single most telling line, quoted verbatim, and what it proves.\n"
    "  Trigger -- what set it off.\n"
    "  Operational facts -- did the pod restart? are pre-incident logs retained? which "
    "workload/namespace?\n\n"
    "Be precise + grounded: quote the evidence line you're citing. Never speculate beyond it -- a "
    "checkable, honest RCA beats a confident guess."
)


def _evidence_bundle(finding: Finding) -> str:
    """The captured evidence as a labeled block for the model -- the finding's headline + every
    structured field, the stack trace last + verbatim (it's the meat the call chain needs)."""
    lines = [
        f"Finding: {finding.last_title}",
        f"Severity: {finding.last_severity}   Status: {finding.status}",
        f"First seen: {finding.first_seen}   Last seen: {finding.last_seen}",
    ]
    details = finding.details or {}
    trace = details.get(EvidenceKeys.TRACE)
    for key, value in details.items():
        if key != EvidenceKeys.TRACE:  # the trace is appended last, verbatim, under its own header
            lines.append(f"{key}: {value}")
    if trace:
        lines.append("\n--- captured log / stack trace ---\n" + str(trace))
    return "\n".join(lines)


def analyze_finding(
    finding: Finding, complete: Callable[[str, str, str], str | None]
) -> str | None:
    """The grounded RCA for one finding, via the LLM seam (``complete``); None when no model is
    configured. The prompt is built ONLY from the finding's captured evidence -- so the analysis is
    anchored to what steadystate actually saw, not the model's priors."""
    return complete(_RCA_SYSTEM, _evidence_bundle(finding), "analyze")
