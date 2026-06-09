"""Root-cause analysis -- turn a captured crash/panic finding into the vendor/support-ready RCA a
senior engineer would write.

steadystate's job is to capture the RIGHT evidence -- above all the logs LEADING UP TO the failure
(the cause lives in the lead-up, not the panic line) -- and frame the question; the model is the
investigator that reasons over it. We don't out-code that reasoning; we feed it well and keep it
honest. So the prompt asks it to investigate -- trace the sequence, bring what it knows, connect the
dots -- while QUOTING the lines it relies on and labelling what's inference vs what the logs show.
The analysis stays checkable without being gagged into a transcript that misses the cause.
"""

from __future__ import annotations

from collections.abc import Callable

from ..evidence import EvidenceKeys
from ..state import Finding

# The RCA prompt. It asks for the exact shape a senior on-call writes (and a vendor's support team
# needs), and -- the whole point -- it FORBIDS going beyond the captured evidence.
_RCA_SYSTEM = (
    "You are a senior SRE INVESTIGATING a production incident -- writing the RCA an "
    "on-call engineer (and, if it's a vendor's bug, their support team) needs. You're "
    "given the captured logs LEADING UP TO the failure plus the error/stack block. Read the whole "
    "sequence and reason like an investigator: the cause is usually in what happened BEFORE the "
    "failure line, not the failure line itself -- trace the operations, the state, and the "
    "trigger. Bring what you know about this kind of system to connect the dots.\n\n"
    "Produce a tight RCA:\n"
    "  Root cause -- one line.\n"
    "  What was happening before it failed -- the lead-up, from the logs.\n"
    "  Call chain -- if a stack trace is present, the frames to the failure (function + file:line "
    "each) and the exact frame where it broke.\n"
    "  Smoking gun -- the single most telling line, quoted verbatim.\n"
    "  Trigger -- what set it off.\n"
    "  Operational facts -- did the pod restart? which workload/namespace?\n\n"
    "Honesty over confidence: QUOTE the log lines you rely on, and clearly separate what the logs "
    "SHOW from what you're INFERRING (an inference is fine -- just label it). If the evidence "
    "genuinely doesn't show something, say so rather than inventing a frame, a file, or a cause."
)


def _evidence_bundle(finding: Finding, live_logs: str = "") -> str:
    """The evidence as a labeled block for the model -- the finding's headline + every structured
    field, then the logs, verbatim and last (the meat the investigation reads). ``live_logs`` (the
    pod's logs RE-FETCHED FRESH at analyze time -- current + previous container) lead when present;
    the scan-time LOG_WINDOW / trace follow as the captured snapshot (the fallback when the pod's
    gone)."""
    lines = [
        f"Finding: {finding.last_title}",
        f"Severity: {finding.last_severity}   Status: {finding.status}",
        f"First seen: {finding.first_seen}   Last seen: {finding.last_seen}",
    ]
    details = finding.details or {}
    window = details.get(EvidenceKeys.LOG_WINDOW)
    trace = details.get(EvidenceKeys.TRACE)
    bulky = {EvidenceKeys.LOG_WINDOW, EvidenceKeys.TRACE}  # the long blocks go last, under headers
    for key, value in details.items():
        if key not in bulky:
            lines.append(f"{key}: {value}")
    if live_logs:
        lines.append(
            "\n--- logs RE-FETCHED LIVE at analyze time (current + previous container) ---\n"
            + live_logs
        )
    if window:
        lines.append(
            "\n--- captured logs leading up to the failure (scan-time snapshot) ---\n" + str(window)
        )
    if trace:
        lines.append("\n--- captured error / stack-trace block ---\n" + str(trace))
    return "\n".join(lines)


def analyze_finding(
    finding: Finding,
    complete: Callable[[str, str, str], str | None],
    *,
    live_logs: str = "",
) -> str | None:
    """The RCA for one finding, via the LLM seam (``complete``); None when no model is configured.
    ``live_logs`` (the pod's logs re-fetched FRESH at analyze time) lead the evidence when the
    caller could pull them -- so the model investigates the live picture, not a stale capture."""
    return complete(_RCA_SYSTEM, _evidence_bundle(finding, live_logs), "analyze")
