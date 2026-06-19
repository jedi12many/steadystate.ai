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

from collections.abc import Callable, Sequence

from ..evidence import EvidenceKeys
from ..state import Finding
from .collect import Evidence

# The RCA prompt. It asks for the exact shape a senior on-call writes (and a vendor's support team
# needs) and tells it to INVESTIGATE the lead-up -- reason, but quote + label inference.
_RCA_SYSTEM = (
    "You are a senior SRE INVESTIGATING a production incident -- writing the RCA an "
    "on-call engineer (and, if it's a vendor's bug, their support team) needs. You're "
    "given the captured logs LEADING UP TO the failure plus the error/stack block. Read the whole "
    "sequence and reason like an investigator: the cause is usually in what happened BEFORE the "
    "failure line, not the failure line itself -- trace the operations, the state, and the "
    "trigger. Bring what you know about this kind of system to connect the dots. If this fleet's "
    "PRIOR RCAs for the same failure are provided, use them -- state up front whether this is the "
    "SAME root cause as before or a NEW one.\n\n"
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


def _evidence_bundle(
    finding: Finding,
    collected: Sequence[Evidence] = (),
    live_logs: str = "",
    prior: str = "",
) -> str:
    """The evidence as a labeled block for the model -- the finding's headline, then ``prior`` (this
    fleet's earlier RCAs for the same failure, framing the analysis up front), the structured keys,
    the ``collected`` evidence (events / pod status gathered live by the read-only collectors,
    each tagged with the read that produced it so the RCA stays checkable), and the logs verbatim
    and last (the meat the investigation reads). ``live_logs`` (the pod's logs RE-FETCHED FRESH at
    analyze time -- current + previous container) lead the logs when present; the scan-time
    LOG_WINDOW / trace follow as the captured snapshot (the fallback)."""
    lines = [
        f"Finding: {finding.last_title}",
        f"Severity: {finding.last_severity}   Status: {finding.status}",
        f"First seen: {finding.first_seen}   Last seen: {finding.last_seen}",
    ]
    if prior:
        lines.append("\n" + prior)
    details = finding.details or {}
    window = details.get(EvidenceKeys.LOG_WINDOW)
    trace = details.get(EvidenceKeys.TRACE)
    bulky = {EvidenceKeys.LOG_WINDOW, EvidenceKeys.TRACE}  # the long blocks go last, under headers
    for key, value in details.items():
        if key not in bulky:
            lines.append(f"{key}: {value}")
    for ev in collected:  # gathered live; operational facts + the event timeline frame the logs
        lines.append(f"\n--- {ev.label} (via `{ev.provenance}`) ---\n{ev.body}")
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
    collected: Sequence[Evidence] = (),
    live_logs: str = "",
    prior: str = "",
) -> str | None:
    """The RCA for one finding, via the LLM seam (``complete``); None when no model is configured.
    ``collected`` is the live read-only evidence the collectors gathered (events, pod status);
    ``live_logs`` (the pod's logs re-fetched FRESH at analyze time) lead when the caller could pull
    them; ``prior`` grounds it in this fleet's earlier RCAs for the same failure (recurrence + their
    root causes), so it can say 'same as before' or 'new'."""
    return complete(_RCA_SYSTEM, _evidence_bundle(finding, collected, live_logs, prior), "analyze")


def prior_incidents(store, finding: Finding, *, limit: int = 3) -> str:
    """This fleet's history for the SAME failure category, as context -- the prior RCAs' root-cause
    lines (not the full re-paste), most-recent first, so it can say 'same root cause as before' or
    'new'. '' when there's no earlier analyzed incident of this category. Cheap: one line each. (The
    same 'ground the model in history' move the decider makes, here for the RCA.)"""
    category = (finding.details or {}).get(EvidenceKeys.CATEGORY, "")
    if not category:
        return ""
    priors: list[str] = []
    for f in sorted(store.all_findings(), key=lambda x: x.last_seen, reverse=True):
        same = (f.details or {}).get(EvidenceKeys.CATEGORY) == category
        if f.fingerprint == finding.fingerprint or not same:
            continue
        got = store.get_analysis(f.fingerprint)
        if got and got[0].strip():
            root = got[0].strip().splitlines()[0][:200]  # the RCA's first line ~ its root cause
            priors.append(f"  - {f.last_title}: {root}")
        if len(priors) >= limit:
            break
    if not priors:
        return ""
    body = "\n".join(priors)
    return (
        f"PRIOR RCAs for this '{category}' failure in this fleet ({len(priors)} earlier):\n{body}"
    )
