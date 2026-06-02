"""The scan engine: build a reasoned Report from a declared-state source.

This is the orchestration both the ``scan`` CLI command and the chat-summoned probe
(``inbound/server.py``) run -- factored out so there is *one* path that turns a source into
Alerts, not two. It is the pure, read-only half: build the source / prober / enricher, collect
drift + declared resources + symptoms, run the pipeline, enrich, and stamp the label.

State (memory, suggestions, autonomy) and emission stay with the caller, so this stays
side-effect-free and safe to call from a request handler. Unknown source/probe/correlator/
enricher/tuning raise plain ``ValueError`` -- the CLI translates that to a clean BadParameter,
the listener catches it and replies with the message.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from .act import build_executor
from .probe import Prober, auto_prober_for, build_prober
from .reason.enrich import build_enricher
from .reason.llm import LLMAnalyst, PromptGate
from .reason.pipeline import Pipeline, build_correlator
from .reason.report import Report, Tuning
from .sources import build_drift_source
from .sources.base import StateSource


@runtime_checkable
class SupportsContext(Protocol):
    """A source or prober that can be aimed at a named backend context -- today a kube context, so
    one cluster = one target. ``build_report`` applies it to whichever of the source/prober opt in;
    components that don't implement it (every non-k8s source) simply ignore ``--context``."""

    def use_context(self, context: str) -> None: ...


@runtime_checkable
class SupportsLogScan(Protocol):
    """A prober that can do a deeper, log-content pass (`probe --deep`) on top of its status check.
    ``build_report(scan_logs=True)`` flips it on for whichever prober opts in; others ignore it."""

    def enable_log_scan(self) -> None: ...


def build_prober_for(probe: str, source: str, path: Path) -> Prober | None:
    """Resolve a ``--probe`` value to a Prober (or None). ``auto`` picks the probe matching the
    source (None where none makes sense, e.g. terraform/ansible); a name builds that probe."""
    if probe == "auto":
        name = auto_prober_for(source)
        return None if name is None else build_prober(name, path)
    if probe == "none":
        return None
    return build_prober(probe, path)  # raises ValueError on an unknown name


def build_report(
    source: str,
    path: Path,
    *,
    probe: str = "none",
    tuning: str = "default",
    correlator: str = "auto",
    enrich: str = "none",
    no_llm: bool = False,
    label: str = "",
    context: str = "",
    scan_logs: bool = False,
    llm_gate: PromptGate | None = None,
) -> Report:
    """Build a reasoned Report: drift + (optional) probe symptoms, scored + correlated + enriched,
    every item stamped with ``label``. Pure -- no state store, no surfaces.

    ``context`` (when set) aims the source + prober at a named backend context -- today a kube
    context, so the live cluster-health source and the kubectl probe both read that one cluster; a
    component that doesn't support it ignores it.

    ``scan_logs`` (`probe --deep`) turns on the prober's deeper log-content pass -- the kubectl
    probe then reads Running pods' log tails for error/fatal signatures, not just pod status.
    Opt-in: it costs a `kubectl logs` per pod. A prober that doesn't support it ignores the flag.

    ``llm_gate`` (opt-in) is consulted before any prompt is sent to the model -- the CLI passes a
    confirmer so a cautious operator can review/approve egress; headless callers leave it None.

    Raises ``ValueError`` for an unknown source / probe / correlator / enricher / tuning.
    """
    level = Tuning(tuning)  # ValueError on a bad value
    analyst = LLMAnalyst(enabled=False if no_llm else None, gate=llm_gate)
    grouping = build_correlator(correlator, analyst)
    enricher = build_enricher(enrich)
    prober = build_prober_for(probe, source, path)
    src = build_drift_source(source, path)
    if context:  # aim whichever of the source/prober support it at this backend context
        for component in (src, prober):
            if isinstance(component, SupportsContext):
                component.use_context(context)
    if scan_logs and isinstance(prober, SupportsLogScan):  # `probe --deep`: read pod logs too
        prober.enable_log_scan()

    drifts = src.collect_drift()
    # The declared inventory feeds the standing-policy pass (CIS/STIG) AND the probe. Only
    # sources that enumerate declared state implement StateSource; native drift sources
    # (Terraform, ArgoCD) don't, so guard rather than assume.
    resources = src.collect_declared() if isinstance(src, StateSource) else []
    # The prober reads the live health of those declared resources into Symptoms (the second
    # departure type). None (probe "none") -> no symptoms, the path is unchanged.
    symptoms = prober.probe(resources) if prober is not None else []

    report = Pipeline(analyst=analyst, tuning=level, correlator=grouping).run(
        drifts, resources, symptoms
    )
    report.llm_calls = analyst.calls  # this scan's LLM spend (prometheus surface / store)
    _stamp_remediability(report, source, path)
    if label:  # stamp the environment on every item so each surfaced alert self-identifies
        for item in report.items:
            item.environment = label
    # Enrichment runs between run() and emit, so a severity bumped by a currently-failing
    # resource flows on. None (enrich "none") honestly no-ops, leaving the report unchanged.
    if enricher is not None:
        enricher.enrich(report)
    return report


def _stamp_remediability(report: Report, source: str, path: Path) -> None:
    """Mark each alert with whether steadystate can actually carry out a remediation for it --
    deterministically, from the same executor + eligibility the suggest/approve path uses, NEVER
    from the LLM. An observe-only source (no executor), or an alert with no eligible drift (a pure
    symptom/policy finding, or only a REMOVED drift), is not remediable. This is the source of
    truth a surface uses to label a recommendation 'apply' vs 'manual' -- so the model's advice and
    the tool's reach never get conflated."""
    executor = build_executor(source, path)
    if executor is None:  # observe-only source -> nothing here is executable
        return
    for alert in report.alerts:
        alert.remediable = any(executor.plan_for(drift).eligible for drift in alert.drifts)
