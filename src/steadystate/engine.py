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

from .probe import Prober, auto_prober_for, build_prober
from .reason.enrich import build_enricher
from .reason.llm import LLMAnalyst
from .reason.pipeline import Pipeline, build_correlator
from .reason.report import Report, Tuning
from .sources import build_drift_source
from .sources.base import StateSource


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
) -> Report:
    """Build a reasoned Report: drift + (optional) probe symptoms, scored + correlated + enriched,
    every item stamped with ``label``. Pure -- no state store, no surfaces.

    Raises ``ValueError`` for an unknown source / probe / correlator / enricher / tuning.
    """
    level = Tuning(tuning)  # ValueError on a bad value
    analyst = LLMAnalyst(enabled=False if no_llm else None)
    grouping = build_correlator(correlator, analyst)
    enricher = build_enricher(enrich)
    prober = build_prober_for(probe, source, path)
    src = build_drift_source(source, path)

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
    if label:  # stamp the environment on every item so each surfaced alert self-identifies
        for item in report.items:
            item.environment = label
    # Enrichment runs between run() and emit, so a severity bumped by a currently-failing
    # resource flows on. None (enrich "none") honestly no-ops, leaving the report unchanged.
    if enricher is not None:
        enricher.enrich(report)
    return report
