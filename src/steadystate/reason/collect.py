"""Evidence collectors -- the deterministic, read-only gathering that feeds `analyze`.

`analyze` is split by design (see reason/analyze.py): the deterministic layer captures the RIGHT
evidence, the model writes the RCA over it. A collector is one unit of that gathering -- a single
read-only probe (cluster events, pod status, ...) wrapped as a labelled `Evidence` block that
carries the exact read that produced it, so every line the RCA leans on is reproducible and
auditable. This is Layer 1 of the investigator: a FIXED bundle, gathered up front. The same
collectors become the model-directed tools of an investigator loop later -- the seam is here so
that step costs no refactor; only *who picks which collector runs* changes.

Each collector is best-effort and degrades to nothing (a denied read / a gone pod returns None),
exactly like the probe it sits on -- a missing collector never fails the analysis, it just narrows
the evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from ..state import Finding


@dataclass(frozen=True)
class Evidence:
    """One gathered block for the RCA bundle: a label (for the model + the reader), the body, and
    ``provenance`` -- the read (the kubectl argv) that produced it. Provenance is the citation +
    audit anchor that keeps an LLM-written RCA checkable against a deterministic observation; it's
    the line between this and 'just ask a chat agent'."""

    label: str
    body: str
    provenance: str


@dataclass(frozen=True)
class CollectCtx:
    """What a collector needs: the finding under analysis, a read-only probe to gather with, and the
    resolved (namespace, pod) to aim at. The probe is duck-typed (a `KubectlProbe`) to keep this
    module free of a probe import -- collectors call its public read methods."""

    finding: Finding
    probe: Any
    namespace: str
    pod: str


class Collector(Protocol):
    """A single read-only evidence gatherer. ``collect`` returns one `Evidence`, or None when
    there's nothing to add (an empty / denied read) -- best-effort, never raising for an expected
    miss."""

    name: str

    def collect(self, ctx: CollectCtx) -> Evidence | None: ...


class PodStatusCollector:
    """The operational facts beyond the logs -- restart count and the LAST termination (reason +
    exit code: 137 = OOMKilled, a smoking gun a log tail misses)."""

    name = "pod_status"

    def collect(self, ctx: CollectCtx) -> Evidence | None:
        body = ctx.probe.pod_status(ctx.namespace, ctx.pod)
        if not body.strip():
            return None
        return Evidence(
            "pod status / last termination",
            body,
            f"kubectl get pod {ctx.pod} -n {ctx.namespace} -o json",
        )


class EventsCollector:
    """The cluster's recent events for the pod -- OOMKilled / FailedScheduling / image-pull / probe
    failures: the lead-up at the CLUSTER level the pod's own logs can't carry."""

    name = "events"

    def collect(self, ctx: CollectCtx) -> Evidence | None:
        body = ctx.probe.events_for(ctx.namespace, ctx.pod)
        if not body.strip():
            return None
        return Evidence(
            "cluster events for the pod",
            body,
            f"kubectl get events -n {ctx.namespace} --field-selector involvedObject.name={ctx.pod}",
        )


# The registry -- mirrors reason/enrich.py's ENRICHERS: a name -> factory map an out-of-tree
# collector can extend. DEFAULT_COLLECTORS is the fixed Layer-1 bundle `analyze` gathers, ordered
# facts-then-timeline: pod status frames, the event stream tells the story.
COLLECTORS: dict[str, Callable[[], Collector]] = {
    "pod_status": PodStatusCollector,
    "events": EventsCollector,
}
DEFAULT_COLLECTORS: tuple[str, ...] = ("pod_status", "events")


def gather(ctx: CollectCtx, names: tuple[str, ...] | None = None) -> list[Evidence]:
    """Run the named collectors (default: all) against ``ctx`` and return the non-empty `Evidence`,
    in registry order. Best-effort to a fault: a collector that raises is skipped (it must never
    fail the analysis), exactly as a denied read returns None -- the RCA just gets less evidence."""
    out: list[Evidence] = []
    for name in names or DEFAULT_COLLECTORS:
        factory = COLLECTORS.get(name)
        if factory is None:
            continue
        try:
            evidence = factory().collect(ctx)
        except Exception:  # a collector is best-effort -- a bad read narrows evidence, never fails
            evidence = None
        if evidence is not None:
            out.append(evidence)
    return out
