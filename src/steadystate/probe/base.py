"""The probe seam: the second kind of departure from steady state.

A `Drift` says *config diverged* (declared ≠ observed). A `Symptom` says the config is fine
but the resource **isn't healthy** -- it's malfunctioning *now* (a crashloop, a restart storm,
a failing healthcheck). It is the operational counterpart to a Drift, and it rides the exact
same reasoning pipeline (Signal → Event → Alert) that `PolicyFinding` already proved out.

A `Prober` probes the *declared* resources it's given -- the same inventory the standing-policy
pass evaluates -- by reading the live health verdict the platform already computes (kubectl pod
status, docker state) into Symptoms. We rent the detection; the reasoning -- correlating a
Symptom to a co-located Drift into one root-caused Alert -- is ours, and is the whole point.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from ..model import Provenance, Resource
from ..reason.alert import Severity


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass
class Symptom:
    """An operational malfunction of a declared resource, observed now. Parallel to `Drift`;
    where Drift says config diverged, a Symptom says config is fine but it's failing."""

    identity: str  # same id space as Drift/Resource, so a Symptom and a Drift can be co-located
    kind: str  # the resource kind (e.g. "Deployment")
    category: str  # "CrashLoopBackOff", "Restarting", "Unhealthy", "Exited", ...
    severity: Severity  # the prober scores it -- a crashloop is HIGH, a flap is MEDIUM
    title: str  # one-line, stable per (identity, category)
    detail: str  # the evidence: pod counts + the failing pod's last log line
    provenance: Provenance
    detected_at: datetime = field(default_factory=_now)
    # Structured key/value evidence for the `show <fp>` view (namespace, cluster, pod count, last
    # log line, ...). Auxiliary -- excluded from equality so it never perturbs identity/grouping.
    evidence: dict[str, str] = field(default_factory=dict, compare=False)

    def summary(self) -> str:
        return f"{self.category} {self.kind} {self.identity}"

    @property
    def fingerprint(self) -> str:
        """A stable, idempotent id for *this resource malfunctioning this way* -- the durable
        finding. ``source|identity|category``, mirroring Drift/PolicyFinding so the state store
        treats it identically (new / recurring / resolved, mute / snooze, all for free)."""
        raw = f"{self.provenance.source}|{self.identity}|{self.category}"
        return hashlib.sha256(raw.encode()).hexdigest()


@runtime_checkable
class Prober(Protocol):
    """Probes the live health of declared resources into Symptoms. The operational counterpart
    to a StateSource (which reconciles declared vs observed config into Drift)."""

    name: str

    def probe(self, resources: list[Resource]) -> list[Symptom]: ...
