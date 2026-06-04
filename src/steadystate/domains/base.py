"""The Domain plugin seam."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..model import Drift, Provenance, Resource
from ..reason.alert import Severity


@dataclass(frozen=True)
class Reference:
    """A framework reference attached to recognized drift.

    Honest framing: this is *config-exposure -> technique mapping, NOT behavioral
    detection*. We map a recognized exposure-increasing config change to the technique
    it enables; we are not detecting an attack. Framework-agnostic on purpose -- MITRE
    ATT&CK is first, but CIS / STIG / CWE reuse the same value type and the same rail.

    Frozen so a Reference is an immutable value: packs share them safely and an Alert
    can carry them without anyone mutating a pack's mapping by accident.
    """

    framework: str  # e.g. "MITRE"
    id: str  # e.g. "T1530"
    name: str = ""  # human-readable technique name, e.g. "Data from Cloud Storage"
    url: str | None = None  # e.g. "https://attack.mitre.org/techniques/T1530/"
    # For a benchmark reference (CIS), which level the control belongs to -- 1 (broadly-applicable
    # hardening that doesn't break function) or 2 (defense-in-depth). None for non-levelled
    # frameworks (MITRE). The `compliance` report filters on it ("CIS Level 1").
    level: int | None = None


@dataclass(frozen=True)
class PolicyFinding:
    """A standing-policy violation a Domain *generates* from a baseline -- not a drift.

    Where ``score`` reacts to a divergence between declared and observed state, a baseline
    pack (CIS/STIG/...) audits the declared posture itself and emits a PolicyFinding for
    each rule a resource violates, whether or not anything drifted. Honest framing: this is
    *config-posture evaluation, NOT runtime/behavioral detection* -- we read the declared
    configuration and report the rules it fails.

    Frozen value type, like Reference: packs build them statelessly and an Alert carries
    them. ``fingerprint`` mirrors :pyattr:`~steadystate.model.Drift.fingerprint` exactly
    (``source|identity|rule_id`` instead of ``...|change_type``) so the state store -- which
    only ever sees fingerprints + a (severity, title) pair -- gives policy findings the same
    new/recurring/resolved + mute/snooze memory as drift, with no store change.
    """

    rule_id: str  # e.g. "CIS-Docker-5.4" -- stable per rule, part of the fingerprint
    identity: str  # the resource it's about (e.g. the compose service name)
    provenance: Provenance
    severity: Severity
    title: str  # one-line, stable per fingerprint: "service 'web' runs privileged"
    detail: str  # the narrative: why it matters
    references: list[Reference] = field(default_factory=list)  # CIS/MITRE chips (Reference rail)

    @property
    def fingerprint(self) -> str:
        """A stable, idempotent id for *this resource violating this rule* -- the durable
        finding. ``source|identity|rule_id``: same resource failing the same rule re-scanned
        -> same fingerprint; a different rule or resource -> a different one."""
        raw = f"{self.provenance.source}|{self.identity}|{self.rule_id}"
        return hashlib.sha256(raw.encode()).hexdigest()


@runtime_checkable
class Domain(Protocol):
    name: str

    def score(self, drift: Drift) -> Severity | None:
        """This domain's severity for the drift, or None if it doesn't care about it."""
        ...

    # NOTE: references() is an OPTIONAL seam extension and is deliberately NOT part of
    # this runtime_checkable Protocol. A pack MAY add
    #
    #     def references(self, drift: Drift) -> list[Reference]: ...
    #
    # to expose the framework references a drift maps to, alongside (never instead of) its
    # severity. We keep it off the Protocol on purpose: this is a runtime_checkable
    # Protocol, so listing references() here would make isinstance(pack, Domain) fail for
    # any existing pack that doesn't implement it -- exactly the breakage we must avoid.
    # The call site (references_for, below) therefore probes with getattr() and falls back
    # to an empty list, so non-implementing packs keep working unchanged and we never force
    # every domain to implement it. The security pack lights it up; CIS/STIG/CWE reuse the
    # same convention later.
    #
    # evaluate() is a second OPTIONAL extension, off the Protocol for the same reason. A
    # baseline pack MAY add
    #
    #     def evaluate(self, resources: list[Resource]) -> list[PolicyFinding]: ...
    #
    # to audit the declared inventory and *generate* findings (CIS/STIG), rather than only
    # scoring an existing drift. evaluate_with (below) probes it the same getattr way.


def references_for(domain: object, drift: Drift) -> list[Reference]:
    """The framework references ``domain`` maps ``drift`` to, or [] if it exposes none.

    Optional-by-convention: a pack opts in by defining ``references(self, drift)``. Packs
    that don't are unaffected -- we getattr the method and fall back to an empty list, so
    the Domain Protocol (just ``score``) is never broadened and no existing pack breaks.
    """
    getter = getattr(domain, "references", None)
    if getter is None:
        return []
    result = getter(drift)
    return list(result) if result else []


def evaluate_with(domain: object, resources: list[Resource]) -> list[PolicyFinding]:
    """The standing-policy findings ``domain`` generates over ``resources``, or [] if none.

    Optional-by-convention, exactly like :func:`references_for`: a baseline pack opts in by
    defining ``evaluate(self, resources)``. Packs that don't are unaffected -- the Domain
    Protocol (just ``score``) is never broadened, so every existing pack keeps working.
    """
    getter = getattr(domain, "evaluate", None)
    if getter is None:
        return []
    result = getter(resources)
    return list(result) if result else []


def evaluate_posture_with(domain: object, resources: list[Resource]) -> list[PolicyFinding]:
    """The *compliance-only* posture findings ``domain`` generates -- the absence-based gaps (CIS
    Level 2 / restricted) that a normal scan deliberately skips because they fire on nearly every
    workload. Optional-by-convention like :func:`evaluate_with`: a pack opts in by defining
    ``evaluate_posture(self, resources)``. ONLY the ``compliance`` command calls this; the scan
    pipeline calls ``evaluate_with`` alone, so everyday scans stay quiet. [] for a pack that doesn't
    implement it."""
    getter = getattr(domain, "evaluate_posture", None)
    if getter is None:
        return []
    result = getter(resources)
    return list(result) if result else []
