"""The Domain plugin seam."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..model import Drift
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
