"""The canonical State Model — the spine. Every source normalizes to this.

Plain stdlib dataclasses on purpose: zero dependencies, easy to read, and the
core stays trivially serializable to JSON for the LLM and for storage.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


def _now() -> datetime:
    return datetime.now(UTC)


class ChangeType(str, Enum):
    ADDED = "added"  # declared, not yet in reality (will be created)
    REMOVED = "removed"  # in reality, not declared (extra / deleted out from under us)
    MODIFIED = "modified"  # declared and observed disagree on properties


@dataclass
class Provenance:
    """Where a resource/drift came from, so an Alert can point at the exact source."""

    source: str  # e.g. "terraform"
    address: str | None = None  # e.g. "aws_s3_bucket.logs"
    file: str | None = None  # declaring file, if known
    line: int | None = None


@dataclass
class Resource:
    """A single declared or observed resource in canonical form."""

    kind: str  # e.g. "aws_s3_bucket"
    identity: str  # stable, idempotent id (e.g. the terraform address)
    provenance: Provenance
    properties: dict = field(default_factory=dict)
    observed_at: datetime = field(default_factory=_now)


@dataclass
class Drift:
    """A reconciled divergence between declared and observed state."""

    identity: str
    kind: str
    change_type: ChangeType
    provenance: Provenance
    declared: dict | None = None  # desired properties (None if the resource is extra)
    observed: dict | None = None  # actual properties (None if the resource is missing)
    detected_at: datetime = field(default_factory=_now)

    def summary(self) -> str:
        return f"{self.change_type.value} {self.kind} {self.identity}"

    @property
    def fingerprint(self) -> str:
        """A stable, idempotent id for *this resource drifting* -- the durable finding.

        Deliberately coarse: ``source|identity|change_type``. "This resource is
        drifting" is one finding whose details (declared/observed properties) churn
        underneath; the fingerprint must not churn with them, or every property tweak
        would read as a brand-new finding and defeat the new-vs-recurring memory. Same
        drift re-ingested -> same fingerprint; a different source, identity, or change
        type -> a different one. (kind is omitted on purpose: identity is already the
        stable id, and a kind rename for the same identity is the same finding.)
        """
        raw = f"{self.provenance.source}|{self.identity}|{self.change_type.value}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), default=str, indent=2)
