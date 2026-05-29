"""Three-layer surfacing + the Brain Tuning knob.

A drift's severity decides its layer, and the tuning level sets the bars:

- EVENT  -- the firehose: every drift. Counted, not surfaced individually.
- ALERT  -- cleared the alert bar: recorded, lower prominence.
- CASE   -- cleared the case bar: page-worthy, full narrative + recommended action.

One operator knob (lenient / default / strict) moves all the bars together: strict
lowers them (more surfaces), lenient raises them (more stays a counted Event).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .case import Case, Layer, Severity


class Tuning(str, Enum):
    LENIENT = "lenient"
    DEFAULT = "default"
    STRICT = "strict"


_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

# (alert_floor, case_floor) per tuning. A higher floor is quieter -- more drift
# stays a counted Event instead of paging someone.
_FLOORS: dict[Tuning, tuple[Severity, Severity]] = {
    Tuning.STRICT: (Severity.LOW, Severity.MEDIUM),
    Tuning.DEFAULT: (Severity.MEDIUM, Severity.HIGH),
    Tuning.LENIENT: (Severity.HIGH, Severity.CRITICAL),
}


def classify(severity: Severity, tuning: Tuning) -> Layer:
    """Which layer a drift of this severity lands in, under this tuning."""
    alert_floor, case_floor = _FLOORS[tuning]
    if _RANK[severity] >= _RANK[case_floor]:
        return Layer.CASE
    if _RANK[severity] >= _RANK[alert_floor]:
        return Layer.ALERT
    return Layer.EVENT


@dataclass
class Report:
    """The result of a scan: every drift as a Case carrying its layer, plus the
    tuning that classified them. Consumers read it by layer."""

    all_cases: list[Case] = field(default_factory=list)
    tuning: Tuning = Tuning.DEFAULT

    @property
    def cases(self) -> list[Case]:
        """CASE layer -- page-worthy, with full narrative + recommended action."""
        return [c for c in self.all_cases if c.layer is Layer.CASE]

    @property
    def alerts(self) -> list[Case]:
        """ALERT layer -- recorded, lower prominence than a Case."""
        return [c for c in self.all_cases if c.layer is Layer.ALERT]

    @property
    def events(self) -> list[Case]:
        """EVENT layer -- the firehose, normally counted rather than listed."""
        return [c for c in self.all_cases if c.layer is Layer.EVENT]

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def surfaced(self) -> list[Case]:
        """Everything above the Event floor (Cases then Alerts) -- the items that
        carry full narrative + recommended action."""
        return self.cases + self.alerts
