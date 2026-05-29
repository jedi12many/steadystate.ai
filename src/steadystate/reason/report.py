"""Three-tier surfacing + the Brain Tuning knob.

Severity decides a drift's tier; tuning sets the bars:

- SIGNAL -- the firehose: every drift. Counted, not surfaced individually.
- EVENT  -- cleared the filter: recorded, lower prominence.
- ALERT  -- analyzed + correlated: surfaced, with or without a recommended action.

One operator knob (lenient / default / strict) moves the bars together: strict
lowers them (more surfaces), lenient raises them (more stays a counted Signal).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .alert import Alert, Layer, Severity


class Tuning(str, Enum):
    LENIENT = "lenient"
    DEFAULT = "default"
    STRICT = "strict"


_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

# (event_floor, alert_floor) per tuning. A higher floor is quieter -- more drift
# stays a counted Signal instead of paging someone.
_FLOORS: dict[Tuning, tuple[Severity, Severity]] = {
    Tuning.STRICT: (Severity.LOW, Severity.MEDIUM),
    Tuning.DEFAULT: (Severity.MEDIUM, Severity.HIGH),
    Tuning.LENIENT: (Severity.HIGH, Severity.CRITICAL),
}


def classify(severity: Severity, tuning: Tuning) -> Layer:
    """Which tier a drift of this severity lands in, under this tuning."""
    event_floor, alert_floor = _FLOORS[tuning]
    if _RANK[severity] >= _RANK[alert_floor]:
        return Layer.ALERT
    if _RANK[severity] >= _RANK[event_floor]:
        return Layer.EVENT
    return Layer.SIGNAL


@dataclass
class Report:
    """The result of a scan: every drift as an Alert carrying its tier, plus the
    tuning that classified them. Consumers read it by tier."""

    items: list[Alert] = field(default_factory=list)
    tuning: Tuning = Tuning.DEFAULT

    @property
    def alerts(self) -> list[Alert]:
        """ALERT tier -- surfaced, analyzed, with an optional recommended action."""
        return [i for i in self.items if i.layer is Layer.ALERT]

    @property
    def events(self) -> list[Alert]:
        """EVENT tier -- cleared the filter, recorded, lower prominence than an Alert."""
        return [i for i in self.items if i.layer is Layer.EVENT]

    @property
    def signals(self) -> list[Alert]:
        """SIGNAL tier -- the raw firehose, normally counted rather than listed."""
        return [i for i in self.items if i.layer is Layer.SIGNAL]

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def surfaced(self) -> list[Alert]:
        """Everything above the raw Signal tier (Alerts then Events) -- what the
        console shows."""
        return self.alerts + self.events
