"""Two-stage surfacing + the Brain Tuning knob.

Severity decides whether a drift is a Signal or an Event; tuning sets that one bar.
Signals are the counted firehose. Events go to the correlator (reason/llm.py), which
groups them by root cause -- each group becomes an Alert. So Alerts are produced by
correlation, not by a severity threshold: a pile of individually-minor Events can
still raise one real Alert.

The tuning knob moves the Signal->Event bar: strict lowers it (more becomes Events,
so more reaches correlation), lenient raises it (more stays a counted Signal).
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

# The single Signal->Event bar per tuning. A higher floor is quieter -- more drift
# stays a counted Signal instead of reaching correlation.
_EVENT_FLOOR = {
    Tuning.STRICT: Severity.LOW,
    Tuning.DEFAULT: Severity.MEDIUM,
    Tuning.LENIENT: Severity.HIGH,
}


def classify(severity: Severity, tuning: Tuning) -> Layer:
    """Signal or Event, under this tuning. (Alerts come from correlation, not here.)"""
    if _RANK[severity] >= _RANK[_EVENT_FLOOR[tuning]]:
        return Layer.EVENT
    return Layer.SIGNAL


@dataclass
class Report:
    """The result of a scan: counted Signals plus correlated Alerts (each Alert bundles
    the Events that share its root cause), with the tuning that produced them."""

    items: list[Alert] = field(default_factory=list)
    tuning: Tuning = Tuning.DEFAULT

    @property
    def alerts(self) -> list[Alert]:
        """Correlated groups -- the surfaced unit, with an optional recommended action."""
        return [i for i in self.items if i.layer is Layer.ALERT]

    @property
    def signals(self) -> list[Alert]:
        """The raw firehose below the Event bar -- normally counted, not listed."""
        return [i for i in self.items if i.layer is Layer.SIGNAL]

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def event_count(self) -> int:
        """How many Events fed correlation -- the drifts bundled across all Alerts."""
        return sum(len(a.drifts) for a in self.alerts)
