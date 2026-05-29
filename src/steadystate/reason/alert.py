"""The reasoning output model and the three tiers: Signal -> Event -> Alert.

A drift starts as a Signal (raw, counted). Filtering promotes the ones worth
recording to Events. Analysis + correlation promote those to Alerts -- the
surfaced artifact, with or without a recommended action (sometimes we can't act).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING

from ..model import Drift

if TYPE_CHECKING:
    # Imported under TYPE_CHECKING only: domains.base imports Severity from this module,
    # so a runtime import here would be circular. Reference is a plain frozen value type.
    from ..domains.base import Reference


class Layer(str, Enum):
    SIGNAL = "signal"  # raw drift -- the firehose, counted
    EVENT = "event"  # cleared the filter -- recorded
    ALERT = "alert"  # analyzed + correlated -- surfaced, with or without an action


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """A reasoned finding at some tier. Alerts (the top tier) carry the narrative
    plus an optional recommended action; lower tiers are recorded/counted."""

    title: str
    severity: Severity
    drifts: list[Drift]
    why_it_matters: str  # the reasoning; honest about it when no LLM was available
    layer: Layer = Layer.ALERT
    recommended_action: str | None = None
    llm_backed: bool = False  # did an LLM actually reason about this? (honesty)
    flagged_by: str | None = None  # domain pack that raised the severity, if any
    # Framework references the flagging domain mapped this drift to (MITRE ATT&CK today;
    # CIS/STIG/CWE later, same field). Config-exposure -> technique mapping, NOT behavioral
    # detection. Populated alongside flagged_by in the pipeline; empty when nothing mapped.
    references: list[Reference] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    # Memory annotations, populated by the state store during a stateful scan and
    # left None when scanning statelessly (so Pipeline stays pure and the stateless
    # path is unchanged). first_seen = when this finding was first recorded; status =
    # its lifecycle state (open / muted / snoozed / resolved).
    first_seen: datetime | None = None
    status: str | None = None
