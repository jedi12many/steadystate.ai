"""The reasoning output model and the three layers (Event -> Alert -> Case)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from ..model import Drift


class Layer(str, Enum):
    EVENT = "event"  # raw, counted, not surfaced
    ALERT = "alert"  # cleared a bar; worth recording, not paging
    CASE = "case"  # correlated + actionable; the thing we put in front of an operator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Case:
    """A correlated, actionable finding."""

    title: str
    severity: Severity
    drifts: list[Drift]
    why_it_matters: str  # the reasoning; honest about it when no LLM was available
    layer: Layer = Layer.CASE
    recommended_action: str | None = None
    llm_backed: bool = False  # did an LLM actually reason about this? (honesty)
    flagged_by: str | None = None  # domain pack that raised the severity, if any
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
