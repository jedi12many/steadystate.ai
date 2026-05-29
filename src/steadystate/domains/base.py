"""The Domain plugin seam."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..model import Drift
from ..reason.alert import Severity


@runtime_checkable
class Domain(Protocol):
    name: str

    def score(self, drift: Drift) -> Severity | None:
        """This domain's severity for the drift, or None if it doesn't care about it."""
        ...
