"""The Surface plugin seam: where Alerts go, and (later) where operator replies come from."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding


@runtime_checkable
class Surface(Protocol):
    name: str

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        """Render a Report. ``resolved`` (findings that cleared since the last scan,
        from the state store) is console-first in Phase 0; other surfaces ignore it."""
        ...
