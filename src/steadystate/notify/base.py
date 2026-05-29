"""The Surface plugin seam: where Alerts go, and (later) where operator replies come from."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..reason.report import Report


@runtime_checkable
class Surface(Protocol):
    name: str

    def emit(self, report: Report) -> None: ...
