"""The Surface plugin seam: where Cases go, and (later) where operator replies come from."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..reason.case import Case


@runtime_checkable
class Surface(Protocol):
    name: str

    def emit(self, cases: list[Case]) -> None: ...
