"""The Executor plugin seam."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..reason.case import Case


@runtime_checkable
class Executor(Protocol):
    name: str

    def apply_eligible(self, case: Case) -> bool:
        """True only if this case has a real, executable, reversible remediation."""
        ...

    def remediate(self, case: Case) -> None: ...
