"""The StateSource plugin seam.

Most sources enumerate declared Resources, which the reconciler diffs against
observed state. Some sources (Terraform, ArgoCD) reconcile natively and yield
Drift directly -- those implement DriftSource.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..model import Drift, Resource


@dataclass(frozen=True)
class Capabilities:
    """A plugin's command manifest, split into two permission categories.

    - ``observe``: read-only commands the plugin runs to *collect* state. Pre-approved --
      steadystate may run these freely (they cannot change a deployment).
    - ``destructive``: potentially state-changing commands the plugin runs to *act*
      (remediate). These ALWAYS require permission before they run -- the approval gate.

    A plugin with no ``destructive`` commands is observe-only by declaration. Documenting
    both per plugin is the permission contract: an operator sees exactly what a plugin will
    run and which side of the approval line each command sits on -- and a hand-written plugin
    declares its own, so the boundary is the plugin's to define, not a central policy's.
    """

    observe: tuple[str, ...] = ()
    destructive: tuple[str, ...] = ()


@runtime_checkable
class StateSource(Protocol):
    name: str

    def collect_declared(self) -> list[Resource]: ...


@runtime_checkable
class DriftSource(Protocol):
    """A source that natively reconciles and yields Drift (e.g. `terraform plan`)."""

    name: str

    def collect_drift(self) -> list[Drift]: ...


@runtime_checkable
class ObservedSource(Protocol):
    """A source that enumerates OBSERVED resources (what is actually running), to be
    diffed against a StateSource's declared resources by reconcile()."""

    name: str

    def collect_observed(self) -> list[Resource]: ...
