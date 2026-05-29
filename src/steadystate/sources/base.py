"""The StateSource plugin seam.

Most sources enumerate declared Resources, which the reconciler diffs against
observed state. Some sources (Terraform, ArgoCD) reconcile natively and yield
Drift directly -- those implement DriftSource.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..model import Drift, Resource


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
