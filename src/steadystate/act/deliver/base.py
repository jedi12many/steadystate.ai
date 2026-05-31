"""The delivery-adapter seam: ship a RemediationArtifact somewhere a human can act on it.

Separating *computing* the fix (deterministic, auth-free -- ``act/artifact.py`` / ``codify.py``)
from *delivering* it is the point: the artifact is a plain patch, and where it lands -- a file, a
git branch, a pull request -- is a pluggable step, exactly like a notify Surface. The auth a PR
needs (a GitHub App, the Actions token) lives only in the adapter that needs it; the lowest rung
(``patch-file``) needs none, so it works anywhere, including GitHub EMU.

Like Surfaces, an adapter is honest: ``ready()`` reports whether it's configured, and an
unconfigured one is skipped, never silently pretended-delivered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..artifact import RemediationArtifact


@dataclass
class DeliveryReceipt:
    """The outcome of one delivery: whether it landed, a reference to where (a patch path, a
    branch name, a PR URL), and a human-readable detail."""

    delivered: bool
    ref: str = ""
    detail: str = ""


@runtime_checkable
class DeliveryAdapter(Protocol):
    name: str

    def ready(self) -> bool: ...

    def deliver(self, artifact: RemediationArtifact) -> DeliveryReceipt: ...
