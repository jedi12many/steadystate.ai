"""The delivery-adapter seam: ship a RemediationArtifact somewhere a human can act on it.

Separating *computing* the fix (deterministic, auth-free -- ``act/artifact.py`` / ``codify.py``)
from *delivering* it is the point. The artifact is a plain patch; where it lands -- a file on
disk, a branch, a pull request -- is a pluggable step, exactly like a notify Surface. The auth a
PR needs (a token, a GitHub App) lives **only** in the adapter that needs it; the floor
(``patch-file``) needs none, so it works anywhere, including under tight credential controls.

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

    def ready(self) -> bool:
        """True iff configured enough to deliver (e.g. a token + repo resolve). A False here means
        the caller skips it with a notice -- never a silent drop, never a crash."""
        ...

    def deliver(self, artifact: RemediationArtifact) -> DeliveryReceipt: ...
