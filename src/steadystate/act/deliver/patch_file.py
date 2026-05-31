"""patch-file delivery (the floor): write the artifact's diff to a ``.patch`` on disk.

The auth-free floor. No git, no remote, no credentials -- it just writes the unified diff, and a
human (or a downstream CI step) runs ``git apply``. Works everywhere, including where a tool can't
hold a credential. Every higher rung (branch, PR) wraps this same deterministic patch.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..artifact import RemediationArtifact
from .base import DeliveryReceipt

_DEFAULT_DIR = ".steadystate/patches"


class PatchFileDelivery:
    name = "patch-file"

    def __init__(self, out_dir: str | Path | None = None) -> None:
        self.out_dir = Path(out_dir or os.environ.get("STEADYSTATE_PATCH_DIR", _DEFAULT_DIR))

    def ready(self) -> bool:
        # No external configuration -- writing a local file is always available.
        return True

    def deliver(self, artifact: RemediationArtifact) -> DeliveryReceipt:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        dest = self.out_dir / f"{artifact.slug}.patch"
        dest.write_text(artifact.patch, encoding="utf-8")
        return DeliveryReceipt(
            delivered=True,
            ref=str(dest),
            detail=f"wrote patch for {artifact.drift_identity} (apply with `git apply`)",
        )
