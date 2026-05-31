"""Delivery adapters -- the deliver seam, keyed by name, mirroring notify/SURFACES.

An adapter ships a RemediationArtifact (see act/artifact.py) somewhere reviewable. Built-ins
register here; ``--deliver <name>`` dispatches without hand-editing the CLI. Adding an in-tree
adapter is one line in ``_BUILTIN_DELIVERIES``.

Out-of-tree adapters register the same way without editing this file: a separately installed
package declares a ``steadystate.deliveries`` entry point (a zero-arg factory) and ``merged()``
overlays it on the built-ins (built-ins win a name clash). See plugins.py.
"""

from __future__ import annotations

from collections.abc import Callable

from ...plugins import merged
from .base import DeliveryAdapter, DeliveryReceipt
from .patch_file import PatchFileDelivery

# name -> zero-arg factory -> DeliveryAdapter. patch-file is the auth-free Level 0; branch / PR
# adapters slot in here behind the same seam, isolating their auth to their own module.
_BUILTIN_DELIVERIES: dict[str, Callable[[], DeliveryAdapter]] = {
    "patch-file": PatchFileDelivery,
}

# Built-ins overlaid with discovered `steadystate.deliveries` entry points.
DELIVERIES: dict[str, Callable[[], DeliveryAdapter]] = merged("deliveries", _BUILTIN_DELIVERIES)

__all__ = ["DELIVERIES", "DeliveryAdapter", "DeliveryReceipt", "build_deliveries"]


def build_deliveries(names: list[str]) -> list[DeliveryAdapter]:
    """Construct the registered DeliveryAdapters for ``names``, or raise ValueError."""
    adapters: list[DeliveryAdapter] = []
    for name in names:
        try:
            factory = DELIVERIES[name]
        except KeyError:
            known = ", ".join(sorted(DELIVERIES))
            raise ValueError(f"unknown delivery '{name}' (known: {known})") from None
        adapters.append(factory())
    return adapters
