"""Probe plugins: read the live health of declared resources into Symptoms (§4 of the
architecture). A new health probe registers here so `--probe <name>` dispatches without
editing the CLI. Mirrors the source / surface / enricher registries.
"""

from __future__ import annotations

from collections.abc import Callable

from .base import Prober, Symptom
from .kubectl import KubectlProbe

# name -> zero-arg factory -> Prober. Indexed by the CLI's --probe choice. "none" (the
# default) means no probe step -- resolved to None in build_prober, not registered here.
PROBES: dict[str, Callable[[], Prober]] = {
    "kubectl": KubectlProbe,
}

__all__ = ["PROBES", "Prober", "Symptom", "build_prober"]


def build_prober(mode: str) -> Prober | None:
    """Construct the Prober for ``mode`` (a registry name or ``none``), or raise ValueError.

    - ``none`` (default): None -- no probe step runs, the un-probed path is unchanged.
    - any registered name (``kubectl`` | an out-of-tree probe): that prober.
    - anything else: ValueError, which the CLI turns into a clean typer.BadParameter.
    """
    if mode == "none":
        return None
    try:
        factory = PROBES[mode]
    except KeyError:
        known = ", ".join(sorted(PROBES))
        raise ValueError(f"unknown prober '{mode}' (known: none, {known})") from None
    return factory()
