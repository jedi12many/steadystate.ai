"""Observe plugins: read the live health of declared resources into Symptoms (§4 of the
architecture). A new health observer registers here so `--observe <name>` dispatches without
editing the CLI. Mirrors the source / surface / enricher registries.
"""

from __future__ import annotations

from collections.abc import Callable

from .base import Observer, Symptom
from .kubectl import KubectlObserver

# name -> zero-arg factory -> Observer. Indexed by the CLI's --observe choice. "none" (the
# default) means no observe step -- resolved to None in build_observer, not registered here.
OBSERVERS: dict[str, Callable[[], Observer]] = {
    "kubectl": KubectlObserver,
}

__all__ = ["OBSERVERS", "Observer", "Symptom", "build_observer"]


def build_observer(mode: str) -> Observer | None:
    """Construct the Observer for ``mode`` (a registry name or ``none``), or raise ValueError.

    - ``none`` (default): None -- no observe step runs, the un-observed path is unchanged.
    - any registered name (``kubectl`` | an out-of-tree observer): that observer.
    - anything else: ValueError, which the CLI turns into a clean typer.BadParameter.
    """
    if mode == "none":
        return None
    try:
        factory = OBSERVERS[mode]
    except KeyError:
        known = ", ".join(sorted(OBSERVERS))
        raise ValueError(f"unknown observer '{mode}' (known: none, {known})") from None
    return factory()
