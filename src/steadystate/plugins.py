"""Out-of-tree plugin discovery -- importlib.metadata entry points.

steadystate's seams are registries: sources, domains, surfaces, inbound adapters, executors,
correlators. *In-tree*, adding to one is a single line in that package's ``__init__``. This
module extends the same idea across the packaging boundary: a **separately installed** package
contributes to any seam by declaring an entry point, so "add a pack, never edit core" holds for
third parties too, not only within this repo.

A plugin package opts in through its own metadata, naming the seam's group and a factory:

    # pyproject.toml of some third-party package
    [project.entry-points."steadystate.sources"]
    pulumi = "acme_steadystate.pulumi:make_source"   # make_source(path) -> DriftSource

    [project.entry-points."steadystate.domains"]
    pci = "acme_steadystate.pci:PCIDomain"           # zero-arg -> a Domain

The object an entry point loads is the same shape the in-tree registry already holds for that
seam (a source factory, a Surface factory, a Domain class, ...). At startup each registry
overlays what it discovers onto its built-ins, with two guarantees:

* **Isolation** -- a plugin that fails to import is logged and skipped; a broken third-party
  package can never crash steadystate or hide the plugins that *do* load.
* **Built-ins win** -- on a name clash the shipped backend keeps the name. An installed package
  can *add* ``--source pulumi`` but never silently redirect ``--source terraform`` at its own
  code (discovery extends a seam, it cannot replace one).

Stdlib only: ``importlib.metadata``, no plugin framework.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

_GROUP_PREFIX = "steadystate."


def discover(seam: str) -> dict[str, object]:
    """Load every entry point in the ``steadystate.<seam>`` group -> ``{name: loaded_object}``.

    Each entry point is loaded independently: one that raises on import is logged and skipped,
    so a single bad plugin never takes the rest -- or the host -- down. A failure to enumerate
    the group at all (a malformed installed distribution) yields an empty mapping, not a crash.
    """
    group = f"{_GROUP_PREFIX}{seam}"
    loaded: dict[str, object] = {}
    try:
        found = entry_points(group=group)
    except Exception as exc:  # a malformed installed dist can make enumeration itself raise
        logger.warning("plugin discovery failed for group %s: %s", group, exc)
        return loaded
    for ep in found:
        try:
            loaded[ep.name] = ep.load()
        except Exception as exc:
            logger.warning("skipping plugin %r in group %s: %s", ep.name, group, exc)
    return loaded


def merged(seam: str, builtins: dict[str, T]) -> dict[str, T]:
    """``builtins`` overlaid on what ``discover(seam)`` finds, **built-ins winning a clash**.

    A discovered name that isn't built in is added; a discovered name that *is* built in is
    dropped in favour of the shipped one -- so installing a package can only extend a seam,
    never hijack a name steadystate already ships. Returns a fresh dict (callers can mutate it
    without touching ``builtins``). Discovered values are trusted to be the seam's expected
    shape; a mismatch surfaces when the value is used, exactly like an in-tree registry typo.
    """
    out: dict[str, T] = dict(builtins)
    for name, value in discover(seam).items():
        if name in out:
            logger.warning("ignoring plugin %r: a built-in already owns that name", name)
            continue
        out[name] = value  # type: ignore[assignment]  # trusted to match T; verified on use
    return out
