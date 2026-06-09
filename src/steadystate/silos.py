"""Named silos -- a registry of your deployments, kept separate.

Running from a laptop against several deployments (a gateway, a proxy, in different regions), each
is its own *silo*: a folder with its own ``.steadystate/`` (state.db, targets, checks) and its own
kubeconfig, walled off so nothing leaks across them. The isolation has always worked by folder; this
just lets you **name** each silo once and refer to it by name -- ``--silo gateway-use1`` instead of
a long ``--dir`` path. The registry is a small JSON map (name -> absolute folder) at
``~/.steadystate/silos.json`` (override with ``STEADYSTATE_SILOS``); it holds only paths, never
secrets.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

SILOS_ENV = "STEADYSTATE_SILOS"


def silos_path() -> Path:
    """The registry file: ``STEADYSTATE_SILOS`` if set, else ``~/.steadystate/silos.json``."""
    override = os.environ.get(SILOS_ENV, "").strip()
    return Path(override) if override else Path.home() / ".steadystate" / "silos.json"


def load_silos() -> dict[str, str]:
    """The registered silos (name -> folder). Missing / malformed file -> {} (no crash)."""
    path = silos_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def save_silos(silos: dict[str, str]) -> None:
    path = silos_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(silos, indent=2, sort_keys=True))


def resolve_silo(name: str) -> str | None:
    """The folder a silo name points at, or None if it isn't registered."""
    return load_silos().get(name)


def add_silo(name: str, directory: str) -> str:
    """Register ``name`` -> the absolute form of ``directory`` (``~`` expanded). Returns the stored
    path. Overwrites an existing name (re-pointing a silo is just adding it again)."""
    resolved = str(Path(directory).expanduser().resolve())
    silos = load_silos()
    silos[name] = resolved
    save_silos(silos)
    return resolved


def remove_silo(name: str) -> bool:
    """Drop ``name`` from the registry. True if it was there, False if it wasn't."""
    silos = load_silos()
    if name not in silos:
        return False
    del silos[name]
    save_silos(silos)
    return True


def discover_silos(parent: str = "") -> dict[str, str]:
    """Find silos under ``parent`` (default: cwd) by convention -- each immediate subfolder that has
    a ``.steadystate/`` is a silo, named by the subfolder. So a ``prod/`` holding ``web1/ web2/
    runners1/`` (each with its own ``.steadystate/``) yields those three by name. Returns
    {name -> absolute folder}, empty when ``parent`` isn't a dir or nothing qualifies. Read-only --
    it only looks; ``silo discover`` is what registers them."""
    base = Path(parent).expanduser() if parent else Path.cwd()
    if not base.is_dir():
        return {}
    return {
        child.name: str(child.resolve())
        for child in sorted(base.iterdir())
        if child.is_dir() and (child / ".steadystate").is_dir()
    }
