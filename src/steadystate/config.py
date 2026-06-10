"""The committed config: ``steadystate/config.toml`` -- a repo/silo's reviewed configuration, in
ONE file beside the IaC instead of scattered ``STEADYSTATE_*`` env vars.

Precedence is 12-factor and **non-breaking**: ``flag > env var > config.toml > built-in default``.
The committed file is only the *baseline* -- env/flags still override per run, so nothing that works
today changes; the config just fills the gaps you'd otherwise fill by hand every run. Same principle
as the committed ``checks.json`` / ``solutions.json`` (see ``docs/repo-native-posture.md``): config
as code, reviewed in PRs -- which matters most for the **bound** (the autonomy envelope), a decision
that should never be a loose env var.

Read-only stdlib ``tomllib``; a missing/malformed file is an empty config (defaults stand), never a
crash. CWD-relative like the other intent files, so ``--silo`` (which chdirs) gets per-silo config.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

DEFAULT_CONFIG_FILE = "steadystate/config.toml"  # the committed convention
CONFIG_ENV = "STEADYSTATE_CONFIG"


def in_steadystate_tree() -> bool:
    """Whether the CWD already sits inside a ``steadystate/`` tree -- e.g. a silo living at
    ``steadystate/silos/<name>/`` in a consumer repo. There, the committed-intent prefix would
    stutter (``steadystate/silos/x/steadystate/config.toml``), so every intent resolver probes the
    BARE filename too (``./config.toml``, ``./targets.json``, ``./kb/``) and fresh writes land
    bare. Outside such a tree nothing changes -- the bare probe stays off, so an unrelated
    ``config.toml`` in a normal IaC repo can never be misread as steadystate's."""
    return any(part.lower() == "steadystate" for part in Path.cwd().parts)


def config_path() -> Path:
    """Where the config lives: ``STEADYSTATE_CONFIG`` if set, else the committed
    ``steadystate/config.toml``, else -- inside a ``steadystate/`` tree (a silo) -- the bare
    ``./config.toml``."""
    env = os.environ.get(CONFIG_ENV, "").strip()
    if env:
        return Path(env)
    committed = Path(DEFAULT_CONFIG_FILE)
    if committed.exists() or not in_steadystate_tree():
        return committed
    return Path("config.toml")


def load_config(path: Path | None = None) -> dict:
    """The whole parsed config, or ``{}`` when there's no readable file. Never raises."""
    resolved = path or config_path()
    if not resolved.exists():
        return {}
    try:
        data = tomllib.loads(resolved.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def config_table(name: str, path: Path | None = None) -> dict:
    """One top-level ``[table]`` from the config (``[ci]``, ``[bound]``, ``[defaults]``, ...), or
    ``{}`` when absent/malformed -- so a caller reads its section without guarding every access."""
    table = load_config(path).get(name)
    return table if isinstance(table, dict) else {}
