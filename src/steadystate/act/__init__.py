"""Executor plugins + guardrails -- the act seam, keyed by source.

Every remediation is apply-eligibility-checked, snapshotted, verified, and reversible; chat
(or any trigger) is a convenience, never a bypass of those guardrails. Executors register
here per source, mirroring DRIFT_SOURCES: a source with an executor can be *acted on*; a
source with none is **observe-only** -- steadystate detects its drift but cannot remediate it,
and build_executor returns None. Adding an in-tree backend's act half is one line in
_BUILTIN_EXECUTORS.

Out-of-tree executors register the same way without editing this file: a separately installed
package declares a `steadystate.executors` entry point (a factory(path) -> Executor) and
`merged()` overlays it on the built-ins (built-ins win a name clash). See plugins.py. A
discovered executor is bound by source name, so it pairs with a discovered (or built-in) source.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..plugins import merged
from .ansible import AnsibleExecutor
from .base import Executor
from .terraform import TerraformExecutor


def _terraform(path: Path) -> Executor:
    # A working dir can apply; a captured plan file can only plan (no dir to run in).
    return TerraformExecutor(working_dir=None if path.is_file() else path)


def _ansible(path: Path) -> Executor:
    # The playbook + inventory come from env (STEADYSTATE_ANSIBLE_PLAYBOOK/_INVENTORY); a dir
    # path is the working dir to run the playbook in (a captured-check file has none).
    return AnsibleExecutor(working_dir=None if path.is_file() else path)


# source name -> factory(path) -> Executor. Only sources listed here can act; everything
# else is observe-only by omission. (k8s/compose are the next entries.)
_BUILTIN_EXECUTORS: dict[str, Callable[[Path], Executor]] = {
    "terraform": _terraform,
    "ansible": _ansible,
}

# Built-ins overlaid with discovered `steadystate.executors` entry points.
EXECUTORS: dict[str, Callable[[Path], Executor]] = merged("executors", _BUILTIN_EXECUTORS)

__all__ = ["EXECUTORS", "Executor", "build_executor"]


def build_executor(source: str, path: Path) -> Executor | None:
    """The registered Executor for ``source``, or None when the source is observe-only."""
    factory = EXECUTORS.get(source)
    return factory(path) if factory is not None else None
