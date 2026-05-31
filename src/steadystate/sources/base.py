"""The StateSource plugin seam.

Most sources enumerate declared Resources, which the reconciler diffs against
observed state. Some sources (Terraform, ArgoCD) reconcile natively and yield
Drift directly -- those implement DriftSource.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .._http import safe_urlopen
from ..model import Drift, Resource


class SourceError(RuntimeError):
    """A drift source's live tool failed -- a missing binary, a non-zero exit, a timeout, or
    unparseable output. Raised instead of leaking a raw subprocess/JSON traceback, so a caller can
    report the failure cleanly (a scan exits non-zero with a message; the listener replies with it)
    rather than crash. **Never** swallowed into an empty result: a drift source going silent would
    be a false "no drift" all-clear -- worse than a loud failure. (The symptom *probe* path may
    degrade to empty: absence of symptoms isn't a guarantee, but a drift scan's emptiness is.)"""


def run_tool(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
    tool: str | None = None,
) -> str:
    """Run a source's live tool with a hard ``timeout`` and return its stdout, converting every
    failure mode into a `SourceError` instead of a raw traceback: a missing binary, a non-zero exit
    (when ``check``), or a hang past ``timeout``. The timeout is the fix for "a hung `terraform
    plan` / `kubectl` blocks the scan forever". ``check=False`` for tools (ansible --check) that
    exit non-zero on a normal result we still parse."""
    name = tool or (argv[0] if argv else "tool")
    try:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            env=dict(env) if env is not None else None,
            check=check,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise SourceError(f"'{name}' not found on PATH -- is it installed?") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"'{name}' timed out after {timeout:g}s") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip().splitlines()
        detail = stderr[-1] if stderr else f"exit {exc.returncode}"
        raise SourceError(f"'{name}' failed: {detail}") from exc
    except OSError as exc:  # permissions, ENOMEM, ...
        raise SourceError(f"'{name}' failed: {exc}") from exc
    return result.stdout


def loads_json(text: str, *, tool: str) -> object:
    """``json.loads``, but an empty/garbage payload raises `SourceError` (a clean "produced no
    parseable JSON") rather than a bare ``JSONDecodeError``."""
    try:
        return json.loads(text or "")
    except json.JSONDecodeError as exc:
        raise SourceError(f"'{tool}' produced no parseable JSON output") from exc


def fetch_json(request: urllib.request.Request | str, *, timeout: float, tool: str) -> object:
    """GET + parse JSON from an HTTP(S) source through the gated opener, with a hard ``timeout`` and
    every failure converted to a clean `SourceError` -- the urllib parallel to `run_tool`. Covers a
    hung/unreachable server (no timeout = block forever), an HTTP error (401/500/...), and an
    unparseable body. ``request`` is a urllib Request so callers keep their auth headers; the URL
    scheme is http(s)-gated by `safe_urlopen` (a bad scheme raises ValueError before any socket)."""
    try:
        with safe_urlopen(request, timeout=timeout) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:  # a subclass of URLError -- catch it FIRST for the code
        raise SourceError(f"'{tool}' returned HTTP {exc.code} {exc.reason}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise SourceError(f"'{tool}' unreachable: {getattr(exc, 'reason', exc)}") from exc
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    return loads_json(text, tool=tool)


@dataclass(frozen=True)
class Capabilities:
    """A plugin's command manifest, split into two permission categories.

    - ``observe``: read-only commands the plugin runs to *collect* state. Pre-approved --
      steadystate may run these freely (they cannot change a deployment).
    - ``destructive``: potentially state-changing commands the plugin runs to *act*
      (remediate). These ALWAYS require permission before they run -- the approval gate.

    A plugin with no ``destructive`` commands is observe-only by declaration. Documenting
    both per plugin is the permission contract: an operator sees exactly what a plugin will
    run and which side of the approval line each command sits on -- and a hand-written plugin
    declares its own, so the boundary is the plugin's to define, not a central policy's.
    """

    observe: tuple[str, ...] = ()
    destructive: tuple[str, ...] = ()


@runtime_checkable
class StateSource(Protocol):
    name: str

    def collect_declared(self) -> list[Resource]: ...


@runtime_checkable
class DriftSource(Protocol):
    """A source that natively reconciles and yields Drift (e.g. `terraform plan`)."""

    name: str

    def collect_drift(self) -> list[Drift]: ...


@runtime_checkable
class ObservedSource(Protocol):
    """A source that enumerates OBSERVED resources (what is actually running), to be
    diffed against a StateSource's declared resources by reconcile()."""

    name: str

    def collect_observed(self) -> list[Resource]: ...
