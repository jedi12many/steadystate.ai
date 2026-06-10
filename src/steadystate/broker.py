"""Credential brokering: mint a short-lived credential at probe time, hold it only that long.

The long-running half of ``examples/brokered-creds``. A pre-launch wrapper re-brokers per *run*,
which fits cron -- but a long-running process (`up`, the MCP server) holds whatever credential it
launched with, so a short-lived kubeconfig expires mid-session while the listener keeps answering.
This seam closes that: a target may name a **broker command** (``kubeconfig_from`` in the targets
registry) whose stdout IS a fresh kubeconfig. It runs at probe time; the output lands in a private
temp file passed to that one probe; the file is deleted the moment the probe finishes. The
credential never outlives the probe that used it, and the *standing* secret (the vault token, the
API key) never touches steadystate at all -- it lives in the broker CLI's own auth.

The command is operator intent -- committed and reviewed in the targets registry like everything
else -- and it runs under the same discipline as an authored solution: an argv via ``shlex.split``,
**no shell** (no pipes/redirection -- wrap those in a script), with a timeout. Failure is CLOSED
and quiet about the secret: a failed broker raises with the exit code and the command's *stderr*,
never its stdout (stdout is the credential), and the probe simply doesn't run -- steadystate never
probes on a stale or half-brokered credential.

Rent the vault, don't rebuild it: the broker is whatever CLI your shop already trusts --
``vault kv get``, ``akeyless get-secret-value``, a ``rancher``/``gcloud`` one-liner, or your own
script. steadystate only runs it, uses the result, and forgets it.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

from .targets import Target

BROKER_TIMEOUT_ENV = "STEADYSTATE_BROKER_TIMEOUT"
_DEFAULT_TIMEOUT = 30.0  # seconds -- a vault round-trip, not a deploy
_STDERR_CLIP = 400  # how much broker stderr a failure message carries


class BrokerError(RuntimeError):
    """A broker command failed -- the target must NOT be probed (fail closed). The message is
    human-readable and secret-free: it may quote the command and its stderr, never its stdout."""


def _timeout() -> float:
    raw = os.environ.get(BROKER_TIMEOUT_ENV, "").strip()
    try:
        return float(raw) if raw else _DEFAULT_TIMEOUT
    except ValueError:
        return _DEFAULT_TIMEOUT


def _broker_output(command: str, target_name: str) -> str:
    """Run one broker command and return its stdout (the fresh credential). Raises
    :class:`BrokerError` -- naming the target, the exit code, and clipped *stderr* only -- on a
    missing binary, a non-zero exit, a timeout, or output that isn't kubeconfig-shaped (a vault
    error message must never be handed to kubectl as a credential)."""
    argv = shlex.split(command)
    if not argv:
        raise BrokerError(f"target '{target_name}': kubeconfig_from is empty")
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list (no shell); operator-authored intent
            argv, capture_output=True, text=True, timeout=_timeout()
        )
    except FileNotFoundError:
        raise BrokerError(
            f"target '{target_name}': broker command not found: '{argv[0]}' -- is the CLI "
            "installed and on PATH?"
        ) from None
    except subprocess.TimeoutExpired:
        raise BrokerError(
            f"target '{target_name}': broker command timed out after {_timeout():g}s "
            f"({BROKER_TIMEOUT_ENV} raises it)"
        ) from None
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()[:_STDERR_CLIP]
        detail = f" -- {stderr}" if stderr else ""
        raise BrokerError(
            f"target '{target_name}': broker command failed (exit {proc.returncode}){detail}"
        )
    credential = proc.stdout or ""
    # Sanity: a kubeconfig (YAML or JSON) always names `clusters`. Without this, a broker that
    # prints an error/JSON envelope to stdout and exits 0 would be handed to kubectl as creds.
    if "clusters" not in credential:
        raise BrokerError(
            f"target '{target_name}': broker output doesn't look like a kubeconfig (no "
            "'clusters' key) -- the command's stdout must be the kubeconfig itself; wrap any "
            "unwrapping (e.g. a JSON field) in a script."
        )
    return credential


@contextlib.contextmanager
def target_credentials(target: Target) -> Iterator[str]:
    """The kubeconfig path a probe of ``target`` should use, valid for the ``with`` body only.

    Without ``kubeconfig_from`` this is just the target's static ``kubeconfig`` (possibly empty =
    the ambient one) -- zero new behavior. With it, the broker runs NOW, the fresh credential is
    written to a private temp file (0600 where the OS honors it), and the file is **deleted on
    exit** -- success or failure -- so the credential's life is exactly one probe."""
    if not target.kubeconfig_from:
        yield target.kubeconfig
        return
    credential = _broker_output(target.kubeconfig_from, target.name)
    fd, raw = tempfile.mkstemp(prefix=f"steadystate-{target.name}-", suffix=".kubeconfig")
    path = Path(raw)
    try:
        os.write(fd, credential.encode("utf-8"))
        os.close(fd)
        with contextlib.suppress(OSError):  # best-effort on platforms with no POSIX modes
            path.chmod(0o600)
        yield str(path)
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
