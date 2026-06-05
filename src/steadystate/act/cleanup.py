"""Evicted-pod cleanup: a guardrailed, command-based remediation for a health Symptom.

A drift remediation rebuilds an executor and reconciles declared vs observed. An evicted-pod
cleanup is different: there is no declared/observed divergence, just dead tombstones to delete --
so the kubectl probe already composed the exact, safe `kubectl delete` (see kubectl._fix_for). We
record it as a PendingAction with a sentinel ``source`` and run it through the SAME approve
guardrail every drift remediation uses: claimed once (no double-run), recorded to the append-only
audit log, and -- crucially -- **re-validated against a strict allow-pattern at run time**, so the
tool can only ever delete pods a human approved, and only with the one cleanup shape we generate
(never an arbitrary command, even if the stored action were tampered with).
"""

from __future__ import annotations

import re
import shlex
import subprocess
from datetime import datetime

from ..state import PendingAction, StateStore
from .base import RemediationResult
from .bounds import Envelope, Impact, Reversibility
from .plan import RemediationPlan, Risk

# The evicted-pod cleanup's envelope: it deletes already-dead (Evicted/Failed) pods in one
# namespace -- nothing of value is destroyed (lossless), and the blast radius is one tenant. The
# bound (act/bounds.py) reads this; the SAME calculus governs it as governs a terraform apply.
CLEANUP_ENVELOPE = Envelope(Reversibility.LOSSLESS, Impact.TENANT)

# The sentinel ``source`` that marks a PendingAction as a direct cleanup command rather than a
# drift remediation -- ``apply_pending`` routes on it. Not a real DriftSource (no executor).
CLEANUP_SOURCE = "kubectl-cleanup"

# The ONE command shape we will execute: the evicted/Failed-phase pod cleanup the probe composes.
# Anchored + character-classed so no shell metacharacter or alternate verb can slip through -- the
# namespace and context are k8s-validated names. Re-checked at run time (defense in depth).
# --context / --kubeconfig tails shared by every k8s action allow-pattern. Both are a SINGLE
# token with a constrained char class (no spaces, no shell metacharacters -- and we run argv with
# no shell anyway), so a context name or a kubeconfig path can ride along but nothing can be
# chained/injected. The kubeconfig path allows `/ . ~` (paths) on top of the context's char set.
_CONTEXT_TAIL = r"(?: --context [\w.@:/-]+)?"
_KUBECONFIG_TAIL = r"(?: --kubeconfig [\w.@:/~-]+)?"

# -- the flexible, injection-proof command checker shared by every k8s allow-pattern -------------
# The old allow-patterns were rigid positional regexes -- the flags had to appear in one exact
# order, so a command that did EXACTLY the safe thing but wrote `-n ns` before `--replicas=0` was
# rejected on a technicality (and an LLM proposer, which doesn't memorise arg order, kept tripping
# it). `safe_kubectl` instead TOKENISES and matches order-independently: the fixed verb, an optional
# single positional, the required valued flags, and only the allowed -n/--context/--kubeconfig --
# rejecting any unknown/extra/duplicate token or shell metacharacter. So the SHAPE can vary but the
# command can never do anything but the one vetted operation. Flexible on shape, sure on safety.

# A flag value is a k8s name, a context, or a kubeconfig path -- never a shell construct.
_NSNAME = re.compile(r"^[\w.-]+$")  # namespace / resource name
_CONTEXT_VAL = re.compile(r"^[\w.@:/-]+$")
_KUBECONFIG_VAL = re.compile(r"^[\w.@:/~-]+$")
# Any of these in the raw string -> reject outright (chaining / redirection / expansion / globbing).
# A vetted command is plain tokens; none of its values need any of these, and we exec argv with no
# shell anyway -- this just refuses to even validate an injected string.
_SHELL_META = ";&|`$<>(){}[]*?!\\'\"\n\r\t"


def _value_ok(flag: str, value: str | None) -> bool:
    if value is None:
        return False
    if flag in ("-n", "--namespace"):
        return bool(_NSNAME.match(value))
    if flag == "--context":
        return bool(_CONTEXT_VAL.match(value))
    if flag == "--kubeconfig":
        return bool(_KUBECONFIG_VAL.match(value))
    return False


def safe_kubectl(
    command: str,
    *,
    verb: tuple[str, ...],
    positional: re.Pattern[str] | None = None,
    required: tuple[tuple[str, str], ...] = (),
    namespace: str = "optional",
) -> bool:
    """Flexible, injection-proof check that ``command`` is EXACTLY one vetted kubectl operation.

    Matches order-INDEPENDENTLY: the fixed ``verb`` prefix, an optional single ``positional`` (e.g.
    ``deployment/<name>``), the ``required`` valued flags (each a ``(name, exact_value)`` accepted
    as ``--k=v`` OR ``--k v``), and only the always-allowed ``-n/--namespace``, ``--context`` and
    ``--kubeconfig``. ANY unknown / extra / out-of-place token, or shell metacharacter, is False.
    ``namespace`` is "optional" | "required" | "forbidden". Pure; the run-time security gate."""
    if any(c in _SHELL_META for c in command):
        return False
    toks = command.split()
    if tuple(toks[: len(verb)]) != verb:
        return False
    rest, req = toks[len(verb) :], dict(required)
    seen_required: set[str] = set()
    seen_ns = False
    got_positional = positional is None
    i = 0
    while i < len(rest):
        tok = rest[i]
        key, has_eq, inline = tok.partition("=")
        value = inline if has_eq else (rest[i + 1] if i + 1 < len(rest) else None)
        is_positional = (
            not got_positional
            and not tok.startswith("-")
            and positional is not None
            and bool(positional.match(tok))
        )
        if key in req:
            if value != req[key]:
                return False
            seen_required.add(key)
        elif key in ("-n", "--namespace", "--context", "--kubeconfig"):
            if not _value_ok(key, value):
                return False
            seen_ns = seen_ns or key in ("-n", "--namespace")
        elif is_positional:
            got_positional = True
            i += 1
            continue
        else:
            return False  # unknown / extra / out-of-place token
        i += 1 if has_eq else 2
    if not got_positional or set(req) - seen_required:
        return False
    if namespace == "required" and not seen_ns:
        return False
    return not (namespace == "forbidden" and seen_ns)


def is_safe_cleanup(command: str) -> bool:
    """True iff ``command`` is exactly the evicted-pod cleanup we generate -- the only thing approve
    will run on the cleanup path. Pure; the security gate for command execution."""
    return safe_kubectl(
        command,
        verb=("kubectl", "delete", "pods"),
        required=(("--field-selector", "status.phase=Failed"),),
    )


def record_cleanups(store: StateStore, report, now: datetime) -> int:
    """Record an approvable cleanup (a PendingAction keyed by the symptom's fingerprint) for every
    evicted Symptom that carries a safe fix -- so it shows in `pending` and `approve <fp>` runs it.
    Idempotent (record_pending upserts by fingerprint). Returns how many were recorded.

    Never auto-runs: it only *offers* the cleanup. (The `--autonomy auto` path applies eligible
    *drift* fingerprints, which this is not -- so a cleanup always waits for an approve.)"""
    recorded = 0
    for alert in report.alerts:
        for symptom in alert.symptoms:
            action = symptom.recommended_action
            if action and is_safe_cleanup(action):
                store.record_pending(
                    PendingAction(
                        fingerprint=symptom.fingerprint,
                        source=CLEANUP_SOURCE,
                        path="",
                        drift_identity=symptom.identity,
                        command=action,
                    ),
                    now,
                )
                recorded += 1
    return recorded


def run_cleanup(action: PendingAction, *, timeout: float = 30.0) -> RemediationResult:
    """Run an approved evicted-pod cleanup. Re-validates the command against the allow-pattern first
    (refuses anything else), then runs it as an argv list (no shell), with a timeout. Returns a
    RemediationResult the audit log records. Best-effort: a failed delete is reported, not raised.
    """
    plan = RemediationPlan(
        drift_identity=action.drift_identity,
        eligible=True,
        risk=Risk.LOW,  # deleting dead (Evicted/Failed) tombstones -- nothing running is touched
        reason="evicted-pod cleanup",
        command=shlex.split(action.command),
        blast_radius="deletes Failed-phase (evicted) pods in the namespace",
        revert="none -- the deleted pods were already dead (Evicted)",
        envelope=CLEANUP_ENVELOPE,
    )
    if not is_safe_cleanup(action.command):  # defense in depth: never run an unrecognized command
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"refused: not a recognized cleanup command ({action.command!r}).",
        )
    try:
        proc = subprocess.run(  # noqa: S603 -- argv list (no shell), command allow-pattern-validated
            plan.command, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return RemediationResult(
            plan=plan, applied=False, verified=False, detail=f"cleanup failed: {exc}"
        )
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout or "").strip()[:200]
        return RemediationResult(
            plan=plan,
            applied=False,
            verified=False,
            detail=f"cleanup failed (exit {proc.returncode}): {why}",
        )
    out = (proc.stdout or "").strip()[:200]
    return RemediationResult(
        plan=plan, applied=True, verified=True, detail=f"cleaned up evicted pods. {out}".strip()
    )
