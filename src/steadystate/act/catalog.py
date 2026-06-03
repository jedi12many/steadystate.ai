"""The trusted action catalog: the source of truth for *(action -> envelope)*.

This is the single rule that makes a proposer -- a deterministic decider today, an LLM tomorrow --
safe to put in the loop: it may choose *what* to do, but it can never assert *how much it is
allowed to break*. The envelope the bound gate reads is a property of the catalog entry, looked up
here, NEVER taken from the proposer. And a proposer may only name an action that exists here, whose
concrete command must pass that entry's validator (the same allow-pattern discipline the cleanup
uses). So the worst a hallucinating model can do is name a vetted, bounded action with a command
that gets re-validated -- it cannot widen its own blast radius or smuggle an un-vetted command.

The catalog is small on purpose. It grows by *adding vetted actions*, each with a human-set
envelope -- and every decider's reach grows with it, always inside the bound. (Today it holds the
one action steadystate fully possesses: the evicted-pod cleanup.)
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .bounds import Envelope, Impact, Reversibility
from .cleanup import CLEANUP_ENVELOPE, is_safe_cleanup

# -- per-action command allow-patterns ---------------------------------------------------------
# Each is anchored (^...$) and character-classed so no alternate verb, extra flag, selector, or
# shell metacharacter can slip through: the regex IS the action's blast-radius guarantee. Two rules
# every k8s entry follows: pin EXACTLY ONE namespace (`-n <ns>` -- never `-A`/`--all-namespaces`,
# the difference between one tenant and the whole fleet), and forbid `--all`/selectors (which would
# silently widen the impact the envelope claims). Re-checked at the gate (decide.gate_proposal).

# delete Succeeded (completed) pod tombstones in one namespace -- lossless, like the evicted clean.
_SAFE_COMPLETED_CLEANUP = re.compile(
    r"^kubectl delete pods(?: -n [\w.-]+)? "
    r"--field-selector=status\.phase=Succeeded(?: --context [\w.@:/-]+)?$"
)

# rollout-restart ONE workload in one namespace. The `<controller>/<name>` shape is the safety: the
# command can only target a Deployment / StatefulSet / DaemonSet (all controllers that recreate
# their pods, no data loss -- a StatefulSet's PVCs persist across a restart), so the restart is
# self-healing BY CONSTRUCTION -- a bare pod can't be named, so the envelope can't be lied into.
_SAFE_ROLLOUT_RESTART = re.compile(
    r"^kubectl rollout restart (?:deployment|statefulset|daemonset)/[\w.-]+ "
    r"-n [\w.-]+(?: --context [\w.@:/-]+)?$"
)


def is_safe_completed_cleanup(command: str) -> bool:
    """True iff ``command`` is exactly the Succeeded-phase pod cleanup shape. Pure."""
    return bool(_SAFE_COMPLETED_CLEANUP.match(command.strip()))


def is_safe_rollout_restart(command: str) -> bool:
    """True iff ``command`` is exactly a single-workload, single-namespace rollout restart of a
    Deployment / StatefulSet / DaemonSet. Pure. The `<controller>/<name>` shape guarantees the
    target is a self-healing controller, never a bare pod."""
    return bool(_SAFE_ROLLOUT_RESTART.match(command.strip()))


@dataclass(frozen=True)
class CatalogAction:
    """One vetted action a decider may propose. ``envelope`` is the TRUSTED blast-radius +
    reversibility the bound is checked against (never the proposer's word); ``validate`` is the
    command allow-pattern (defense against a proposer emitting a malformed/injected command);
    ``description`` is shown to a human and to the model, so the LLM knows when it applies."""

    name: str
    envelope: Envelope  # trusted -- the bound reads this, not the proposer
    validate: Callable[[str], bool]  # the command allow-pattern (re-checked at gate time)
    description: str


_BUILTIN_ACTIONS: tuple[CatalogAction, ...] = (
    CatalogAction(
        name="reclaim-evicted-pods",
        envelope=CLEANUP_ENVELOPE,  # lossless / tenant
        validate=is_safe_cleanup,
        description=(
            "delete Evicted (Failed-phase) pod tombstones in one namespace -- for a workload whose "
            "pods were evicted by node memory/disk pressure. Lossless: the pods are already dead. "
            "Command shape: kubectl delete pods -n <ns> --field-selector=status.phase=Failed "
            "[--context <ctx>]"
        ),
    ),
    CatalogAction(
        name="delete-completed-pods",
        # Succeeded-phase pods are finished work (a Job's pods, a one-shot) -- deleting the
        # tombstones destroys nothing of value, in one namespace. Same envelope as the evicted one.
        envelope=Envelope(Reversibility.LOSSLESS, Impact.TENANT),
        validate=is_safe_completed_cleanup,
        description=(
            "delete Succeeded (completed) pod tombstones in one namespace -- finished Job/one-shot "
            "pods piling up. Lossless: the work is done, nothing running is touched. Command "
            "shape: kubectl delete pods -n <ns> --field-selector=status.phase=Succeeded "
            "[--context <ctx>]"
        ),
    ),
    CatalogAction(
        name="rollout-restart-workload",
        # A rolling restart is controller-managed and data-safe (the platform brings new pods up,
        # honoring surge/maxUnavailable / StatefulSet ordering; PVCs persist) -> self-healing; it
        # touches one workload -> service. The `<controller>/<name>` command shape guarantees the
        # target is a Deployment/StatefulSet/DaemonSet, so this envelope can never be applied to a
        # non-self-healing resource (e.g. a bare pod).
        envelope=Envelope(Reversibility.SELF_HEALING, Impact.SERVICE),
        validate=is_safe_rollout_restart,
        description=(
            "roll-restart ONE workload (Deployment / StatefulSet / DaemonSet) in one namespace -- "
            "for a workload wedged in a way a fresh set of pods clears (a stuck rollout, a leaked "
            "connection/cache), NOT a CrashLoopBackOff (restarting a crash loop just loops again "
            "-- that needs a real fix). Self-healing: the controller manages it, no data loss. "
            "Command shape: kubectl rollout restart <deployment|statefulset|daemonset>/<name> "
            "-n <ns> [--context <ctx>]"
        ),
    ),
)

ACTIONS: dict[str, CatalogAction] = {a.name: a for a in _BUILTIN_ACTIONS}


def catalog_action(name: str) -> CatalogAction | None:
    """The vetted action named ``name``, or None when no such action exists -- the lookup the gate
    uses to reject a proposer that names something not in the catalog."""
    return ACTIONS.get(name)


def catalog_menu() -> str:
    """The catalog rendered for a model prompt: each action's name + description, so the LLM can
    only ever pick from the vetted menu (and is told the exact command shape to fill)."""
    return "\n".join(f"- {a.name}: {a.description}" for a in _BUILTIN_ACTIONS)
