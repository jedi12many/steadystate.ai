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
from .cleanup import _CONTEXT_TAIL, _KUBECONFIG_TAIL, CLEANUP_ENVELOPE, is_safe_cleanup

# -- per-action command allow-patterns ---------------------------------------------------------
# Each is anchored (^...$) and character-classed so no alternate verb, extra flag, selector, or
# shell metacharacter can slip through: the regex IS the action's blast-radius guarantee. Two rules
# every k8s entry follows: pin EXACTLY ONE namespace (`-n <ns>` -- never `-A`/`--all-namespaces`,
# the difference between one tenant and the whole fleet), and forbid `--all`/selectors (which would
# silently widen the impact the envelope claims). Re-checked at the gate (decide.gate_proposal).

# delete Succeeded (completed) pod tombstones in one namespace -- lossless, like the evicted clean.
_SAFE_COMPLETED_CLEANUP = re.compile(
    r"^kubectl delete pods(?: -n [\w.-]+)? "
    r"--field-selector=status\.phase=Succeeded" + _CONTEXT_TAIL + _KUBECONFIG_TAIL + r"$"
)

# rollout-restart ONE workload in one namespace. The `<controller>/<name>` shape is the safety: the
# command can only target a Deployment / StatefulSet / DaemonSet (all controllers that recreate
# their pods, no data loss -- a StatefulSet's PVCs persist across a restart), so the restart is
# self-healing BY CONSTRUCTION -- a bare pod can't be named, so the envelope can't be lied into.
_SAFE_ROLLOUT_RESTART = re.compile(
    r"^kubectl rollout restart (?:deployment|statefulset|daemonset)/[\w.-]+ "
    r"-n [\w.-]+" + _CONTEXT_TAIL + _KUBECONFIG_TAIL + r"$"
)


def is_safe_completed_cleanup(command: str) -> bool:
    """True iff ``command`` is exactly the Succeeded-phase pod cleanup shape. Pure."""
    return bool(_SAFE_COMPLETED_CLEANUP.match(command.strip()))


def is_safe_rollout_restart(command: str) -> bool:
    """True iff ``command`` is exactly a single-workload, single-namespace rollout restart of a
    Deployment / StatefulSet / DaemonSet. Pure. The `<controller>/<name>` shape guarantees the
    target is a self-healing controller, never a bare pod."""
    return bool(_SAFE_ROLLOUT_RESTART.match(command.strip()))


# -- break-glass shapes (OUT of the autonomous bound -- human-only, friction-gated) -------------
# These are vetted shapes like every other catalog entry, but their envelopes are outside the
# default bound, so `fix`/`run` won't run them autonomously -- only an authorized human can, through
# the break-glass confirmation. They are NOT offered (no `categories`): you must name one.

# scale a workload to zero replicas -- take a misbehaving service offline. Recoverable (scale back
# up) but out of bound (RECOVERABLE never auto), so it's a light-tier break-glass.
_SAFE_SCALE_TO_ZERO = re.compile(
    r"^kubectl scale (?:deployment|statefulset)/[\w.-]+ --replicas=0 "
    r"-n [\w.-]+" + _CONTEXT_TAIL + _KUBECONFIG_TAIL + r"$"
)

# delete ONE node -- the canonical break-glass: irreversible, node-scope. The bare `node <name>`
# shape (no `-n`, no selector) can target only a single named node.
_SAFE_DELETE_NODE = re.compile(
    r"^kubectl delete node [\w.-]+" + _CONTEXT_TAIL + _KUBECONFIG_TAIL + r"$"
)


def is_safe_scale_to_zero(command: str) -> bool:
    """True iff ``command`` is exactly a scale-to-zero of one Deployment/StatefulSet in one ns."""
    return bool(_SAFE_SCALE_TO_ZERO.match(command.strip()))


def is_safe_delete_node(command: str) -> bool:
    """True iff ``command`` is exactly a single-node delete. Pure."""
    return bool(_SAFE_DELETE_NODE.match(command.strip()))


# -- composing a command from a finding's stored keys ------------------------------------------


@dataclass(frozen=True)
class FindingFields:
    """The keys a stored finding supplies for composing a command -- its evidence (kind / workload
    name / namespace / cluster-context) plus the kubeconfig resolved from its target. Whatever the
    finding doesn't carry is empty; a ``compose`` returns None when a key it needs is missing, and
    the composed command is re-validated by the action's allow-pattern anyway (defense in depth)."""

    kind: str = ""
    name: str = ""
    namespace: str = ""
    context: str = ""
    kubeconfig: str = ""


def _tail(fields: FindingFields) -> str:
    """The `--context`/`--kubeconfig` suffix common to every composed command -- so a finding on a
    discovered (cwd-kubeconfig) cluster is reachable."""
    tail = ""
    if fields.context:
        tail += f" --context {fields.context}"
    if fields.kubeconfig:
        tail += f" --kubeconfig {fields.kubeconfig}"
    return tail


_RESTARTABLE_KINDS = frozenset({"deployment", "statefulset", "daemonset"})


def _compose_rollout_restart(f: FindingFields) -> str | None:
    kind = f.kind.lower()
    if kind not in _RESTARTABLE_KINDS or not f.name or not f.namespace:
        return None  # only a controller we can roll-restart; a bare pod / missing key -> no command
    return f"kubectl rollout restart {kind}/{f.name} -n {f.namespace}" + _tail(f)


def _compose_evicted(f: FindingFields) -> str | None:
    if not f.namespace:
        return None
    return f"kubectl delete pods -n {f.namespace} --field-selector=status.phase=Failed" + _tail(f)


def _compose_completed(f: FindingFields) -> str | None:
    if not f.namespace:
        return None
    return f"kubectl delete pods -n {f.namespace} --field-selector=status.phase=Succeeded" + _tail(
        f
    )


_SCALABLE_KINDS = frozenset({"deployment", "statefulset"})


def _compose_scale_to_zero(f: FindingFields) -> str | None:
    kind = f.kind.lower()
    if kind not in _SCALABLE_KINDS or not f.name or not f.namespace:
        return None
    return f"kubectl scale {kind}/{f.name} --replicas=0 -n {f.namespace}" + _tail(f)


def _compose_delete_node(f: FindingFields) -> str | None:
    if not f.name:  # the node name -- a node finding stores it; nothing else here is needed
        return None
    return f"kubectl delete node {f.name}" + _tail(f)


# The pod-malfunction categories a workload *recycle* recovers (after a human has fixed the root
# cause -- a corrected secret/config, a cleared dependency). NOT Evicted (that's a cleanup) and NOT
# the node categories (a restart can't fix a full disk). The kubectl probe's waiting reasons + the
# log-scan `Erroring`.
_RESTART_CATEGORIES = frozenset(
    {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerConfigError",
        "CreateContainerError",
        "RunContainerError",
        "Erroring",
    }
)


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
    # The Symptom categories this action is the OFFERED fix for -- what `fix <fp>` applies for a
    # finding of that category. Empty = not auto-offered (you can still `run` it explicitly).
    categories: frozenset[str] = frozenset()
    # Build the concrete command from a finding's stored keys (FindingFields), or None when a key it
    # needs is missing / the finding isn't a fit. The output is re-validated by ``validate``.
    compose: Callable[[FindingFields], str | None] | None = None


_BUILTIN_ACTIONS: tuple[CatalogAction, ...] = (
    CatalogAction(
        name="reclaim-evicted-pods",
        envelope=CLEANUP_ENVELOPE,  # lossless / tenant
        validate=is_safe_cleanup,
        categories=frozenset({"Evicted"}),
        compose=_compose_evicted,
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
        # Succeeded pods aren't a health *finding* (nothing's wrong) -- no auto-offer; `run` it.
        compose=_compose_completed,
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
        categories=_RESTART_CATEGORIES,
        compose=_compose_rollout_restart,
        description=(
            "roll-restart ONE workload (Deployment / StatefulSet / DaemonSet) in one namespace -- "
            "for a workload wedged in a way a fresh set of pods clears (a stuck rollout, a leaked "
            "connection/cache), NOT a CrashLoopBackOff (restarting a crash loop just loops again "
            "-- that needs a real fix). Self-healing: the controller manages it, no data loss. "
            "Command shape: kubectl rollout restart <deployment|statefulset|daemonset>/<name> "
            "-n <ns> [--context <ctx>]"
        ),
    ),
    # -- break-glass: OUT of the bound, human-only, never auto-offered (empty categories) --------
    CatalogAction(
        name="scale-to-zero",
        # Recoverable (scale back up) but out of bound -> a light-tier break-glass: take a
        # misbehaving Deployment/StatefulSet offline. One workload -> service.
        envelope=Envelope(Reversibility.RECOVERABLE, Impact.SERVICE),
        validate=is_safe_scale_to_zero,
        compose=_compose_scale_to_zero,
        description=(
            "BREAK-GLASS: scale ONE Deployment/StatefulSet to zero replicas -- take a misbehaving "
            "service offline. Recoverable (scale it back up), but out of the bound, so it needs a "
            "human confirmation. Command shape: kubectl scale <deployment|statefulset>/<name> "
            "--replicas=0 -n <ns> [--context <ctx>]"
        ),
    ),
    CatalogAction(
        name="delete-node",
        # The canonical break-glass: irreversible, node-scope -> the strong tier (type the node
        # name to confirm). The bare `node <name>` shape can only ever name a single node.
        envelope=Envelope(Reversibility.IRREVERSIBLE, Impact.NODE),
        validate=is_safe_delete_node,
        compose=_compose_delete_node,
        description=(
            "BREAK-GLASS: delete ONE node from the cluster (its pods reschedule elsewhere). "
            "Irreversible and node-scope, so it needs a strong confirmation -- you type the node "
            "name back. Command shape: kubectl delete node <name> [--context <ctx>]"
        ),
    ),
)

ACTIONS: dict[str, CatalogAction] = {a.name: a for a in _BUILTIN_ACTIONS}


def catalog_action(name: str) -> CatalogAction | None:
    """The vetted action named ``name``, or None when no such action exists -- the lookup the gate
    uses to reject a proposer that names something not in the catalog."""
    return ACTIONS.get(name)


def offered_action(category: str) -> CatalogAction | None:
    """The vetted action steadystate OFFERS as the fix for a finding of ``category`` -- what
    `fix <fp>` applies. None when no catalog action recovers that category (so `fix` says
    'no automated fix -- escalate' rather than guessing). Pure."""
    return next((a for a in _BUILTIN_ACTIONS if category in a.categories), None)


def action_for_command(command: str) -> CatalogAction | None:
    """The vetted action whose allow-pattern accepts ``command`` -- the run-time lookup the generic
    runner uses to know which envelope a stored command belongs to (and to refuse a command no
    vetted action recognizes). At most one matches (the patterns are disjoint shapes). Pure."""
    return next((a for a in _BUILTIN_ACTIONS if a.validate(command)), None)


def catalog_menu() -> str:
    """The catalog rendered for a model prompt: each action's name + description, so the LLM can
    only ever pick from the vetted menu (and is told the exact command shape to fill)."""
    return "\n".join(f"- {a.name}: {a.description}" for a in _BUILTIN_ACTIONS)
