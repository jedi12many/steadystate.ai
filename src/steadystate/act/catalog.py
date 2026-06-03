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

from collections.abc import Callable
from dataclasses import dataclass

from .bounds import Envelope
from .cleanup import CLEANUP_ENVELOPE, is_safe_cleanup


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
