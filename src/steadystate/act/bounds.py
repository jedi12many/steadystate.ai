"""Action envelopes + the bound: one impact-and-reversibility calculus for *all* infrastructure.

The decision a good operator makes before any change is always the same two questions -- *how much
does this touch, and can I undo it?* -- and it does not depend on whether the change is a
`kubectl delete`, a `terraform apply`, or an ansible play. So that calculus lives here, once,
backend-agnostic: every action declares an ``Envelope`` (its reversibility and its blast radius on
a generic scale), and a human declares the **bound** -- which envelopes may run unattended. The
gate (``within_bounds``) sees only the envelope, never a backend.

What the bound governs today: the autonomous paths -- reflexes (``hold``), the decider
(``propose``), and the drift ``--autonomy auto`` path for any executor that declares an envelope
(terraform does; ``can_run_unattended`` in act/plan.py is the gate). An executor that has not yet
declared envelopes (ansible) falls back to the older ``eligible`` boolean -- the migration is
incremental, and absence of an envelope only keeps prior behavior, never loosens it. So this is on
its way to "one grid governs every source", and is honest that it is not all the way there yet.

This is the spine the autonomy story stands on. A reflex today, an LLM tomorrow, decides *what to
do*; the bound decides *how much it is ever allowed to break*. The decider proposes an action and
its envelope; the gate checks that envelope against the human's bound; out-of-bound escalates no
matter how confident the decider is. The one decision that never goes to the code or the model is
the bound itself -- a human sets it (the conservative default, widened via ``STEADYSTATE_BOUND`` as
trust grows), and flipping a reflex to ``auto`` can never cross it.

The two axes are deliberately generic; each backend maps its own nouns onto them:

    Impact         k8s              terraform              ansible            compose
    ------         ---              ---------              -------            -------
    ONE            a pod            one resource           one host/task      one container
    SERVICE        a workload       a module               a role             a service
    TENANT         a namespace      a workspace/state      an inventory group a project/stack
    NODE           a node           --                     a managed host     the docker host
    FLEET          the cluster      a root/account/region  the whole inventory the engine

    Reversibility  example
    -------------  -------
    LOSSLESS       destroys nothing of value (delete an evicted pod, `docker rm` a dead container)
    SELF_HEALING   the platform restores it (delete a Running pod, restart a service, cordon a node)
    RECOVERABLE    a known inverse exists (scale down<->up, a re-appliable terraform change)
    IRREVERSIBLE   real loss, no inverse (delete a PVC, `terraform destroy` a database)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import IntEnum

# Both axes are ordinal (IntEnum), worst last -- so a policy is just "the highest tier still
# allowed" and the gate is a comparison. Names render lowercased for humans; the order is the point.


class Reversibility(IntEnum):
    """Can the action be undone, and is anything of value lost if it can't? Ascending severity."""

    LOSSLESS = 0
    SELF_HEALING = 1
    RECOVERABLE = 2
    IRREVERSIBLE = 3


class Impact(IntEnum):
    """The blast radius on a generic, cross-backend scale (each backend maps its nouns). Rising."""

    ONE = 0
    SERVICE = 1
    TENANT = 2
    NODE = 3
    FLEET = 4


@dataclass(frozen=True)
class Envelope:
    """What an action would do, in the only two terms the bound cares about. Backend-agnostic: a
    kubectl cleanup, a terraform apply, and an ansible play all describe themselves this way."""

    reversibility: Reversibility
    impact: Impact

    @property
    def label(self) -> str:
        return f"{self.reversibility.name.lower()}/{self.impact.name.lower()}"


# The bound: for each reversibility, the HIGHEST impact tier that may run unattended (None = never).
# This is the human's 3am calculus, written down once. Conservative by default -- only a lossless or
# self-healing action, and only within a small blast radius, runs without a human; anything
# recoverable-or-worse, or anything reaching a node/the fleet, escalates. An operator widens it as
# trust grows (the same graduation `hold`'s reflexes use), but it is ALWAYS a human's decision: the
# bound is the one thing a decider -- reflex or model -- never sets for itself.
BoundPolicy = dict[Reversibility, "Impact | None"]

DEFAULT_BOUND: BoundPolicy = {
    Reversibility.LOSSLESS: Impact.TENANT,  # lossless, up to a whole tenant (namespace/stack): auto
    Reversibility.SELF_HEALING: Impact.SERVICE,  # self-healing up to one service -> auto
    Reversibility.RECOVERABLE: None,  # a known inverse still needs a human, until trust is earned
    Reversibility.IRREVERSIBLE: None,  # never autonomous, at any size
}


def within_bounds(envelope: Envelope, policy: BoundPolicy = DEFAULT_BOUND) -> bool:
    """True iff ``envelope`` may run unattended under ``policy`` -- the gate every decider passes
    through, seeing only the envelope, never a backend. Pure. ``False`` (escalate) is the safe
    default for any reversibility the policy doesn't permit."""
    ceiling = policy.get(envelope.reversibility)
    return ceiling is not None and envelope.impact <= ceiling


def confirmation_tier(envelope: Envelope, policy: BoundPolicy = DEFAULT_BOUND) -> int:
    """How much confirmation friction an action needs, from its envelope alone. ``0`` = within the
    bound -- autonomous-eligible, no confirmation (`fix`/`run` just runs it). Out of bound is
    break-glass: ``2`` (STRONG -- type the target's name to confirm) when it's IRREVERSIBLE or
    reaches a NODE/the FLEET; else ``1`` (light -- a plain confirm). So the most dangerous things
    get the most friction, automatically. Pure."""
    if within_bounds(envelope, policy):
        return 0
    if envelope.reversibility >= Reversibility.IRREVERSIBLE or envelope.impact >= Impact.NODE:
        return 2
    return 1


_REVERSIBILITY_BY_NAME = {r.name.lower(): r for r in Reversibility}
_IMPACT_BY_NAME = {i.name.lower(): i for i in Impact}


def _config_bound_table() -> dict:
    from ..config import config_table  # local import: keep bounds.py importable without the config

    return config_table("bound")


def _apply_bound_pair(policy: BoundPolicy, rev_name: str, impact_name: str) -> None:
    """Overlay one ``reversibility=impact`` decision onto ``policy`` (in place). An unknown
    reversibility or impact is **skipped**, never applied -- a typo can only leave the bound at the
    conservative default, never silently widen it ('never escalate on uncertainty')."""
    reversibility = _REVERSIBILITY_BY_NAME.get(rev_name.strip().lower())
    if reversibility is None:
        return
    impact = impact_name.strip().lower()
    if impact in ("none", "never", ""):
        policy[reversibility] = None  # explicitly forbid auto for this reversibility
    elif impact in _IMPACT_BY_NAME:
        policy[reversibility] = _IMPACT_BY_NAME[impact]
    # else: an unknown impact name -> skip (stay conservative; never widen on a typo)


def bound_from_env(raw: str | None = None) -> BoundPolicy:
    """The *active* bound: ``DEFAULT_BOUND`` overlaid with the committed ``[bound]`` table, then the
    ``STEADYSTATE_BOUND`` env knob (env wins). The widen/narrow dial every autonomy gate reads, so
    one source governs the whole tool: drift auto-apply, reflexes, solution auto-apply, the decider.

    The bound is the one decision that should never be casual -- so it belongs in the **committed
    config**, reviewed in PRs (`[bound]` with ``reversibility = "impact"`` keys), with the env var
    the per-run override. Reversibility names: ``lossless`` / ``self_healing`` / ``recoverable`` /
    ``irreversible``; impact names ``one`` / ``service`` / ``tenant`` / ``node`` / ``fleet`` (each
    pair names the HIGHEST impact tier that may run unattended for that reversibility; ``none``
    forbids it). Env format mirrors it: comma-separated ``reversibility=impact`` pairs, e.g.
    ``STEADYSTATE_BOUND="recoverable=service"``.

    Unparseable entries are skipped (never widen on a typo). Pure given ``raw``; with ``raw`` None
    it reads the committed ``[bound]`` table then ``STEADYSTATE_BOUND``."""
    policy = dict(DEFAULT_BOUND)
    if raw is None:  # the live resolution: committed config first (baseline), then env (override)
        for rev_name, impact in _config_bound_table().items():
            _apply_bound_pair(policy, rev_name, str(impact))
        raw = os.environ.get("STEADYSTATE_BOUND", "")
    for token in raw.replace(";", ",").split(","):
        key, sep, value = token.partition("=")
        if sep:  # a `reversibility=impact` pair (a bare token is skipped)
            _apply_bound_pair(policy, key, value)
    return policy
