"""Break-glass: who may override the bound, and the sentinel that marks a pending one.

The bound restrains the *autonomous* path -- the code and the LLM. A human can deliberately run an
action *outside* the bound (scale a service to zero, delete a node), but only under friction and
only if they're authorized. This module is the authorization gate; the friction (a plain confirm
vs. typing the target's name) is decided by the envelope (``bounds.confirmation_tier``), and the
shape is still a vetted catalog action -- break-glass overrides the bound, never the allow-pattern.

**Default-CLOSED.** ``STEADYSTATE_BREAKGLASS_USERS`` is a comma list of operators allowed to issue
and confirm break-glass. Unset/empty = *nobody* -- break-glass is off until someone names the
authorized people (who'd already have cluster access). The signed inbound webhook is the OUTER
boundary (only verified operators reach the listener at all); this allowlist is the INNER gate on
who, among them, may override the bound -- so the most dangerous capability is opt-in, attributable.
"""

from __future__ import annotations

import os

# The sentinel ``source`` marking a PendingAction as an awaiting-confirmation break-glass command --
# ``apply_pending`` routes on it (confirm + run with the bound overridden, audited as BREAKGLASS).
BREAKGLASS_SOURCE = "kubectl-breakglass"

_USERS_ENV = "STEADYSTATE_BREAKGLASS_USERS"


def breakglass_users() -> set[str]:
    """The operators authorized to break-glass, from ``STEADYSTATE_BREAKGLASS_USERS`` (comma list).
    Empty when unset -- the default-closed posture. Pure given the env."""
    return {u.strip() for u in os.environ.get(_USERS_ENV, "").split(",") if u.strip()}


def breakglass_allowed(actor: str) -> bool:
    """Whether ``actor`` may issue/confirm a break-glass action. Default-CLOSED: an empty allowlist
    permits nobody, so break-glass stays off until it's deliberately enabled for named operators."""
    return actor in breakglass_users()
