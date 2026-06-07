"""Function-first triage: is a finding something actually FAILING, or just diverged/imperfect?

The operator's rule (and the agent's): *don't chase red herrings.* A config drift, or a posture nit,
on a workload that's doing its job is **NOTED** -- context, not a call to action. Only a live
malfunction is **IMPAIRED** -- worth attention, worth your (or an agent's) time. This split is what
lets a glance lead with "is it working?" instead of a pile of findings, and what keeps the model
from proposing changes to things that aren't broken.

Read deterministically from a finding's stored shape -- because the three finding kinds record
differently: a **drift** carries a ``change`` type (REMOVED/MODIFIED/ADDED); a **live symptom** (a
probe failure, a failed custom check) carries structured evidence (namespace, the failure category,
the failing signal) and no ``change``; a **posture/policy** finding carries no evidence. So:
evidence + no change -> impaired; a ``change`` -> noted (drift); nothing -> noted (posture)."""

from __future__ import annotations

from collections.abc import Mapping

IMPAIRED = (
    "impaired"  # a live malfunction -- the thing isn't doing its job (a symptom / failed check)
)
NOTED = "noted"  # config drift or posture -- diverged/imperfect, but not a live failure


def finding_disposition(details: Mapping[str, str] | None) -> str:
    """``IMPAIRED`` iff a finding is a live malfunction; ``NOTED`` for config drift / posture. A
    drift records a ``change`` type, a live symptom records evidence (and no change), a posture
    finding records none. The safe default is ``NOTED`` -- we don't call something broken unless it
    carries the evidence of a live failure, so a glance never cries wolf over a red herring."""
    d = details or {}
    if not d:
        return NOTED  # no evidence -> a posture/policy finding (or nothing to place) -> noted
    if "change" in d:
        return NOTED  # a config drift -- diverged from declared, not a live failure
    return IMPAIRED  # probe/check evidence with no change -> a live symptom -> impaired


# The one-word "is it working?" verdict, leading with the strongest signal. A FAILED smoke test
# means the service actively isn't serving (DOWN); a live malfunction with smoke passing means it's
# up but hurting (DEGRADED); otherwise WORKING. The smoke test dominates -- proof beats inference.
WORKING = "WORKING"
DEGRADED = "DEGRADED"
DOWN = "DOWN"


def wall_verdict(impaired: int, smoke_failures: int) -> str:
    """Combine the active smoke result + the passive impaired count into one verdict. A smoke
    failure -> DOWN (actively not working); malfunctions but smoke ok -> DEGRADED; else WORKING."""
    if smoke_failures:
        return DOWN
    if impaired:
        return DEGRADED
    return WORKING
