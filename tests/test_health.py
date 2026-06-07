"""Function-first disposition: a live malfunction (IMPAIRED) vs config drift / posture (NOTED).
The whole point is 'don't chase red herrings' -- only a finding carrying live failure evidence is
impaired; a drift (a `change`) or an evidence-less posture finding is merely noted."""

from __future__ import annotations

from steadystate.health import IMPAIRED, NOTED, finding_disposition


def test_a_live_symptom_with_evidence_is_impaired():
    # a probe failure / failed custom check records structured evidence and no `change`
    assert (
        finding_disposition({"category": "CrashLoopBackOff", "namespace": "akeyless"}) == IMPAIRED
    )
    assert (
        finding_disposition({"found": "False", "matched_pods": "3"}) == IMPAIRED
    )  # a custom check


def test_a_config_drift_is_noted_not_impaired():
    # a drift carries a `change` type -> diverged from declared, but not a live failure
    assert finding_disposition({"change": "MODIFIED", "kind": "deployment"}) == NOTED
    assert finding_disposition({"change": "REMOVED", "kind": "service"}) == NOTED


def test_an_evidence_less_finding_is_noted_by_default():
    # a posture/policy finding records no evidence -> noted (don't cry wolf on what we can't place)
    assert finding_disposition({}) == NOTED
    assert finding_disposition(None) == NOTED
