"""EvidenceKeys pins the cross-module contract inside Finding.details / Symptom.evidence. The
string VALUES are persisted in SQLite (the details JSON), so changing a value silently breaks
already-stored findings -- this freezes the values, and a round-trip proves the constant drives
real behaviour. (The NAMES are the indirection a typo turns into an AttributeError; the VALUES are
the on-disk contract.)"""

from __future__ import annotations

from steadystate.evidence import EvidenceKeys
from steadystate.health import IMPAIRED, NOTED, finding_disposition


def test_persisted_key_values_are_frozen():
    # a value change breaks findings already in state.db -- pin every one to its on-disk string.
    assert EvidenceKeys.CATEGORY == "category"
    assert EvidenceKeys.WORKLOAD == "workload"
    assert EvidenceKeys.NAMESPACE == "namespace"
    assert EvidenceKeys.CLUSTER == "cluster"
    assert EvidenceKeys.KIND == "kind"
    assert EvidenceKeys.NODE == "node"
    assert EvidenceKeys.CHANGE == "change"
    assert EvidenceKeys.LAST_LOG == "last_log"
    assert EvidenceKeys.TRACE == "trace"
    assert EvidenceKeys.SAMPLE == "sample"
    assert EvidenceKeys.CORRELATED == "correlated"


def test_change_key_drives_drift_vs_symptom():
    # the contract in action: CHANGE -> NOTED (drift); a live category, no change -> IMPAIRED
    assert finding_disposition({EvidenceKeys.CHANGE: "modified"}) == NOTED
    assert finding_disposition({EvidenceKeys.CATEGORY: "CrashLoopBackOff"}) == IMPAIRED
