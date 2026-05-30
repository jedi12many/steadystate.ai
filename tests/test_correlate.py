"""LLM correlation: grouping Events by root cause, with honest degrade.

We monkeypatch LLMAnalyst._complete (the raw model call) so nothing hits a network
or needs a key -- the correlation + parsing + degrade logic is what's under test.
"""

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.llm import LLMAnalyst
from steadystate.reason.pipeline import Pipeline


def _drift(identity: str, change_type: ChangeType = ChangeType.REMOVED) -> Drift:
    return Drift(
        identity=identity,
        kind="node",
        change_type=change_type,
        provenance=Provenance(source="terraform", address=identity),
    )


_GROUPED = (
    '{"groups": [{"drift_indexes": [0, 1], "title": "node-7 out of storage", '
    '"why_it_matters": "disk full -> evictions + write errors", '
    '"recommended_action": "free disk on node-7"}]}'
)


def test_correlate_degrades_to_singletons_without_a_model(monkeypatch):
    monkeypatch.setattr(LLMAnalyst, "_complete", lambda self, system, user, caller: None)
    clusters = LLMAnalyst().correlate([_drift("a"), _drift("b")])
    assert [c.drift_indexes for c in clusters] == [[0], [1]]
    assert all(not c.llm_backed for c in clusters)


def test_correlate_groups_by_cause(monkeypatch):
    monkeypatch.setattr(LLMAnalyst, "_complete", lambda self, system, user, caller: _GROUPED)
    clusters = LLMAnalyst().correlate([_drift("a"), _drift("b")])
    assert len(clusters) == 1
    assert clusters[0].drift_indexes == [0, 1]
    assert clusters[0].llm_backed is True
    assert clusters[0].title == "node-7 out of storage"


def test_correlate_rejects_incomplete_coverage(monkeypatch):
    # Only index 0 grouped, 1 is missing -> doesn't cover all drifts -> degrade.
    bad = (
        '{"groups": [{"drift_indexes": [0], "title": "t", '
        '"why_it_matters": "w", "recommended_action": null}]}'
    )
    monkeypatch.setattr(LLMAnalyst, "_complete", lambda self, system, user, caller: bad)
    clusters = LLMAnalyst().correlate([_drift("a"), _drift("b")])
    assert len(clusters) == 2  # degraded to singletons
    assert all(not c.llm_backed for c in clusters)


def test_correlate_handles_non_json(monkeypatch):
    monkeypatch.setattr(
        LLMAnalyst, "_complete", lambda self, system, user, caller: "sorry, no idea"
    )
    clusters = LLMAnalyst().correlate([_drift("a")])
    assert len(clusters) == 1 and not clusters[0].llm_backed


def test_pipeline_folds_correlated_events_into_one_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(LLMAnalyst, "_complete", lambda self, system, user, caller: _GROUPED)
    # Two HIGH (REMOVED) drifts -> both Events under default -> correlate -> one Alert.
    report = Pipeline().run([_drift("disk"), _drift("pods")])
    assert len(report.alerts) == 1
    alert = report.alerts[0]
    assert len(alert.drifts) == 2
    assert alert.llm_backed is True
    assert alert.title == "node-7 out of storage"
    assert alert.recommended_action == "free disk on node-7"
    assert report.event_count == 2
