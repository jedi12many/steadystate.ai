from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.pipeline import Pipeline, baseline_severity
from steadystate.reason.report import Tuning


def _modified(actionable: bool) -> Drift:
    return Drift(
        identity="google_compute_instance.vm",
        kind="google_compute_instance",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform"),
        declared={"x": 2},
        observed={"x": 1},
        actionable=actionable,
    )


def test_non_actionable_drift_floors_to_low():
    assert baseline_severity(_modified(actionable=True)).value == "medium"
    assert baseline_severity(_modified(actionable=False)).value == "low"


def test_non_actionable_drift_is_a_counted_signal_not_an_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def run(drift: Drift):
        return Pipeline(tuning=Tuning.DEFAULT, correlator="deterministic").run([drift])

    # LOW under default tuning -> below the Event bar -> a counted Signal, not a surfaced
    # Alert, and never given a (no-op) terraform-apply remediation.
    report = run(_modified(actionable=False))
    assert report.alerts == []
    assert report.signal_count == 1

    # The actionable counterpart surfaces as a MEDIUM Alert with a reconcile action.
    report2 = run(_modified(actionable=True))
    assert len(report2.alerts) == 1
    assert report2.alerts[0].recommended_action is not None


def test_pipeline_degrades_honestly_without_llm(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    drift = Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform"),
        observed={"id": "b"},
    )
    report = Pipeline().run([drift])
    # REMOVED -> HIGH -> CASE under default tuning.
    assert len(report.alerts) == 1
    assert report.alerts[0].llm_backed is False  # honest: no fabricated reasoning
    assert report.alerts[0].severity.value == "high"  # a removed declared resource
