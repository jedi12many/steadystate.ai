"""Three-layer classification + the Brain Tuning knob."""

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.case import Case, Layer, Severity
from steadystate.reason.pipeline import Pipeline
from steadystate.reason.report import Report, Tuning, classify


def _drift(change_type: ChangeType = ChangeType.MODIFIED) -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=change_type,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
    )


# --- classify ---------------------------------------------------------------


def test_classify_default_thresholds():
    assert classify(Severity.LOW, Tuning.DEFAULT) is Layer.EVENT
    assert classify(Severity.MEDIUM, Tuning.DEFAULT) is Layer.ALERT
    assert classify(Severity.HIGH, Tuning.DEFAULT) is Layer.CASE
    assert classify(Severity.CRITICAL, Tuning.DEFAULT) is Layer.CASE


def test_classify_strict_lowers_the_bar():
    assert classify(Severity.LOW, Tuning.STRICT) is Layer.ALERT
    assert classify(Severity.MEDIUM, Tuning.STRICT) is Layer.CASE


def test_classify_lenient_raises_the_bar():
    assert classify(Severity.MEDIUM, Tuning.LENIENT) is Layer.EVENT
    assert classify(Severity.HIGH, Tuning.LENIENT) is Layer.ALERT
    assert classify(Severity.CRITICAL, Tuning.LENIENT) is Layer.CASE


# --- Report partitioning ----------------------------------------------------


def _case(layer: Layer) -> Case:
    return Case(title="t", severity=Severity.MEDIUM, drifts=[], why_it_matters="w", layer=layer)


def test_report_partitions_by_layer():
    report = Report(
        all_cases=[_case(Layer.CASE), _case(Layer.ALERT), _case(Layer.EVENT), _case(Layer.EVENT)]
    )
    assert len(report.cases) == 1
    assert len(report.alerts) == 1
    assert report.event_count == 2
    assert len(report.surfaced) == 2  # cases + alerts; events excluded


# --- pipeline integration: tuning moves what surfaces -----------------------


def test_modified_drift_is_alert_by_default(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.DEFAULT).run([_drift(ChangeType.MODIFIED)])  # MEDIUM
    assert report.alerts and not report.cases
    assert report.alerts[0].recommended_action  # alerts still get the executor action


def test_strict_promotes_modified_to_case(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.STRICT).run([_drift(ChangeType.MODIFIED)])
    assert report.cases and not report.alerts


def test_lenient_demotes_modified_to_counted_event(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.LENIENT).run([_drift(ChangeType.MODIFIED)])
    assert report.event_count == 1
    assert not report.surfaced
    # events are the cheap firehose: no LLM, no executor action
    assert report.events[0].llm_backed is False
    assert report.events[0].recommended_action is None


def test_empty_scan_is_quiet():
    assert Pipeline().run([]).all_cases == []
