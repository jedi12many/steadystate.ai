"""Signal/Event classification + Brain Tuning, and the Report shape."""

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.pipeline import Pipeline
from steadystate.reason.report import Report, Tuning, classify


def _drift(
    change_type: ChangeType = ChangeType.MODIFIED, identity: str = "aws_s3_bucket.logs"
) -> Drift:
    return Drift(
        identity=identity,
        kind="aws_s3_bucket",
        change_type=change_type,
        provenance=Provenance(source="terraform", address=identity),
    )


# --- classify (one bar: Signal vs Event) ------------------------------------


def test_classify_default():
    assert classify(Severity.LOW, Tuning.DEFAULT) is Layer.SIGNAL
    assert classify(Severity.MEDIUM, Tuning.DEFAULT) is Layer.EVENT
    assert classify(Severity.HIGH, Tuning.DEFAULT) is Layer.EVENT


def test_classify_strict_and_lenient():
    assert classify(Severity.LOW, Tuning.STRICT) is Layer.EVENT  # everything is an Event
    assert classify(Severity.MEDIUM, Tuning.LENIENT) is Layer.SIGNAL  # only HIGH+ are Events
    assert classify(Severity.HIGH, Tuning.LENIENT) is Layer.EVENT


# --- Report -----------------------------------------------------------------


def _item(layer: Layer, drifts: list[Drift] | None = None) -> Alert:
    return Alert(
        title="t", severity=Severity.MEDIUM, drifts=drifts or [], why_it_matters="w", layer=layer
    )


def test_report_partitions_and_counts():
    report = Report(
        items=[
            _item(Layer.ALERT, drifts=[_drift(), _drift()]),  # one Alert bundling two Events
            _item(Layer.SIGNAL),
            _item(Layer.SIGNAL),
        ]
    )
    assert len(report.alerts) == 1
    assert report.signal_count == 2
    assert report.event_count == 2  # the two drifts bundled in the Alert


# --- pipeline: Signals deterministic; Events -> correlation -> Alerts -------


def test_low_severity_drift_is_a_counted_signal(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.DEFAULT).run([_drift(ChangeType.ADDED)])  # ADDED -> LOW
    assert report.signal_count == 1
    assert not report.alerts


def test_event_without_llm_becomes_its_own_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline().run([_drift(ChangeType.REMOVED)])  # HIGH -> Event -> singleton Alert
    assert len(report.alerts) == 1
    assert report.alerts[0].llm_backed is False
    assert len(report.alerts[0].drifts) == 1


def test_tuning_moves_the_signal_event_bar(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # MODIFIED -> MEDIUM: a counted Signal under lenient, an Event (then Alert) under strict.
    assert Pipeline(tuning=Tuning.LENIENT).run([_drift(ChangeType.MODIFIED)]).signal_count == 1
    assert len(Pipeline(tuning=Tuning.STRICT).run([_drift(ChangeType.MODIFIED)]).alerts) == 1


def test_empty_scan_is_quiet():
    assert Pipeline().run([]).items == []
