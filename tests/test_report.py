"""Three-tier classification (Signal/Event/Alert) + the Brain Tuning knob."""

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Layer, Severity
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
    assert classify(Severity.LOW, Tuning.DEFAULT) is Layer.SIGNAL
    assert classify(Severity.MEDIUM, Tuning.DEFAULT) is Layer.EVENT
    assert classify(Severity.HIGH, Tuning.DEFAULT) is Layer.ALERT
    assert classify(Severity.CRITICAL, Tuning.DEFAULT) is Layer.ALERT


def test_classify_strict_lowers_the_bar():
    assert classify(Severity.LOW, Tuning.STRICT) is Layer.EVENT
    assert classify(Severity.MEDIUM, Tuning.STRICT) is Layer.ALERT


def test_classify_lenient_raises_the_bar():
    assert classify(Severity.MEDIUM, Tuning.LENIENT) is Layer.SIGNAL
    assert classify(Severity.HIGH, Tuning.LENIENT) is Layer.EVENT
    assert classify(Severity.CRITICAL, Tuning.LENIENT) is Layer.ALERT


# --- Report partitioning ----------------------------------------------------


def _item(layer: Layer) -> Alert:
    return Alert(title="t", severity=Severity.MEDIUM, drifts=[], why_it_matters="w", layer=layer)


def test_report_partitions_by_tier():
    report = Report(
        items=[_item(Layer.ALERT), _item(Layer.EVENT), _item(Layer.SIGNAL), _item(Layer.SIGNAL)]
    )
    assert len(report.alerts) == 1
    assert len(report.events) == 1
    assert report.signal_count == 2
    assert len(report.surfaced) == 2  # alerts + events; raw signals excluded


# --- pipeline integration: tuning moves what surfaces -----------------------


def test_modified_drift_is_event_by_default(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.DEFAULT).run([_drift(ChangeType.MODIFIED)])  # MEDIUM
    assert report.events and not report.alerts
    # Events are recorded but not analyzed -- no LLM, no action.
    assert report.events[0].recommended_action is None
    assert report.events[0].llm_backed is False


def test_strict_promotes_modified_to_alert(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.STRICT).run([_drift(ChangeType.MODIFIED)])
    assert report.alerts and not report.events
    # The Alert tier gets the executor-backed action even without an LLM.
    assert report.alerts[0].recommended_action


def test_lenient_demotes_modified_to_counted_signal(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = Pipeline(tuning=Tuning.LENIENT).run([_drift(ChangeType.MODIFIED)])
    assert report.signal_count == 1
    assert not report.surfaced


def test_empty_scan_is_quiet():
    assert Pipeline().run([]).items == []
