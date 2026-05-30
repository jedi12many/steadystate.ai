"""The Symptom path through the pipeline: malfunction -> Alert, and the cross-type diagnosis
(a Symptom co-located with a Drift folds into one root-caused Alert)."""

from __future__ import annotations

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.observe.base import Symptom
from steadystate.reason.alert import Severity
from steadystate.reason.llm import LLMAnalyst
from steadystate.reason.pipeline import Pipeline
from steadystate.reason.report import Tuning

_WEB = "apps/Deployment/prod/web"


def _drift(identity: str = _WEB) -> Drift:
    return Drift(
        identity=identity,
        kind="Deployment",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="kubernetes", address=identity),
        declared={"images": ["web:1.28-rc"]},
        observed={"images": ["web:1.27"]},
    )


def _symptom(identity: str = _WEB, category: str = "CrashLoopBackOff", severity=Severity.HIGH):
    return Symptom(
        identity=identity,
        kind="Deployment",
        category=category,
        severity=severity,
        title=f"{identity.rsplit('/', 1)[-1]} is {category}",
        detail=f"2 pod(s) {category}; last log: fatal: missing DB_URL",
        provenance=Provenance(source="kubernetes", address=identity),
    )


def _pipeline() -> Pipeline:
    return Pipeline(
        analyst=LLMAnalyst(enabled=False), tuning=Tuning.DEFAULT, correlator="deterministic"
    )


def test_standalone_symptom_becomes_its_own_alert():
    report = _pipeline().run([], symptoms=[_symptom()])
    [alert] = report.alerts
    assert alert.drifts == [] and len(alert.symptoms) == 1
    assert alert.symptoms[0].category == "CrashLoopBackOff"
    assert alert.resources == [_WEB]  # symptom alerts still name their resource


def test_symptom_diagnoses_into_a_co_located_drift():
    report = _pipeline().run([_drift()], symptoms=[_symptom()])
    assert len(report.alerts) == 1  # ONE alert, not two -- the diagnosis
    [alert] = report.alerts
    assert len(alert.drifts) == 1 and len(alert.symptoms) == 1  # both, on one alert
    assert alert.severity is Severity.HIGH  # raised to the symptom's severity
    assert "root cause" in alert.title.lower()
    assert "missing DB_URL" in alert.why_it_matters  # the operational evidence is folded in


def test_a_symptom_elsewhere_stays_separate_from_the_drift():
    report = _pipeline().run([_drift()], symptoms=[_symptom(), _symptom(identity="x/y/api")])
    titles = sorted(a.title for a in report.alerts)
    assert len(report.alerts) == 2  # the web diagnosis + the standalone api symptom
    assert any("root cause" in t.lower() for t in titles)
    assert any(a.symptoms and not a.drifts for a in report.alerts)  # api stands alone


def test_low_severity_symptom_is_a_signal_not_an_alert():
    report = _pipeline().run([], symptoms=[_symptom(severity=Severity.LOW)])
    assert report.alerts == [] and report.signal_count == 1  # below the default bar


def test_no_symptoms_is_the_unchanged_path():
    drift = _drift()
    assert len(_pipeline().run([drift]).alerts) == len(_pipeline().run([drift], symptoms=[]).alerts)


def test_diagnosis_keeps_both_fingerprints_for_memory():
    from steadystate.reconcile_state import _fingerprints

    [alert] = _pipeline().run([_drift()], symptoms=[_symptom()]).alerts
    fps = _fingerprints(alert)
    assert _drift().fingerprint in fps and _symptom().fingerprint in fps  # remembers both
