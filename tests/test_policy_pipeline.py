"""Integration: standing-policy findings flow drift-free through the pipeline into
Alerts, ride the state store's memory by fingerprint, and render on the surfaces."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.domains.compliance import DockerComplianceDomain
from steadystate.model import Provenance, Resource
from steadystate.notify.console import ConsoleSurface
from steadystate.notify.slack import format_slack_message
from steadystate.notify.teams import format_teams_message
from steadystate.reason.alert import Layer, Severity
from steadystate.reason.pipeline import Pipeline
from steadystate.reason.report import Tuning
from steadystate.reconcile_state import reconcile
from steadystate.state import StateStore


def _service(name: str = "web", **props: object) -> Resource:
    return Resource(
        kind="docker_compose_service",
        identity=name,
        provenance=Provenance(source="docker-compose", address=name),
        properties=props,
    )


def _pipeline(tuning: Tuning = Tuning.DEFAULT) -> Pipeline:
    # Isolate the compliance pack; deterministic correlator never calls a model.
    return Pipeline(domains=[DockerComplianceDomain()], tuning=tuning, correlator="deterministic")


def _privileged() -> Resource:
    # Exactly one rule fires (privileged, HIGH); everything else is hardened.
    return _service(
        privileged=True, image="nginx:1.25", user="1000", security_opt=["no-new-privileges:true"]
    )


def _hardened() -> Resource:
    return _service(image="nginx:1.25", user="1000", security_opt=["no-new-privileges:true"])


def _low_only() -> Resource:
    # Only the no-new-privileges rule fires -> a single LOW finding.
    return _service(image="nginx:1.25", user="1000")


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


# -- pipeline: findings -> Alerts/Signals ---------------------------------------


def test_high_finding_becomes_a_driftless_alert():
    report = _pipeline().run([], [_privileged()])
    assert len(report.alerts) == 1
    alert = report.alerts[0]
    assert alert.layer is Layer.ALERT
    assert alert.severity is Severity.HIGH
    assert alert.drifts == []  # standing policy: no drift
    assert len(alert.findings) == 1
    assert alert.flagged_by == "docker-compliance"
    assert alert.references  # carries the CIS/MITRE chips


def test_low_finding_is_a_counted_signal_under_default_tuning():
    report = _pipeline().run([], [_low_only()])
    assert report.alerts == []
    assert report.signal_count >= 1


def test_strict_tuning_promotes_low_findings_to_alerts():
    report = _pipeline(Tuning.STRICT).run([], [_low_only()])
    assert len(report.alerts) >= 1


def test_no_resources_means_no_policy_findings():
    # Back-compat: the stateless drift path (no resources) does no policy work.
    report = _pipeline().run([])
    assert report.items == []


# -- memory by fingerprint (the proof the rail is right) ------------------------


def test_policy_finding_is_new_then_recurring_then_resolved():
    store = StateStore()
    pipe = _pipeline()

    first = pipe.run([], [_privileged()])
    reconcile(first, store, now=_t(1))
    assert first.alerts[0].status == "open"
    assert first.alerts[0].first_seen == _t(1)  # NEW: first_seen == this scan

    second = pipe.run([], [_privileged()])
    reconcile(second, store, now=_t(2))
    assert second.alerts[0].first_seen == _t(1)  # recurring: original first_seen preserved

    cleared = pipe.run([], [_hardened()])  # privileged removed -> violation gone
    resolved = reconcile(cleared, store, now=_t(3))
    bad_fp = pipe.run([], [_privileged()]).alerts[0].findings[0].fingerprint
    assert bad_fp in {r.fingerprint for r in resolved}


def test_muted_policy_finding_is_suppressed_on_the_next_scan():
    store = StateStore()
    pipe = _pipeline()

    first = pipe.run([], [_privileged()])
    reconcile(first, store, now=_t(1))
    fingerprint = first.alerts[0].findings[0].fingerprint

    store.mute(fingerprint, note=None, actor="cli", now=_t(1))

    second = pipe.run([], [_privileged()])
    reconcile(second, store, now=_t(2))
    assert second.alerts == []  # the only alert was muted -> dropped from the surface


# -- surfaces render a driftless Alert ------------------------------------------


def test_slack_renders_the_cis_chip():
    alert = _pipeline().run([], [_privileged()]).alerts[0]
    assert "CIS Docker-5.4" in format_slack_message(alert)["text"]


def test_teams_sources_a_driftless_alert_from_its_finding():
    alert = _pipeline().run([], [_privileged()]).alerts[0]
    facts = format_teams_message(alert)["attachments"][0]["content"]["body"][1]["facts"]
    assert {"title": "Source", "value": "docker-compose"} in facts


def test_console_emits_a_policy_alert_without_drifts():
    # Empty drifts must not raise (the "N correlated" badge guards on len()).
    ConsoleSurface().emit(_pipeline().run([], [_privileged()]))
