"""ServiceNow assignment-group routing -- a committed [servicenow] map sends each incident to the
right team's queue. These pin the matcher semantics (mirrors the runbook: `for` = exact category,
`match` = title regex, both = AND, first route wins), the defaults (config default, env override,
opt-in -- no config means no assignment_group field at all), the broken-route discipline (an
uncompilable regex skips the route, never eats the ticket), and the payload wiring."""

from __future__ import annotations

from steadystate.model import Provenance
from steadystate.notify.servicenow import assignment_group_for, format_servicenow_incident
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Severity


def _sym(category: str) -> Symptom:
    return Symptom(
        identity=f"default/{category}",
        kind="Pod",
        category=category,
        severity=Severity.MEDIUM,
        title=f"{category} seen",
        detail="d",
        provenance=Provenance(source="k8s"),
    )


def _alert(title: str = "gateway not routing", *categories: str) -> Alert:
    return Alert(
        title=title,
        severity=Severity.HIGH,
        drifts=[],
        symptoms=[_sym(c) for c in categories],
        why_it_matters="w",
    )


def _config(tmp_path, monkeypatch, body: str) -> None:
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text(body)
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_SERVICENOW_GROUP", raising=False)


# -- the matcher semantics (injected routes -- pure) -------------------------------------------


def test_for_matches_a_symptom_category_exactly():
    routes = [{"for": "NetworkUnreachable", "group": "network-ops"}]
    assert assignment_group_for(_alert("x", "NetworkUnreachable"), routes) == "network-ops"
    assert assignment_group_for(_alert("x", "Evicted"), routes) == ""  # no default -> ""


def test_match_is_a_title_regex_and_first_route_wins():
    routes = [
        {"match": "dns|gateway|proxy", "group": "network-ops"},
        {"match": "gateway", "group": "second-team"},  # also matches -- but the FIRST wins
    ]
    assert assignment_group_for(_alert("the gateway is not routing"), routes) == "network-ops"


def test_both_set_means_both_must_hold():
    routes = [{"for": "Evicted", "match": "gateway", "group": "network-ops"}]
    assert assignment_group_for(_alert("gateway pods evicted", "Evicted"), routes) == "network-ops"
    assert assignment_group_for(_alert("web pods evicted", "Evicted"), routes) == ""
    assert assignment_group_for(_alert("gateway down", "CrashLoop"), routes) == ""


def test_a_broken_regex_route_is_skipped_never_eats_the_ticket():
    routes = [
        {"match": "([unclosed", "group": "broken-route"},
        {"match": "gateway", "group": "network-ops"},
    ]
    assert assignment_group_for(_alert("gateway down"), routes) == "network-ops"


def test_unmatched_falls_to_the_default_group():
    routes = [{"for": "NetworkUnreachable", "group": "network-ops"}]
    got = assignment_group_for(_alert("disk full", "DiskPressure"), routes, default="platform-ops")
    assert got == "platform-ops"


# -- config + payload wiring -------------------------------------------------------------------


def test_routing_is_opt_in_no_config_means_no_assignment_field(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no config.toml here
    monkeypatch.delenv("STEADYSTATE_SERVICENOW_GROUP", raising=False)
    assert "assignment_group" not in format_servicenow_incident(_alert())


def test_committed_routes_steer_the_incident_payload(tmp_path, monkeypatch):
    _config(
        tmp_path,
        monkeypatch,
        '[servicenow]\nassignment_group = "platform-ops"\n\n'
        '[[servicenow.route]]\nfor = "NetworkUnreachable"\ngroup = "network-ops"\n',
    )
    routed = format_servicenow_incident(_alert("link down", "NetworkUnreachable"))
    assert routed["assignment_group"] == "network-ops"  # the network team gets the ticket
    fallthrough = format_servicenow_incident(_alert("disk full", "DiskPressure"))
    assert fallthrough["assignment_group"] == "platform-ops"  # everything else -> the default


def test_env_overrides_the_config_default(tmp_path, monkeypatch):
    _config(tmp_path, monkeypatch, '[servicenow]\nassignment_group = "platform-ops"\n')
    monkeypatch.setenv("STEADYSTATE_SERVICENOW_GROUP", "override-team")
    assert format_servicenow_incident(_alert())["assignment_group"] == "override-team"
