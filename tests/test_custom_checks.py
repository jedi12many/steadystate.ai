"""Per-wall custom health checks: the declarative schema (validation is the safety boundary -- a
check is data, never code), k8s-quantity parsing, the read-aggregate-compare evaluation, and that a
fired check becomes a normal Symptom (so it rides the pipeline). The read is faked -- no cluster."""

from __future__ import annotations

import json

from steadystate.probe.custom import (
    CustomCheckEvaluator,
    DockerCheckEvaluator,
    _aggregate,
    _cpu_millicores,
    _fires,
    _mem_mib,
    _pod_values,
    evaluate_custom_checks,
    load_checks,
    parse_check,
)

_GOOD = {
    "name": "gateway-cold",
    "read": {"kind": "kubectl-cpu", "selector": "app=gateway", "namespace": "prod"},
    "when": {"op": "<", "value": 5},
    "emit": {"severity": "medium", "title": "gateway region looks cold"},
}


# -- the schema is the safety boundary: only vetted shapes parse ----------------


def test_a_well_formed_check_parses():
    check = parse_check(_GOOD)
    assert check is not None
    assert check.kind == "kubectl-cpu" and check.op == "<" and check.value == 5.0
    assert check.severity.value == "medium" and check.agg == "sum"  # agg defaults to sum


def test_an_unvetted_read_kind_or_operator_is_rejected():
    # the whole point: a check can only ever name a vetted read kind + operator -- never code.
    assert parse_check({**_GOOD, "read": {**_GOOD["read"], "kind": "exec-script"}}) is None
    assert parse_check({**_GOOD, "when": {"op": "; rm -rf", "value": 5}}) is None
    assert parse_check({**_GOOD, "read": {**_GOOD["read"], "agg": "eval"}}) is None


def test_missing_or_wrong_typed_fields_are_rejected():
    assert parse_check({**_GOOD, "name": ""}) is None
    assert (
        parse_check({**_GOOD, "read": {"kind": "kubectl-cpu", "namespace": "prod"}}) is None
    )  # no selector
    assert parse_check({**_GOOD, "when": {"op": "<", "value": "lots"}}) is None  # non-numeric
    assert (
        parse_check({**_GOOD, "when": {"op": "<", "value": True}}) is None
    )  # bool is not a number
    assert parse_check({**_GOOD, "emit": {"severity": "apocalyptic", "title": "x"}}) is None


# -- k8s quantity parsing -------------------------------------------------------


def test_cpu_quantity_parsing_to_millicores():
    assert _cpu_millicores("5m") == 5.0
    assert _cpu_millicores("2") == 2000.0  # cores -> millicores
    assert abs(_cpu_millicores("123456n") - 0.123456) < 1e-9  # nanocores
    assert _cpu_millicores("garbage") is None


def test_memory_quantity_parsing_to_mib():
    assert _mem_mib("512Mi") == 512.0
    assert _mem_mib("1Gi") == 1024.0
    assert _mem_mib("524288Ki") == 512.0
    assert _mem_mib("nope") is None


def test_pod_values_sums_each_pods_containers():
    payload = {
        "items": [
            {"containers": [{"usage": {"cpu": "3m"}}, {"usage": {"cpu": "1m"}}]},  # pod total 4m
            {"containers": [{"usage": {"cpu": "10m"}}]},
        ]
    }
    assert sorted(_pod_values(payload, "kubectl-cpu")) == [4.0, 10.0]


def test_aggregation_modes_and_operators():
    assert _aggregate([4.0, 10.0], "sum") == 14.0
    assert _aggregate([4.0, 10.0], "max") == 10.0
    assert _aggregate([4.0, 10.0], "avg") == 7.0
    assert _fires("<", 4, 5) and not _fires("<", 6, 5)
    assert _fires(">=", 5, 5) and _fires("!=", 4, 5)


# -- evaluation: a fired check is a normal Symptom ------------------------------


def _evaluator(check: dict, payload: dict | None, monkeypatch) -> CustomCheckEvaluator:
    import steadystate.probe.custom as mod

    monkeypatch.setattr(mod, "load_checks", lambda _p: [c for c in [parse_check(check)] if c])
    ev = CustomCheckEvaluator()
    monkeypatch.setattr(ev, "_pod_metrics", lambda ns, sel: payload)
    return ev


def test_a_check_that_holds_emits_a_symptom_that_rides_the_pipeline(monkeypatch):
    payload = {"items": [{"containers": [{"usage": {"cpu": "3m"}}]}]}  # 3m < 5 -> fires
    syms = _evaluator(_GOOD, payload, monkeypatch).evaluate()
    assert len(syms) == 1
    s = syms[0]
    assert s.title == "gateway region looks cold" and s.severity.value == "medium"
    assert s.category == "gateway-cold"  # category = check name -> stable fingerprint across scans
    assert s.provenance.source == "custom-check"
    assert s.recommended_action is None  # a check OBSERVES; it never carries an auto-fix
    assert "app=gateway" in s.detail and s.evidence["matched_pods"] == "1"


def test_a_check_that_does_not_hold_emits_nothing(monkeypatch):
    payload = {"items": [{"containers": [{"usage": {"cpu": "50m"}}]}]}  # 50m < 5 is False
    assert _evaluator(_GOOD, payload, monkeypatch).evaluate() == []


def test_unavailable_metrics_never_false_alarm(monkeypatch):
    # the read couldn't be taken (no metrics-server / unreachable) -> NO finding, not a false alarm.
    assert _evaluator(_GOOD, None, monkeypatch).evaluate() == []


def test_no_matching_pods_emits_nothing(monkeypatch):
    assert _evaluator(_GOOD, {"items": []}, monkeypatch).evaluate() == []


# -- loading from the wall ------------------------------------------------------


def test_load_checks_skips_invalid_keeps_valid_and_tolerates_a_missing_file(tmp_path):
    assert load_checks(str(tmp_path / "absent.json")) == []  # missing -> [], no crash
    f = tmp_path / "checks.json"
    f.write_text(json.dumps([_GOOD, {"name": "broken"}, {"junk": True}]))  # 1 valid, 2 invalid
    loaded = load_checks(str(f))
    assert [c.name for c in loaded] == ["gateway-cold"]  # the valid one survives


def test_evaluate_custom_checks_is_a_no_op_without_a_checks_file(tmp_path):
    # the common case: a wall with no checks file -> [] (cheap, no kubectl call attempted).
    assert evaluate_custom_checks("ctx", "kube", checks_path=str(tmp_path / "none.json")) == []


# -- the kubectl-log kind: functional health ('running, but doing its job?') ----

_POSTFIX = {
    "name": "postfix-routing",
    "read": {"kind": "kubectl-log", "selector": "app=postfix", "namespace": "mail"},
    "when": {"pattern": "status=sent", "expect": "present"},
    "emit": {"severity": "high", "title": "postfix is not routing mail"},
}


def test_a_log_check_parses_with_its_pattern_and_a_valid_regex_is_required():
    check = parse_check(_POSTFIX)
    assert check is not None and check.pattern == "status=sent" and check.expect == "present"
    assert check.tail == 200  # default tail
    assert (
        parse_check({**_POSTFIX, "when": {"pattern": "x", "expect": "maybe"}}) is None
    )  # bad expect
    assert parse_check({**_POSTFIX, "when": {"pattern": "[unclosed", "expect": "present"}}) is None
    assert parse_check({**_POSTFIX, "when": {"expect": "present"}}) is None  # no pattern


def _log_evaluator(check: dict, logs: str | None, monkeypatch) -> CustomCheckEvaluator:
    import steadystate.probe.custom as mod

    monkeypatch.setattr(mod, "load_checks", lambda _p: [c for c in [parse_check(check)] if c])
    ev = CustomCheckEvaluator()
    monkeypatch.setattr(ev, "_pod_logs", lambda ns, sel, tail: logs)
    return ev


def test_present_check_fires_when_the_success_signal_is_missing(monkeypatch):
    # 'is postfix routing?' -> expect status=sent PRESENT; if it's not in the logs, fire.
    quiet = _log_evaluator(
        _POSTFIX, "postfix/postfix: connect from relay\npostfix: waiting", monkeypatch
    )
    syms = quiet.evaluate()
    assert len(syms) == 1 and syms[0].title == "postfix is not routing mail"
    assert syms[0].evidence["found"] == "False" and syms[0].category == "postfix-routing"
    # ...and when it IS routing (the signal is present), no finding.
    routing = _log_evaluator(_POSTFIX, "postfix/qmgr: status=sent (250 ok)", monkeypatch)
    assert routing.evaluate() == []


def test_absent_check_fires_when_an_error_pattern_appears(monkeypatch):
    err = {**_POSTFIX, "when": {"pattern": "fatal|panic", "expect": "absent"}}
    seen = _log_evaluator(err, "postfix/master: fatal: cannot bind to port 25", monkeypatch)
    assert len(seen.evaluate()) == 1  # the error is present -> fire
    clean = _log_evaluator(err, "postfix/qmgr: all good", monkeypatch)
    assert clean.evaluate() == []  # no error -> no finding


def test_logs_unavailable_is_no_finding_not_a_false_alarm(monkeypatch):
    # a *down* app is the generic prober's job; a log read we couldn't take must not fire.
    assert _log_evaluator(_POSTFIX, None, monkeypatch).evaluate() == []


# -- docker-log: the same functional health over a container's logs -------------

_NGINX = {
    "name": "web-serving",
    "read": {"kind": "docker-log", "selector": "name=web"},  # a `docker ps --filter`, no namespace
    "when": {"pattern": "GET /", "expect": "present"},
    "emit": {"severity": "high", "title": "web is not serving requests"},
}


def test_docker_log_parses_without_a_namespace_but_kubectl_still_requires_one():
    check = parse_check(_NGINX)
    assert check is not None and check.kind == "docker-log" and check.namespace == ""
    # a kubectl read is namespace-scoped, so it's still required there
    k8s_no_ns = {
        "name": "x",
        "read": {"kind": "kubectl-log", "selector": "app=x"},
        "when": {"pattern": "y", "expect": "present"},
        "emit": {"severity": "low", "title": "t"},
    }
    assert parse_check(k8s_no_ns) is None


def _docker_evaluator(check: dict, logs: str | None, monkeypatch) -> DockerCheckEvaluator:
    import steadystate.probe.custom as mod

    monkeypatch.setattr(mod, "load_checks", lambda _p: [c for c in [parse_check(check)] if c])
    ev = DockerCheckEvaluator()
    monkeypatch.setattr(ev, "_container_logs", lambda sel, tail: logs)
    return ev


def test_docker_log_fires_when_the_signal_is_missing_and_stays_quiet_when_present(monkeypatch):
    missing = _docker_evaluator(_NGINX, "connection from relay\nidle", monkeypatch).evaluate()
    assert len(missing) == 1 and missing[0].title == "web is not serving requests"
    assert missing[0].provenance.source == "custom-check"  # rides the pipeline like any Symptom
    serving = _docker_evaluator(_NGINX, "172.0.0.1 - GET / 200", monkeypatch)
    assert serving.evaluate() == []


def test_docker_unavailable_is_no_finding(monkeypatch):
    assert _docker_evaluator(_NGINX, None, monkeypatch).evaluate() == []
