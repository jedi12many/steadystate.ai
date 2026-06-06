"""Per-wall custom health checks: the declarative schema (validation is the safety boundary -- a
check is data, never code), k8s-quantity parsing, the read-aggregate-compare evaluation, and that a
fired check becomes a normal Symptom (so it rides the pipeline). The read is faked -- no cluster."""

from __future__ import annotations

import json

from steadystate.probe.custom import (
    CustomCheckEvaluator,
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
