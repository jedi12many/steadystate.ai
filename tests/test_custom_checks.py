"""Per-wall custom health checks: the declarative schema (validation is the safety boundary -- a
check is data, never code), k8s-quantity parsing, the read-aggregate-compare evaluation, and that a
fired check becomes a normal Symptom (so it rides the pipeline). The read is faked -- no cluster."""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from steadystate.probe.custom import (
    AnsibleCheckEvaluator,
    CustomCheckEvaluator,
    DockerCheckEvaluator,
    HttpCheckEvaluator,
    _aggregate,
    _cpu_millicores,
    _fires,
    _mem_mib,
    _pod_values,
    add_check,
    define_check,
    evaluate_custom_checks,
    load_checks,
    parse_check,
    resolve_checks_path,
    run_smoke_checks,
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


# -- ansible-service: is a host/VM service in the expected state? (vetted read, no command) -------

_SQUID = {
    "name": "squid-up",
    "read": {"kind": "ansible-service", "selector": "proxies", "service": "squid"},
    "when": {"expect": "active"},
    "emit": {"severity": "high", "title": "squid is not running on a proxy host"},
}


def test_ansible_service_parses_and_rejects_a_command_or_wrong_expect():
    check = parse_check(_SQUID)
    assert check is not None and check.service == "squid" and check.expect == "active"
    assert check.selector == "proxies" and check.namespace == ""  # host pattern, no namespace
    assert parse_check({**_SQUID, "when": {"expect": "present"}}) is None  # log expect, not service
    # no `command` kind exists -- arbitrary command execution is deliberately not in the schema
    cmd = {**_SQUID, "read": {"kind": "ansible-command", "selector": "all", "service": "x"}}
    assert parse_check(cmd) is None


def _ansible_evaluator(check: dict, states, monkeypatch) -> AnsibleCheckEvaluator:
    import steadystate.probe.custom as mod

    monkeypatch.setattr(mod, "load_checks", lambda _p: [c for c in [parse_check(check)] if c])
    ev = AnsibleCheckEvaluator()
    monkeypatch.setattr(ev, "_service_states", lambda pattern: states)
    return ev


def test_ansible_service_fires_when_a_host_is_not_in_the_expected_state(monkeypatch):
    states = {
        "p1": {"squid.service": {"state": "running"}},
        "p2": {"squid.service": {"state": "stopped"}},  # the offender
    }
    syms = _ansible_evaluator(_SQUID, states, monkeypatch).evaluate()
    assert len(syms) == 1 and "1/2 host(s)" in syms[0].detail and "p2" in syms[0].detail
    assert syms[0].evidence["service"] == "squid" and syms[0].provenance.source == "custom-check"
    # all hosts running (incl. the `active` synonym) -> clean
    ok = {
        "p1": {"squid.service": {"state": "running"}},
        "p2": {"squid.service": {"state": "active"}},
    }
    assert _ansible_evaluator(_SQUID, ok, monkeypatch).evaluate() == []


def test_ansible_unavailable_or_no_hosts_is_no_finding(monkeypatch):
    assert _ansible_evaluator(_SQUID, None, monkeypatch).evaluate() == []  # ansible couldn't run
    assert _ansible_evaluator(_SQUID, {}, monkeypatch).evaluate() == []  # no hosts matched


# -- authoring: validate + store (the gate), and natural-language -> check -------


def test_add_check_validates_stores_and_replaces_by_name(tmp_path):
    cp = str(tmp_path / "checks.json")
    check, msg = add_check(_SQUID, cp)
    assert check is not None and "added" in msg
    assert [c.name for c in load_checks(cp)] == ["squid-up"]
    # re-defining the same name UPDATES it (no duplicate) -- idempotent authoring
    add_check({**_SQUID, "emit": {"severity": "medium", "title": "squid down (v2)"}}, cp)
    loaded = load_checks(cp)
    assert len(loaded) == 1 and loaded[0].severity.value == "medium"


def test_add_check_rejects_an_invalid_check_and_stores_nothing(tmp_path):
    cp = str(tmp_path / "checks.json")
    # the validation IS the gate: an unvetted read kind never gets written
    bad = {
        "name": "x",
        "read": {"kind": "exec-script", "selector": "y"},
        "when": {},
        "emit": {"severity": "high", "title": "t"},
    }
    check, msg = add_check(bad, cp)
    assert check is None and "schema" in msg.lower()
    assert load_checks(cp) == []  # nothing stored


def test_define_check_translates_via_the_llm_and_degrades_cleanly():
    ok = {
        "name": "web-up",
        "read": {"kind": "docker-log", "selector": "name=web"},
        "when": {"pattern": "GET", "expect": "present"},
        "emit": {"severity": "low", "title": "web idle"},
    }
    assert define_check("alert if web stops serving", lambda s, u, c: json.dumps(ok)) == ok
    assert define_check("x", lambda *_a: None) is None  # no model configured -> None
    assert define_check("x", lambda *_a: "not json at all") is None  # unparseable -> None


def test_checks_path_resolves_explicit_then_env_then_default(tmp_path, monkeypatch):
    # checks are intent, not runtime state -> they can live in a version-controlled file, separate
    # from the gitignored .steadystate/. explicit (--checks) > STEADYSTATE_CHECKS > the default.
    monkeypatch.delenv("STEADYSTATE_CHECKS", raising=False)
    assert resolve_checks_path() == ".steadystate/checks.json"
    monkeypatch.setenv("STEADYSTATE_CHECKS", "/team/checks.json")
    assert resolve_checks_path() == "/team/checks.json"
    assert resolve_checks_path("/cli/override.json") == "/cli/override.json"  # explicit wins
    # add_check + load_checks honor the env-pointed file with no explicit path
    versioned = str(tmp_path / "team-checks.json")
    monkeypatch.setenv("STEADYSTATE_CHECKS", versioned)
    add_check(_SQUID)
    assert (tmp_path / "team-checks.json").exists()
    assert [c.name for c in load_checks()] == ["squid-up"]


def test_add_check_and_checks_dispatch_through_run_command(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_CHECKS", raising=False)
    # the agent path: an MCP/chat caller fills the schema and dispatches add-check/checks like any
    # other verb. The wall is the cwd (.steadystate/checks.json).
    monkeypatch.chdir(tmp_path)
    from steadystate.inbound.base import ADD_CHECK, CHECKS, Command
    from steadystate.inbound.server import run_command

    payload = json.dumps(_SQUID)
    assert "added" in run_command(Command(ADD_CHECK, "mcp", payload), ":memory:")
    listed = run_command(Command(CHECKS, "mcp"), ":memory:")
    assert "squid-up" in listed and "ansible-service" in listed
    # a malformed payload is refused, not stored
    assert "parse" in run_command(Command(ADD_CHECK, "mcp", "{not json"), ":memory:").lower()


# -- http: the smoke test -- actively exercise an endpoint and assert the response --------------

_SMOKE = {
    "name": "gw-smoke",
    "read": {"kind": "http", "url": "https://gw/health"},
    "when": {"status": 200, "body": "ok"},
    "emit": {"severity": "high", "title": "gateway not responding"},
}


def test_http_smoke_parses_and_rejects_unsafe_requests():
    c = parse_check(_SMOKE)
    assert c is not None and c.kind == "http" and c.method == "GET" and c.status == 200
    assert c.url == "https://gw/health" and c.body == "ok" and c.selector == ""  # url is the target
    # the safety boundary: only idempotent methods, only http(s), a compilable body regex
    mutate = {**_SMOKE, "read": {"kind": "http", "url": "https://gw/h", "method": "POST"}}
    assert parse_check(mutate) is None  # a mutating method -- a smoke test reads, never writes
    assert parse_check({**_SMOKE, "read": {"kind": "http", "url": "file:///etc/passwd"}}) is None
    assert parse_check({**_SMOKE, "when": {"body": "[unclosed"}}) is None  # broken regex dropped


def _handler(status: int, body: str):
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 -- BaseHTTPRequestHandler's required name
            self.send_response(status)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_a):  # keep the test output quiet
            return

    return _H


@contextlib.contextmanager
def _server(status: int, body: str):
    httpd = HTTPServer(("127.0.0.1", 0), _handler(status, body))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/health"
    finally:
        httpd.shutdown()


def _smoke_eval(url: str, monkeypatch) -> HttpCheckEvaluator:
    import steadystate.probe.custom as mod

    check = parse_check({**_SMOKE, "read": {"kind": "http", "url": url}})
    monkeypatch.setattr(mod, "load_checks", lambda _p: [check])
    return HttpCheckEvaluator(timeout=3.0)


def test_http_smoke_is_clean_when_status_and_body_match(monkeypatch):
    with _server(200, "all ok here") as url:  # 200 + body contains 'ok' -> working
        assert _smoke_eval(url, monkeypatch).evaluate() == []


def test_http_smoke_fires_on_a_wrong_status_or_a_missing_body_signal(monkeypatch):
    with _server(503, "down") as url:
        syms = _smoke_eval(url, monkeypatch).evaluate()
        assert len(syms) == 1 and "503" in syms[0].detail and syms[0].evidence["status"] == "503"
    with _server(200, "nope") as url:  # answers 200 but the success signal 'ok' is missing
        syms = _smoke_eval(url, monkeypatch).evaluate()
        assert len(syms) == 1 and "body missing" in syms[0].detail


def test_http_smoke_unreachable_is_a_failure_not_a_noop(monkeypatch):
    # the opposite of the passive kinds: a smoke test that can't reach the service IS it being down
    syms = _smoke_eval("http://127.0.0.1:1/health", monkeypatch).evaluate()  # nothing listening
    assert len(syms) == 1 and "did not respond" in syms[0].detail
    assert syms[0].provenance.source == "custom-check"  # rides the pipeline as a Symptom


# -- the `smoke` verb: run the smoke tests live and report PASS *and* FAIL ------------------------


def _two_http_checks(good_url: str, bad_url: str):
    good = parse_check({**_SMOKE, "read": {"kind": "http", "url": good_url}})
    bad = parse_check(
        {**_SMOKE, "name": "db-smoke", "read": {"kind": "http", "url": bad_url}, "when": {}}
    )
    return [c for c in (good, bad) if c is not None]


def test_run_smoke_checks_reports_a_pass_affirmatively_not_just_silence(monkeypatch):
    import steadystate.probe.custom as mod

    with _server(200, "all ok here") as good, _server(503, "down") as bad:
        monkeypatch.setattr(mod, "load_checks", lambda _p="": _two_http_checks(good, bad))
        by = {r.name: r for r in run_smoke_checks()}
    assert (
        by["gw-smoke"].passed is True and by["gw-smoke"].detail == ""
    )  # a PASS is SHOWN, not silent
    assert by["gw-smoke"].kind == "http" and by["gw-smoke"].target.endswith("/health")
    assert by["db-smoke"].passed is False and "503" in by["db-smoke"].detail


def test_smoke_verb_renders_failures_first_and_dispatches(monkeypatch):
    import steadystate.probe.custom as mod
    from steadystate.inbound.base import SMOKE, Command
    from steadystate.inbound.server import _render_smoke, run_command

    with _server(200, "all ok here") as good, _server(503, "down") as bad:
        monkeypatch.setattr(mod, "load_checks", lambda _p="": _two_http_checks(good, bad))
        out = _render_smoke()
        assert "1 pass, 1 FAIL" in out
        assert out.index("[FAIL]") < out.index("[PASS]")  # failures lead -- the thing that matters
        assert "gw-smoke" in out and "db-smoke" in out
        # rides the chat/MCP grammar like any other verb
        assert "FAIL" in run_command(Command(SMOKE, "mcp"), ":memory:")


def test_smoke_with_no_http_checks_is_a_clear_note(monkeypatch):
    import steadystate.probe.custom as mod
    from steadystate.inbound.server import _render_smoke

    monkeypatch.setattr(mod, "load_checks", lambda _p="": [])
    assert run_smoke_checks() == []
    assert "no smoke tests" in _render_smoke()


# -- the `health` verdict: smoke (active) + impaired (passive) -> WORKING/DEGRADED/DOWN ----------


def test_health_verdict_combines_smoke_and_impaired(monkeypatch, tmp_path):
    import steadystate.probe.custom as mod
    from steadystate.inbound.server import _render_health
    from steadystate.state import StateStore

    db = str(tmp_path / "s.db")
    # an impaired finding in the store (a live symptom)
    from datetime import UTC, datetime

    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "gw 5xx spike")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Unhealthy", "namespace": "akeyless"}},
        )

    with _server(200, "all ok here") as good:  # smoke passes, but a symptom is open -> DEGRADED
        monkeypatch.setattr(mod, "load_checks", lambda _p="": _two_http_checks(good, good)[:1])
        out = _render_health(db)
        assert out.startswith("DEGRADED") and "1 impaired" in out and "1/1 pass" in out

    with _server(503, "down") as bad:  # smoke FAILS -> DOWN (it actively isn't working)
        monkeypatch.setattr(mod, "load_checks", lambda _p="": _two_http_checks(bad, bad)[:1])
        out = _render_health(db)
        assert out.startswith("DOWN") and "[smoke FAIL]" in out

    # nothing impaired + smoke passes -> WORKING
    empty = str(tmp_path / "empty.db")
    with StateStore(empty):
        pass
    with _server(200, "all ok here") as good:
        monkeypatch.setattr(mod, "load_checks", lambda _p="": _two_http_checks(good, good)[:1])
        assert _render_health(empty).startswith("WORKING")


def test_health_scopes_to_a_workload_and_correlates_smoke_symptom_drift(monkeypatch, tmp_path):
    from datetime import UTC, datetime

    import steadystate.probe.custom as mod
    from steadystate.inbound.server import _render_health
    from steadystate.state import StateStore

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {
                "a" * 64: ("high", "akeyless-gateway 5xx spike"),
                "b" * 64: ("high", "akeyless-gateway image drifted"),
                "c" * 64: ("medium", "db slow query"),  # an UNRELATED workload
            },
            datetime.now(UTC),
            {
                "a" * 64: {"category": "Unhealthy", "workload": "akeyless-gateway"},  # symptom
                "b" * 64: {
                    "change": "MODIFIED",
                    "kind": "deployment",
                    "workload": "akeyless-gateway",
                },
                "c" * 64: {"category": "Slow", "workload": "db"},
            },
        )
    with _server(503, "down") as gw:
        check = parse_check(
            {**_SMOKE, "name": "akeyless-gateway-smoke", "read": {"kind": "http", "url": gw}}
        )
        monkeypatch.setattr(mod, "load_checks", lambda _p="": [check])
        out = _render_health(db, workload="akeyless-gateway")
    assert out.startswith("DOWN") and "akeyless-gateway" in out
    assert "smoke FAIL" in out and "5xx spike" in out  # the active probe + the live symptom
    assert "likely cause" in out and "image drifted" in out  # correlated to the config drift
    assert "db slow query" not in out  # the unrelated workload is scoped out
