"""Prometheus surface tests -- pure-format assertions plus a network-mocked emit.

Mirrors test_slack.py / test_teams.py: format_* is exercised without any network
(the clock is pinned), and the emit path is checked by monkeypatching urllib so no
socket is ever opened.
"""

import logging

from steadystate.notify.prometheus import PrometheusSurface, format_prometheus_metrics
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.cost import LlmCall
from steadystate.reason.report import Report

_PINNED = 1_700_000_000.0  # a fixed unix time so exposition output is stable


def _case(**overrides) -> Alert:
    base = {
        "title": "Public S3 bucket",
        "severity": Severity.HIGH,
        "drifts": [],
        "why_it_matters": "aws_s3_bucket.logs went from private to public-read.",
        "recommended_action": "Re-apply terraform to restore the private ACL.",
    }
    base.update(overrides)
    return Alert(**base)


def _metric_lines(text: str) -> list[str]:
    """Just the sample lines (drop # HELP / # TYPE)."""
    return [ln for ln in text.splitlines() if ln and not ln.startswith("#")]


def _value(text: str, name: str) -> str:
    """The value of a no-label metric line `name <value>`."""
    for ln in _metric_lines(text):
        if ln.startswith(name + " "):
            return ln.split(" ", 1)[1]
    raise AssertionError(f"metric {name!r} not found in:\n{text}")


# --- format_prometheus_metrics ----------------------------------------------


def test_format_has_help_and_type_for_each_metric():
    text = format_prometheus_metrics(Report(items=[_case()]), now=_PINNED)
    for name in (
        "steadystate_alerts",
        "steadystate_alerts_total",
        "steadystate_signals_total",
        "steadystate_resolved_total",
        "steadystate_last_scan_timestamp_seconds",
    ):
        assert f"# HELP {name} " in text
        assert f"# TYPE {name} gauge" in text


def test_format_emits_every_severity_including_zeros():
    # One HIGH alert: high=1, the other three severities still appear as 0.
    text = format_prometheus_metrics(Report(items=[_case(severity=Severity.HIGH)]), now=_PINNED)
    assert 'steadystate_alerts{severity="high"} 1' in text
    assert 'steadystate_alerts{severity="low"} 0' in text
    assert 'steadystate_alerts{severity="medium"} 0' in text
    assert 'steadystate_alerts{severity="critical"} 0' in text


def test_format_counts_per_severity():
    report = Report(
        items=[
            _case(severity=Severity.HIGH),
            _case(severity=Severity.HIGH),
            _case(severity=Severity.CRITICAL),
        ]
    )
    text = format_prometheus_metrics(report, now=_PINNED)
    assert 'steadystate_alerts{severity="high"} 2' in text
    assert 'steadystate_alerts{severity="critical"} 1' in text
    assert _value(text, "steadystate_alerts_total") == "3"


def test_format_alerts_total_and_signals_and_resolved():
    # A SIGNAL-layer item is counted in signals, not alerts.
    signal = _case(layer=Layer.SIGNAL, severity=Severity.LOW)
    report = Report(items=[_case(), signal])

    class _Resolved:
        fingerprint = "fp"
        title = "cleared"

    text = format_prometheus_metrics(report, resolved=[_Resolved(), _Resolved()], now=_PINNED)
    assert _value(text, "steadystate_alerts_total") == "1"  # only the ALERT-layer item
    assert _value(text, "steadystate_signals_total") == "1"
    assert _value(text, "steadystate_resolved_total") == "2"


def test_format_resolved_defaults_to_zero_when_none():
    text = format_prometheus_metrics(Report(items=[_case()]), now=_PINNED)
    assert _value(text, "steadystate_resolved_total") == "0"


def test_format_pins_timestamp():
    text = format_prometheus_metrics(Report(items=[_case()]), now=_PINNED)
    assert _value(text, "steadystate_last_scan_timestamp_seconds") == str(_PINNED)


def test_format_timestamp_defaults_to_now(monkeypatch):
    monkeypatch.setattr("steadystate.notify.prometheus.time.time", lambda: 42.5)
    text = format_prometheus_metrics(Report(items=[_case()]))
    assert _value(text, "steadystate_last_scan_timestamp_seconds") == "42.5"


def test_format_escapes_label_values(monkeypatch):
    # A severity carrying exposition metacharacters must be escaped, not leaked raw.
    from steadystate.notify import prometheus

    monkeypatch.setattr(prometheus, "_SEVERITIES", ('a"b\\c\nd',))
    text = prometheus.format_prometheus_metrics(Report(items=[]), now=_PINNED)
    assert 'steadystate_alerts{severity="a\\"b\\\\c\\nd"} 0' in text


def test_format_ends_with_newline():
    text = format_prometheus_metrics(Report(items=[_case()]), now=_PINNED)
    assert text.endswith("\n")


# --- PrometheusSurface.emit (no network) ------------------------------------


def test_emit_pushes_once(monkeypatch):
    surface = PrometheusSurface(pushgateway_url="http://pushgw.test:9091")

    pushed: list[str] = []
    monkeypatch.setattr(surface, "_push", lambda body: pushed.append(body))

    surface.emit(Report(items=[_case(), _case(severity=Severity.CRITICAL)]))
    assert len(pushed) == 1  # a single snapshot, not one per alert
    assert "steadystate_alerts_total 2" in pushed[0]


def test_emit_push_puts_to_job_endpoint(monkeypatch):
    surface = PrometheusSurface(pushgateway_url="http://pushgw.test:9091/", job="steadystate")

    seen: dict[str, object] = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b""

    def _fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["data"] = request.data
        seen["content_type"] = request.headers.get("Content-type")
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    surface.emit(Report(items=[_case()]))
    assert seen["url"] == "http://pushgw.test:9091/metrics/job/steadystate"
    assert seen["method"] == "PUT"  # PUT replaces the job group
    assert isinstance(seen["data"], bytes) and seen["data"]
    assert str(seen["content_type"]).startswith("text/plain")


def test_no_pushgateway_degrades_honestly(monkeypatch, caplog):
    monkeypatch.delenv("PROMETHEUS_PUSHGATEWAY_URL", raising=False)
    surface = PrometheusSurface()
    assert surface.pushgateway_url is None

    pushed: list[str] = []
    monkeypatch.setattr(surface, "_push", lambda body: pushed.append(body))

    with caplog.at_level(logging.WARNING, logger="steadystate.notify.prometheus"):
        surface.emit(Report(items=[_case(), _case()]))

    assert pushed == []  # nothing sent, no network touched
    assert len(caplog.records) == 1  # one honest line, no crash
    assert "pushgateway" in caplog.text.lower()


def test_constructor_arg_overrides_missing_env(monkeypatch):
    monkeypatch.delenv("PROMETHEUS_PUSHGATEWAY_URL", raising=False)
    surface = PrometheusSurface(pushgateway_url="http://pushgw.test:9091")
    assert surface.pushgateway_url == "http://pushgw.test:9091"
    assert surface.job == "steadystate"  # default job name


# -- LLM spend metrics ----------------------------------------------------------


def test_metrics_include_llm_cost_total_and_per_caller():
    report = Report(
        items=[_case()],
        llm_calls=[
            LlmCall(
                "correlate", "anthropic", "claude-sonnet-4-6", input_tokens=1000, output_tokens=500
            ),
            LlmCall("correlate", "anthropic", "claude-sonnet-4-6", succeeded=False),  # failure row
            LlmCall(
                "analyze", "anthropic", "claude-opus-4-8", input_tokens=1000, output_tokens=1000
            ),
        ],
    )
    text = format_prometheus_metrics(report, now=_PINNED)

    assert float(_value(text, "steadystate_llm_cost_usd_total")) > 0
    assert _value(text, "steadystate_llm_calls_total") == "3"  # failures counted
    lines = _metric_lines(text)
    assert any('steadystate_llm_cost_usd{caller="correlate"}' in ln for ln in lines)
    assert any('steadystate_llm_cost_usd{caller="analyze"}' in ln for ln in lines)


def test_metrics_zero_llm_cost_when_no_calls():
    text = format_prometheus_metrics(Report(items=[_case()]), now=_PINNED)
    assert _value(text, "steadystate_llm_cost_usd_total") == "0"
    assert _value(text, "steadystate_llm_calls_total") == "0"
    # No per-caller breakdown when nothing was spent.
    assert not any("steadystate_llm_cost_usd{caller=" in ln for ln in _metric_lines(text))
