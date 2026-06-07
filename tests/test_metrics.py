"""The metric-source seam: rent monitoring (Prometheus first), feed named readings to the agent.
The Prometheus HTTP API is faked with a local server -- no real Prometheus. The point: a reading we
can take is surfaced; one we can't degrades to *unavailable* (never a crash, never a guess)."""

from __future__ import annotations

import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from steadystate.metrics import (
    PrometheusMetrics,
    build_metric_source,
    fetch_metrics,
    load_metric_queries,
)


@contextlib.contextmanager
def _prometheus(value: str = "4.2", status: str = "success", result_type: str = "vector"):
    """A fake Prometheus /api/v1/query returning one series with ``value`` (or an error/empty)."""

    class _H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if result_type == "empty":
                data = {"resultType": "vector", "result": []}
            elif result_type == "scalar":
                data = {"resultType": "scalar", "result": [1700000000, value]}
            else:
                data = {"resultType": "vector", "result": [{"metric": {}, "value": [1.7e9, value]}]}
            body = json.dumps({"status": status, "data": data}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            return

    httpd = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()


_QUERIES = {"p99_latency": "histogram_quantile(0.99, x)", "error_rate": "rate(errors[5m])"}


# -- config --------------------------------------------------------------------


def test_load_metric_queries_reads_the_map_and_tolerates_missing_or_bad(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_METRIC_QUERIES", str(tmp_path / "metrics.json"))
    assert load_metric_queries() == {}  # missing -> {}
    (tmp_path / "metrics.json").write_text(json.dumps(_QUERIES))
    assert load_metric_queries() == _QUERIES
    (tmp_path / "metrics.json").write_text("{ not json")
    assert load_metric_queries() == {}  # malformed -> {}, no crash


# -- the Prometheus adapter ----------------------------------------------------


def test_prometheus_fetches_named_readings(monkeypatch):
    with _prometheus(value="4.2") as url:
        src = PrometheusMetrics(base_url=url, queries={"p99_latency": "q"})
        readings = {m.name: m for m in src.fetch()}
    assert readings["p99_latency"].available and readings["p99_latency"].value == pytest.approx(4.2)


def test_prometheus_scalar_result_is_read_too(monkeypatch):
    with _prometheus(value="0.06", result_type="scalar") as url:
        (reading,) = PrometheusMetrics(base_url=url, queries={"error_rate": "q"}).fetch()
    assert reading.available and reading.value == pytest.approx(0.06)


def test_a_reading_we_cannot_take_is_unavailable_not_a_guess():
    # unreachable -> unavailable (no number invented); same for an empty / error response
    down = PrometheusMetrics(base_url="http://127.0.0.1:1", queries={"x": "q"}).fetch()
    assert down[0].available is False and down[0].note
    with _prometheus(result_type="empty") as url:
        empty = PrometheusMetrics(base_url=url, queries={"x": "q"}).fetch()
    assert empty[0].available is False
    # no URL at all -> unavailable, named
    nourl = PrometheusMetrics(base_url="", queries={"x": "q"}).fetch()
    assert nourl[0].available is False and "PROMETHEUS_URL" in nourl[0].note


# -- the registry seam ---------------------------------------------------------


def test_build_metric_source_resolves_prometheus_and_rejects_unknown(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_METRICS_SOURCE", raising=False)
    monkeypatch.delenv("PROMETHEUS_URL", raising=False)
    assert build_metric_source() is None  # nothing configured -> the un-enriched path
    monkeypatch.setenv("PROMETHEUS_URL", "http://prom")
    assert isinstance(build_metric_source(), PrometheusMetrics)  # inferred from the URL
    with pytest.raises(ValueError, match="unknown metric source"):
        build_metric_source("datadog")  # not registered (yet) -> a clean error


def test_fetch_metrics_is_a_no_op_without_queries(monkeypatch, tmp_path):
    monkeypatch.setenv("STEADYSTATE_METRIC_QUERIES", str(tmp_path / "none.json"))
    assert fetch_metrics() == []  # no queries -> [], no source built, no network


# -- the `metrics` verb --------------------------------------------------------


def test_metrics_verb_renders_and_is_read_only(monkeypatch, tmp_path):
    from steadystate.inbound.base import METRICS, Command
    from steadystate.inbound.mcp import mcp_tools
    from steadystate.inbound.server import run_command

    monkeypatch.setenv("STEADYSTATE_METRIC_QUERIES", str(tmp_path / "metrics.json"))
    (tmp_path / "metrics.json").write_text(json.dumps({"p99_latency": "q"}))
    with _prometheus(value="4.2") as url:
        monkeypatch.setenv("PROMETHEUS_URL", url)
        out = run_command(Command(METRICS, "mcp"), ":memory:")
    assert "p99_latency" in out and "4.2" in out
    # read-only -> an agent can pull metric context without a write grant
    assert "metrics" in {t["name"] for t in mcp_tools(write=False)}


def test_health_folds_in_the_metric_context(monkeypatch, tmp_path):
    # the agent's verdict + WHY, now with the live monitoring numbers alongside it
    from datetime import UTC, datetime

    import steadystate.probe.custom as custom
    from steadystate.inbound.server import _render_health
    from steadystate.state import StateStore

    monkeypatch.setenv("STEADYSTATE_METRIC_QUERIES", str(tmp_path / "metrics.json"))
    (tmp_path / "metrics.json").write_text(json.dumps({"p99_latency": "q"}))
    monkeypatch.setattr(custom, "load_checks", lambda _p="": [])  # no smoke checks
    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record(
            {"a" * 64: ("high", "gateway 5xx spike")},
            datetime.now(UTC),
            {"a" * 64: {"category": "Unhealthy", "workload": "gateway"}},
        )
    with _prometheus(value="4.2") as url:
        monkeypatch.setenv("PROMETHEUS_URL", url)
        out = _render_health(db, workload="gateway")
    assert out.startswith("DEGRADED")  # verdict unchanged -- metrics are CONTEXT, not part of it
    assert "metrics:" in out and "p99_latency 4.2" in out  # monitoring folded in next to the verdict
