"""Pluggable metric sources -- rent the monitoring you already have, feed it to the agent.

steadystate is not a monitoring system; it *consumes* one. A ``MetricSource`` fetches a handful of
named numeric readings (p99 latency, error rate, saturation, ...) from your monitoring backend, so
the agent reasons over steadystate's truth (drift, symptoms, the `health` verdict) **and** the live
metrics -- without us re-implementing a time-series database (the part that's already done better).

This is a registered seam, the same shape as sources / probes / surfaces: a name -> factory in
``METRIC_SOURCES``, resolved by ``build_metric_source``. **Prometheus** ships first; Datadog /
CloudWatch / ... are one registry entry away -- "rent any monitoring," fed to the agent uniformly.

*What* to read is operator config: a JSON map ``{name: query}`` at ``STEADYSTATE_METRIC_QUERIES``
(default ``.steadystate/metrics.json``) -- e.g. ``{"p99_latency": "histogram_quantile(0.99, ..)"}``.
A reading we can't take degrades to *unavailable* (never a crash, never a made-up number)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ._http import safe_urlopen

DEFAULT_METRICS_FILE = ".steadystate/metrics.json"
METRICS_QUERIES_ENV = "STEADYSTATE_METRIC_QUERIES"
METRICS_SOURCE_ENV = "STEADYSTATE_METRICS_SOURCE"


@dataclass(frozen=True)
class Metric:
    """One named numeric reading. ``available`` is False when the source couldn't return it (a
    flaky backend, an empty query) -- we surface the gap honestly rather than invent a value."""

    name: str
    value: float = 0.0
    available: bool = True
    note: str = ""  # the reason when unavailable, or an optional unit/label


@runtime_checkable
class MetricSource(Protocol):
    """A monitoring backend steadystate reads named metrics from. One method: fetch the configured
    readings. Implementations live behind ``METRIC_SOURCES`` so adding one never touches callers."""

    def fetch(self) -> list[Metric]: ...


def resolve_metric_queries_path(explicit: str = "") -> str:
    return explicit or os.environ.get(METRICS_QUERIES_ENV, "").strip() or DEFAULT_METRICS_FILE


def load_metric_queries(path: str = "") -> dict[str, str]:
    """The operator's ``{name: query}`` map. Missing / malformed -> {} (the un-enriched path)."""
    resolved = Path(resolve_metric_queries_path(path))
    if not resolved.exists():
        return {}
    try:
        data = json.loads(resolved.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str) and v}


class PrometheusMetrics:
    """Read named metrics from a Prometheus HTTP API (instant queries). Each configured PromQL is
    one ``/api/v1/query``; the first series' value is the reading. A flaky Prometheus degrades to
    *unavailable* per metric -- never a crash, never a guessed number. http(s)-gated, read-only."""

    name = "prometheus"

    def __init__(
        self, base_url: str = "", queries: dict[str, str] | None = None, timeout: float = 10.0
    ) -> None:
        self.base_url = base_url or os.environ.get("PROMETHEUS_URL", "")
        self.queries = queries if queries is not None else load_metric_queries()
        self.timeout = timeout

    def fetch(self) -> list[Metric]:
        if not self.base_url:
            return [Metric(n, available=False, note="no PROMETHEUS_URL") for n in self.queries]
        out: list[Metric] = []
        for name, promql in self.queries.items():
            value = self._instant(promql)
            if value is None:
                out.append(Metric(name, available=False, note="no data"))
            else:
                out.append(Metric(name, value))
        return out

    def _instant(self, promql: str) -> float | None:
        """The scalar value of an instant query, or None (unreachable / empty / non-numeric)."""
        query_string = urllib.parse.urlencode({"query": promql})
        url = f"{self.base_url.rstrip('/')}/api/v1/query?{query_string}"
        try:
            with safe_urlopen(url, timeout=self.timeout) as response:
                payload = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError):
            return None
        if not isinstance(payload, dict) or payload.get("status") != "success":
            return None
        data = payload.get("data", {})
        result = data.get("result")
        raw = None
        if data.get("resultType") == "scalar" and isinstance(result, list) and len(result) == 2:
            raw = result[1]  # scalar: [timestamp, "value"]
        elif isinstance(result, list) and result and isinstance(result[0], dict):
            raw = result[0].get("value", [None, None])[1]  # vector: first series' value
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None


# The registry: a name -> factory. A new backend (datadog, cloudwatch) registers here.
METRIC_SOURCES: dict[str, type] = {"prometheus": PrometheusMetrics}


def build_metric_source(name: str = "") -> MetricSource | None:
    """Resolve a metric source by name (or ``STEADYSTATE_METRICS_SOURCE``, else ``prometheus`` when
    a ``PROMETHEUS_URL`` is set). None when none is configured -- the un-enriched path. ValueError
    for an unknown name, mirroring the other registries."""
    name = name or os.environ.get(METRICS_SOURCE_ENV, "").strip()
    if not name:
        name = "prometheus" if os.environ.get("PROMETHEUS_URL", "").strip() else ""
    if not name:
        return None
    factory = METRIC_SOURCES.get(name)
    if factory is None:
        have = ", ".join(sorted(METRIC_SOURCES))
        raise ValueError(f"unknown metric source: {name!r} (have: {have})")
    return factory()


def fetch_metrics(name: str = "", workload: str = "") -> list[Metric]:
    """Build the configured metric source and fetch its readings. [] when none is configured or no
    queries are defined -- a cheap no-op. ``workload`` (when given) fills the ``$WORKLOAD``
    placeholder in each query, so ``...{app="$WORKLOAD"}...`` scopes to that workload while queries
    without it stay global. Read-only; the agent's metric context, on demand."""
    queries = load_metric_queries()
    if not queries:
        return []
    source = build_metric_source(name)
    if source is None:
        return []
    if workload and hasattr(source, "queries"):
        source.queries = {n: q.replace("$WORKLOAD", workload) for n, q in queries.items()}
    return source.fetch()
