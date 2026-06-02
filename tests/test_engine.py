"""The scan engine (build_report): the shared path the CLI scan and the chat-summoned probe run.

The full drift/probe/reason pipeline is covered by the source/pipeline/scan tests; here we cover
the engine's own contract -- that it returns a Report, surfaces unknown config as ValueError (the
plain error the CLI turns into BadParameter and the listener echoes), and resolves probes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from steadystate.engine import SupportsContext, build_prober_for, build_report
from steadystate.probe.kubectl import KubectlProbe
from steadystate.reason.report import Report
from steadystate.sources.k8s import KubernetesLiveSource


def _plan(tmp_path, changes=None):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps({"resource_changes": changes or []}), encoding="utf-8")
    return path


def test_build_report_returns_a_clean_report_for_no_drift(tmp_path):
    report = build_report("terraform", _plan(tmp_path), no_llm=True)
    assert isinstance(report, Report)
    assert report.alerts == [] and report.llm_calls == []


def test_build_report_unknown_source_raises_valueerror(tmp_path):
    with pytest.raises(ValueError, match="unknown source"):
        build_report("nope", tmp_path / "x", no_llm=True)


def test_build_report_unknown_probe_raises_valueerror(tmp_path):
    with pytest.raises(ValueError, match="unknown prober"):
        build_report("terraform", _plan(tmp_path), probe="nope", no_llm=True)


def test_build_report_unknown_tuning_raises_valueerror(tmp_path):
    with pytest.raises(ValueError, match="Tuning"):
        build_report("terraform", _plan(tmp_path), tuning="loose", no_llm=True)


def test_build_prober_for_none_and_auto(tmp_path):
    assert build_prober_for("none", "terraform", tmp_path) is None
    # auto picks the probe matching the source -- none for terraform, the kubectl probe for k8s.
    # The source registers as "k8s" (the --source value); auto must key on that, not "kubernetes".
    assert build_prober_for("auto", "terraform", tmp_path) is None
    assert isinstance(build_prober_for("auto", "k8s", tmp_path), KubectlProbe)


# -- live cluster health: context threading (k8s-live) ----------------------------------------


def test_live_source_and_kubectl_probe_support_context():
    # build_report's contract: both opt into the SupportsContext seam so --context reaches them.
    assert isinstance(KubernetesLiveSource(), SupportsContext)
    assert isinstance(KubectlProbe(), SupportsContext)


def test_build_report_threads_context_to_source_and_probe(monkeypatch):
    # A crash-looping pod across a live cluster, aimed by --context: both the workload enumeration
    # (source) and the pod read (probe) must carry --context <ctx>.
    seen: list[list[str]] = []
    workloads = {
        "kind": "List",
        "items": [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"namespace": "prod", "name": "web"},
                "spec": {"template": {"spec": {"containers": [{"image": "web:1"}]}}},
            }
        ],
    }
    monkeypatch.setattr(
        "steadystate.sources.k8s.run_tool",
        lambda argv, **kw: seen.append(argv) or json.dumps(workloads),
    )
    pods = {
        "items": [
            {
                "metadata": {"name": "web-abc", "namespace": "prod"},
                "status": {
                    "phase": "Running",
                    "containerStatuses": [
                        {"restartCount": 9, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
                    ],
                },
            }
        ]
    }

    class _Result:
        stdout = json.dumps(pods)

    monkeypatch.setattr(
        "steadystate.probe.kubectl.subprocess.run",
        lambda argv, **kw: seen.append(argv) or _Result(),
    )

    report = build_report("k8s-live", Path("."), probe="auto", context="prod-cluster", no_llm=True)
    # The fire surfaced...
    assert any("CrashLoopBackOff" in (a.title or "") for a in report.alerts)
    # ...and every kubectl call (workload enum + pod read) was aimed at the context.
    assert seen and all("--context" in argv and "prod-cluster" in argv for argv in seen)
