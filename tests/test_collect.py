"""Evidence collectors (Layer 1 of the investigator): the deterministic, read-only gathering that
fattens the RCA bundle beyond the logs. These pin the kubectl-JSON renderers (pure), the registry's
best-effort gather, and the wiring into the evidence bundle + the `analyze` verb."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.probe.kubectl import render_events, render_pod_status
from steadystate.reason.analyze import _evidence_bundle
from steadystate.reason.collect import CollectCtx, Evidence, gather
from steadystate.state import Finding


def _finding(details: dict) -> Finding:
    now = datetime.now(UTC).isoformat()
    return Finding(
        fingerprint="c" * 64,
        first_seen=now,
        last_seen=now,
        last_severity="high",
        last_title="api is CrashLoopBackOff in prod",
        status="open",
        details=details,
    )


# -- the kubectl-JSON renderers are pure (no cluster needed) ----------------------


def test_render_pod_status_surfaces_the_oom_smoking_gun():
    doc = {
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "False", "reason": "ContainersNotReady"}],
            "containerStatuses": [
                {
                    "name": "api",
                    "restartCount": 7,
                    "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                    "lastState": {
                        "terminated": {
                            "reason": "OOMKilled",
                            "exitCode": 137,
                            "finishedAt": "2026-06-19T10:00:00Z",
                        }
                    },
                }
            ],
        }
    }
    out = render_pod_status(doc)
    assert "restarts=7" in out  # the recurrence
    assert "waiting=CrashLoopBackOff" in out
    assert (
        "lastTerminated=OOMKilled" in out and "exit=137" in out
    )  # the smoking gun a log tail misses
    assert "Ready: False (ContainersNotReady)" in out


def test_render_pod_status_empty_doc_is_blank():
    assert render_pod_status({}) == ""


def test_render_events_orders_oldest_last_and_bounds():
    items = [
        {
            "lastTimestamp": f"2026-06-19T10:{n:02d}:00Z",
            "type": "Normal",
            "reason": f"E{n}",
            "message": f"event {n}",
        }
        for n in range(20)
    ]
    items.append(
        {
            "lastTimestamp": "2026-06-19T09:00:00Z",
            "type": "Warning",
            "reason": "OOMKilling",
            "count": 3,
            "message": "Memory  cgroup\nout of memory",
        }
    )
    out = render_events({"items": items})
    lines = out.splitlines()
    assert len(lines) == 15  # bounded to the last 15 by timestamp
    assert lines[-1].endswith("event 19") and "E19" in lines[-1]  # newest last
    assert "event 0" not in out  # the oldest Normal events dropped by the bound
    # the early Warning (sorts oldest) is dropped here; the renderer collapses whitespace + count
    rendered = render_events({"items": items[-1:]})
    assert "Warning" in rendered and "OOMKilling x3" in rendered
    assert "Memory cgroup out of memory" in rendered  # newlines/double-spaces collapsed


# -- gather: best-effort, wraps probe output as cited Evidence --------------------


class _FakeProbe:
    """A duck-typed probe: returns canned strings for the two read methods."""

    def __init__(self, status: str = "", events: str = "", raises: str = "") -> None:
        self._status, self._events, self._raises = status, events, raises

    def pod_status(self, namespace: str, pod: str) -> str:
        if self._raises == "pod_status":
            raise RuntimeError("boom")
        return self._status

    def events_for(self, namespace: str, pod: str) -> str:
        if self._raises == "events":
            raise RuntimeError("boom")
        return self._events


def _ctx(probe) -> CollectCtx:
    return CollectCtx(finding=_finding({}), probe=probe, namespace="prod", pod="api-7f9")


def test_gather_wraps_each_nonempty_read_as_cited_evidence():
    out = gather(_ctx(_FakeProbe(status="restarts=7", events="OOMKilling")))
    by_label = {e.label: e for e in out}
    assert "pod status / last termination" in by_label and "cluster events for the pod" in by_label
    status = by_label["pod status / last termination"]
    assert status.body == "restarts=7"
    assert status.provenance == "kubectl get pod api-7f9 -n prod -o json"  # the citation
    events = by_label["cluster events for the pod"]
    assert "involvedObject.name=api-7f9" in events.provenance


def test_gather_skips_empty_reads():
    out = gather(_ctx(_FakeProbe(status="", events="OOMKilling")))
    assert [e.label for e in out] == ["cluster events for the pod"]  # no status block when blank


def test_gather_is_best_effort_a_raising_collector_is_skipped_not_fatal():
    # pod_status raises; events still returns -- a bad read narrows evidence, never fails analyze.
    out = gather(_ctx(_FakeProbe(events="OOMKilling", raises="pod_status")))
    assert [e.label for e in out] == ["cluster events for the pod"]


# -- the bundle renders collected evidence, cited, before the logs ----------------


def test_evidence_bundle_renders_collected_blocks_with_provenance_before_logs():
    collected = [
        Evidence(
            "pod status / last termination",
            "lastTerminated=OOMKilled exit=137",
            "kubectl get pod api-7f9 -n prod -o json",
        ),
    ]
    bundle = _evidence_bundle(
        _finding({"workload": "api"}), collected=collected, live_logs="fresh tail here"
    )
    assert "pod status / last termination" in bundle
    assert "lastTerminated=OOMKilled exit=137" in bundle
    assert "via `kubectl get pod api-7f9 -n prod -o json`" in bundle  # the citation rides along
    assert bundle.index("OOMKilled") < bundle.index("fresh tail here")  # facts frame the logs
