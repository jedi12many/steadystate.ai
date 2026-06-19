"""Evidence collectors (Layer 1 of the investigator): the deterministic, read-only gathering that
fattens the RCA bundle beyond the logs. These pin the kubectl-JSON renderers (pure), the registry's
best-effort gather, and the wiring into the evidence bundle + the `analyze` verb."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.probe.kubectl import render_events, render_pod_status, render_rollout
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


def test_render_rollout_flags_an_in_progress_deploy_with_image_and_timing():
    doc = {
        "metadata": {"generation": 5},
        "spec": {
            "replicas": 3,
            "template": {"spec": {"containers": [{"image": "api:v2-bad"}]}},
        },
        "status": {
            "observedGeneration": 4,
            "updatedReplicas": 1,
            "availableReplicas": 2,
            "unavailableReplicas": 1,
            "conditions": [
                {
                    "type": "Progressing",
                    "status": "True",
                    "reason": "ReplicaSetUpdated",
                    "lastUpdateTime": "2026-06-19T10:00:00Z",
                    "message": 'ReplicaSet "api-abc" is progressing.',
                }
            ],
        },
    }
    out = render_rollout(doc)
    assert "images: api:v2-bad" in out  # what a bad bump changed
    assert "rollout in progress" in out  # generation 5 != observed 4
    assert "unavailable=1" in out and "desired=3" in out
    assert "Progressing: True reason=ReplicaSetUpdated at 2026-06-19T10:00:00Z" in out  # WHEN/why


def test_render_rollout_surfaces_statefulset_mid_rollout_revisions():
    doc = {
        "metadata": {"generation": 2},
        "spec": {"template": {"spec": {"containers": []}}},
        "status": {"currentRevision": "web-1", "updateRevision": "web-2"},
    }
    out = render_rollout(doc)
    assert "current=web-1 update=web-2" in out and "mid-rollout" in out


# -- gather: best-effort, wraps probe output as cited Evidence --------------------


class _FakeProbe:
    """A duck-typed probe: canned strings per read method; ``raises`` names one that blows up."""

    def __init__(
        self,
        status: str = "",
        events: str = "",
        rollout: str = "",
        logs: str = "",
        raises: str = "",
    ) -> None:
        self._status, self._events = status, events
        self._rollout, self._logs, self._raises = rollout, logs, raises

    def _maybe_raise(self, which: str) -> None:
        if self._raises == which:
            raise RuntimeError("boom")

    def pod_status(self, namespace: str, pod: str) -> str:
        self._maybe_raise("pod_status")
        return self._status

    def events_for(self, namespace: str, pod: str) -> str:
        self._maybe_raise("events")
        return self._events

    def rollout_status(self, namespace: str, kind: str, name: str) -> str:
        self._maybe_raise("rollout")
        return self._rollout

    def logs_for_analysis(self, namespace: str, pod: str) -> str:
        self._maybe_raise("pod_logs")
        return self._logs


def _ctx(probe, details: dict | None = None) -> CollectCtx:
    return CollectCtx(finding=_finding(details or {}), probe=probe, namespace="prod", pod="api-7f9")


def test_gather_wraps_each_nonempty_read_as_cited_evidence_in_read_order():
    probe = _FakeProbe(
        status="restarts=7", events="OOMKilling", rollout="images: api:v2", logs="boom"
    )
    out = gather(_ctx(probe, {"kind": "Deployment", "workload": "api"}))
    assert [e.label for e in out] == [  # registry order: facts, change, timeline, logs (last)
        "pod status / last termination",
        "recent rollout (a likely trigger)",
        "cluster events for the pod",
        "logs re-fetched live at analyze time (current + previous container)",
    ]
    by_label = {e.label: e for e in out}
    assert (
        by_label["pod status / last termination"].provenance
        == "kubectl get pod api-7f9 -n prod -o json"
    )
    assert by_label["recent rollout (a likely trigger)"].provenance == (
        "kubectl get deployment api -n prod -o json"
    )
    assert "involvedObject.name=api-7f9" in by_label["cluster events for the pod"].provenance


def test_rollout_collector_only_fires_for_a_deployment_or_statefulset():
    probe = _FakeProbe(rollout="images: api:v2")
    # a node / bare-pod finding carries no kind -> no rollout block
    assert [e.label for e in gather(_ctx(probe, {}))] == []
    # a StatefulSet finding does
    out = gather(_ctx(probe, {"kind": "StatefulSet", "workload": "web"}))
    assert [e.label for e in out] == ["recent rollout (a likely trigger)"]


def test_gather_skips_empty_reads():
    out = gather(_ctx(_FakeProbe(status="", events="OOMKilling")))
    assert [e.label for e in out] == ["cluster events for the pod"]  # no status block when blank


def test_gather_is_best_effort_a_raising_collector_is_skipped_not_fatal():
    # pod_status raises; events still returns -- a bad read narrows evidence, never fails analyze.
    out = gather(_ctx(_FakeProbe(events="OOMKilling", raises="pod_status")))
    assert [e.label for e in out] == ["cluster events for the pod"]


# -- the bundle renders collected evidence, cited, in order -----------------------


def test_evidence_bundle_renders_collected_blocks_with_provenance_and_logs_last():
    collected = [
        Evidence(
            "pod status / last termination",
            "lastTerminated=OOMKilled exit=137",
            "kubectl get pod api-7f9 -n prod -o json",
        ),
        Evidence(
            "logs re-fetched live at analyze time (current + previous container)",
            "fresh tail here",
            "kubectl logs api-7f9 -n prod --tail --previous / (current)",
        ),
    ]
    bundle = _evidence_bundle(_finding({"workload": "api"}), collected=collected)
    assert "pod status / last termination" in bundle
    assert "lastTerminated=OOMKilled exit=137" in bundle
    assert "via `kubectl get pod api-7f9 -n prod -o json`" in bundle  # the citation rides along
    assert bundle.index("OOMKilled") < bundle.index("fresh tail here")  # facts frame the logs
