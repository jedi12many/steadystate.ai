"""The probe seam: the Symptom value type, the KubectlProbe, and the registry."""

from __future__ import annotations

import pytest

from steadystate.model import Provenance, Resource
from steadystate.probe import PROBE_CAPABILITIES, PROBES, auto_prober_for, build_prober
from steadystate.probe.base import Symptom
from steadystate.probe.kubectl import (
    KubectlProbe,
    PodHealth,
    category_and_severity,
    scan_log_text,
    unhealthy_pods,
)
from steadystate.reason.alert import Severity


def test_probe_capabilities_cover_every_registered_probe():
    # A probe registered without a declared command manifest would slip past `steadystate commands`
    # and the catalog -- this fails if the two registries drift apart.
    assert set(PROBE_CAPABILITIES) == set(PROBES)


def test_probes_are_observe_only_and_declare_kubectl_logs():
    for name, caps in PROBE_CAPABILITIES.items():
        assert caps.destructive == (), f"{name} probe must not declare a destructive command"
    # The whole point: `kubectl logs` (the failing pod's evidence) is now a declared observe cmd.
    assert any("kubectl logs" in cmd for cmd in PROBE_CAPABILITIES["kubectl"].observe)
    assert any("docker logs" in cmd for cmd in PROBE_CAPABILITIES["docker"].observe)


def test_probe_manifest_matches_what_the_probe_actually_runs():
    # The kubectl probe shells out to `kubectl get pods` and `kubectl logs`; both must be declared.
    declared = " ".join(PROBE_CAPABILITIES["kubectl"].observe)
    assert "kubectl get pods" in declared and "kubectl logs" in declared


def _symptom(category: str = "CrashLoopBackOff", identity: str = "apps/Deployment/prod/web"):
    return Symptom(
        identity=identity,
        kind="Deployment",
        category=category,
        severity=Severity.HIGH,
        title=f"x is {category}",
        detail="2 pod(s)",
        provenance=Provenance(source="kubernetes", address=identity),
    )


def _pod(name: str, *, waiting: str | None = None, phase: str = "Running", restarts: int = 0):
    state = {"waiting": {"reason": waiting}} if waiting else {}
    container = {"restartCount": restarts, "state": state}
    status = {"phase": phase, "containerStatuses": [container]}
    return {"metadata": {"name": name}, "status": status}


def _pods(*items: dict) -> dict:
    return {"items": list(items)}


def _resource(identity: str = "apps/Deployment/prod/web", source: str = "kubernetes") -> Resource:
    return Resource(
        kind="Deployment",
        identity=identity,
        provenance=Provenance(source=source, address=identity),
    )


# -- the Symptom value type -----------------------------------------------------


def test_fingerprint_stable_and_distinct_per_category():
    assert _symptom("CrashLoopBackOff").fingerprint == _symptom("CrashLoopBackOff").fingerprint
    assert _symptom("CrashLoopBackOff").fingerprint != _symptom("ImagePullBackOff").fingerprint
    assert _symptom(identity="a/b").fingerprint != _symptom(identity="a/c").fingerprint


def test_summary_reads_category_kind_identity():
    symptom = _symptom("CrashLoopBackOff")
    assert symptom.summary() == f"CrashLoopBackOff Deployment {symptom.identity}"


# -- unhealthy_pods (pure) ------------------------------------------------------


def test_detects_crashloop():
    pods = _pods(_pod("web-abc-123", waiting="CrashLoopBackOff", restarts=7))
    [health] = unhealthy_pods(pods, "web")
    assert (health.name, health.reason, health.restarts) == ("web-abc-123", "CrashLoopBackOff", 7)


def test_detects_image_pull_and_failed_phase():
    pods = _pods(_pod("web-1", waiting="ImagePullBackOff"), _pod("web-2", phase="Failed"))
    assert {p.reason for p in unhealthy_pods(pods, "web")} == {"ImagePullBackOff", "Failed"}


def _evicted(name: str) -> dict:
    return {"metadata": {"name": name}, "status": {"phase": "Failed", "reason": "Evicted"}}


def test_evicted_pod_is_distinct_from_a_plain_failed_pod():
    pods = _pods(_evicted("web-1"), _pod("web-2", phase="Failed"))
    assert {p.name: p.reason for p in unhealthy_pods(pods, "web")} == {
        "web-1": "Evicted",  # phase Failed + reason Evicted -> Evicted, not generic Failed
        "web-2": "Failed",
    }


def test_evicted_is_medium_not_high():
    # a crash/ImagePull is HIGH (cannot run); an evicted pod is a dead tombstone -> MEDIUM cleanup.
    assert category_and_severity([PodHealth("web-1", "Evicted", 0)]) == ("Evicted", Severity.MEDIUM)


def test_evicted_symptom_recommends_a_cleanup(monkeypatch):
    # the whole point: the tool now OFFERS a fix for evicted pods -- the scoped cleanup command.
    prober = KubectlProbe()
    prober.use_context("prod-cluster")
    monkeypatch.setattr(prober, "_all_pods", lambda: {"prod": {"items": [_evicted("web-1")]}})
    monkeypatch.setattr(prober, "_last_log_line", lambda namespace, pod: "")
    [sym] = prober.probe([_resource()])  # _resource() lives in namespace "prod"
    assert sym.category == "Evicted" and sym.severity is Severity.MEDIUM
    assert sym.recommended_action == (
        "kubectl delete pods -n prod --field-selector=status.phase=Failed --context prod-cluster"
    )


def test_detects_restart_threshold_even_when_running():
    [pod] = unhealthy_pods(_pods(_pod("web-x", phase="Running", restarts=6)), "web")
    assert pod.reason == "6 restarts"


def test_healthy_pods_are_ignored():
    assert unhealthy_pods(_pods(_pod("web-ok", phase="Running", restarts=0)), "web") == []


def test_matches_only_workload_pods_by_prefix():
    pods = _pods(
        _pod("web-abc", waiting="CrashLoopBackOff"),  # belongs to web
        _pod("api-abc", waiting="CrashLoopBackOff"),  # a different workload
    )
    assert [p.name for p in unhealthy_pods(pods, "web")] == ["web-abc"]


def _owned_pod(
    name: str, controller: str, *, kind: str = "ReplicaSet", waiting: str = "CrashLoopBackOff"
) -> dict:
    """A pod with a controller ownerReference (the ReplicaSet for a Deployment, or the
    StatefulSet/DaemonSet directly) -- the real shape `kubectl get pods -o json` returns."""
    pod = _pod(name, waiting=waiting)
    pod["metadata"]["ownerReferences"] = [{"kind": kind, "name": controller, "controller": True}]
    return pod


def test_overlapping_names_do_not_claim_each_others_pods():
    # Two deployments in ONE namespace: squid and squid-proxy. Their pods are named by their own
    # ReplicaSets (squid-<hash> / squid-proxy-<hash>). Matching on the controller, squid must NOT
    # claim squid-proxy's pod (whose owner suffix is `proxy-<hash>`, not a bare hash).
    pods = _pods(
        _owned_pod("squid-7d8f9-aa", "squid-7d8f9"),
        _owned_pod("squid-proxy-1a2b3-bb", "squid-proxy-1a2b3"),
    )
    assert [p.name for p in unhealthy_pods(pods, "squid")] == ["squid-7d8f9-aa"]
    assert [p.name for p in unhealthy_pods(pods, "squid-proxy")] == ["squid-proxy-1a2b3-bb"]


def test_statefulset_pod_owner_is_the_workload_directly():
    # A StatefulSet/DaemonSet pod's controller IS the workload (no ReplicaSet in between), so the
    # sibling `db-proxy` StatefulSet must not be claimed by workload `db`.
    pods = _pods(
        _owned_pod("db-0", "db", kind="StatefulSet"),
        _owned_pod("db-proxy-0", "db-proxy", kind="StatefulSet"),
    )
    assert [p.name for p in unhealthy_pods(pods, "db")] == ["db-0"]


def test_bare_pod_without_a_controller_falls_back_to_name_prefix():
    # No ownerReferences -> the legacy name-prefix match still applies (unchanged behavior).
    pods = _pods(_pod("squid-x", waiting="CrashLoopBackOff"))
    assert [p.name for p in unhealthy_pods(pods, "squid")] == ["squid-x"]


def test_aggregates_restarts_across_containers():
    pod = {
        "metadata": {"name": "web-1"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"restartCount": 3, "state": {}},
                {"restartCount": 4, "state": {}},
            ],
        },
    }
    [health] = unhealthy_pods(_pods(pod), "web")
    assert health.restarts == 7 and health.reason == "7 restarts"


# -- category + severity (pure) -------------------------------------------------


def test_cannot_run_reason_is_high():
    sick = [PodHealth(name="web-1", reason="CrashLoopBackOff", restarts=9)]
    assert category_and_severity(sick) == ("CrashLoopBackOff", Severity.HIGH)


def test_restart_flap_is_medium():
    sick = [PodHealth(name="web-1", reason="7 restarts", restarts=7)]
    assert category_and_severity(sick) == ("7 restarts", Severity.MEDIUM)


def test_a_single_cannot_run_pod_makes_the_whole_symptom_high():
    sick = [
        PodHealth(name="web-1", reason="5 restarts", restarts=5),
        PodHealth(name="web-2", reason="CrashLoopBackOff", restarts=20),
    ]
    category, severity = category_and_severity(sick)
    assert severity is Severity.HIGH and category == "CrashLoopBackOff"


# -- the probe ------------------------------------------------------------------


def _probe(monkeypatch, pods: dict, log: str = "fatal: missing DB_URL"):
    prober = KubectlProbe()
    # `_resource()` lives in namespace "prod"; _all_pods returns pods grouped by namespace.
    monkeypatch.setattr(prober, "_all_pods", lambda: {"prod": pods})
    monkeypatch.setattr(prober, "_last_log_line", lambda namespace, pod: log)
    return prober


def test_probe_produces_a_symptom_for_an_unhealthy_declared_workload(monkeypatch):
    pods = {"items": [_pod("web-abc", waiting="CrashLoopBackOff", restarts=9)]}
    prober = _probe(monkeypatch, pods)
    [symptom] = prober.probe([_resource()])
    assert symptom.identity == "apps/Deployment/prod/web"
    assert symptom.category == "CrashLoopBackOff" and symptom.severity is Severity.HIGH
    assert "missing DB_URL" in symptom.detail  # the failing pod's last log line


def test_symptom_title_names_the_namespace_and_cluster(monkeypatch):
    # The title is the one field every surface shows (chat probe, scan panel, the remembered
    # `findings` row), so it must say WHERE -- namespace, and the cluster too on a fleet -- else a
    # `squid is CrashLoopBackOff` over many clusters/namespaces is unactionable.
    pods = {"items": [_pod("web-abc", waiting="CrashLoopBackOff", restarts=9)]}

    ambient = _probe(monkeypatch, pods)
    [sym] = ambient.probe([_resource()])  # _resource() lives in namespace "prod"
    assert sym.title == "web is CrashLoopBackOff in prod"  # single cluster -> namespace only

    fleet = _probe(monkeypatch, pods)
    fleet.use_context("prod-cluster")  # a target = a cluster -> qualify the title with it
    [sym2] = fleet.probe([_resource()])
    assert sym2.title == "web is CrashLoopBackOff in prod-cluster/prod"


def test_symptom_carries_structured_evidence_for_the_raw_view(monkeypatch):
    # The `show <fp>` view reads these fields out of the store -- the probe must capture them.
    pods = {"items": [_pod("web-abc", waiting="CrashLoopBackOff", restarts=9)]}
    prober = _probe(monkeypatch, pods)
    prober.use_context("prod-cluster")
    [sym] = prober.probe([_resource()])  # _resource() lives in namespace "prod"
    assert sym.evidence["namespace"] == "prod"
    assert sym.evidence["cluster"] == "prod-cluster"
    assert sym.evidence["workload"] == "web"
    assert sym.evidence["unhealthy_pods"] == "1"
    assert sym.evidence["pods"] == "web-abc"
    assert sym.evidence["max_restarts"] == "9"
    assert "missing DB_URL" in sym.evidence["last_log"]  # the raw error
    # no context -> no cluster field (a single ambient cluster needs no qualifier)
    [ambient] = _probe(monkeypatch, pods).probe([_resource()])
    assert "cluster" not in ambient.evidence


def test_probe_is_silent_on_a_healthy_workload(monkeypatch):
    prober = _probe(monkeypatch, {"items": [_pod("web-ok", phase="Running")]})
    assert prober.probe([_resource()]) == []


def test_probe_ignores_non_kubernetes_resources(monkeypatch):
    fetched: list[int] = []
    prober = KubectlProbe()
    monkeypatch.setattr(prober, "_all_pods", lambda: fetched.append(1) or {})
    assert prober.probe([_resource(identity="aws_s3_bucket.logs", source="terraform")]) == []
    assert fetched == []  # no kubernetes resource -> never even ran kubectl


def test_probe_degrades_when_kubectl_unavailable(monkeypatch):
    def boom(*args, **kwargs):
        raise FileNotFoundError("kubectl not found")

    monkeypatch.setattr("steadystate.probe.kubectl.subprocess.run", boom)
    assert KubectlProbe().probe([_resource()]) == []  # no cluster -> no symptoms, no raise


def test_all_pods_fetches_every_namespace_in_one_call(monkeypatch):
    import json

    doc = {
        "items": [
            {"metadata": {"name": "web-1", "namespace": "prod"}, "status": {}},
            {"metadata": {"name": "api-1", "namespace": "stg"}, "status": {}},
            {"metadata": {"name": "web-2", "namespace": "prod"}, "status": {}},
        ]
    }
    calls: list[list[str]] = []

    class _Result:
        stdout = json.dumps(doc)

    monkeypatch.setattr(
        "steadystate.probe.kubectl.subprocess.run",
        lambda argv, **kw: calls.append(argv) or _Result(),
    )
    grouped = KubectlProbe()._all_pods()
    assert len(calls) == 1 and "-A" in calls[0]  # ONE call, all namespaces -- not per-namespace
    assert set(grouped) == {"prod", "stg"}
    assert [p["metadata"]["name"] for p in grouped["prod"]["items"]] == ["web-1", "web-2"]


def test_probe_threads_context_into_every_kubectl_call(monkeypatch):
    calls: list[list[str]] = []

    class _Result:
        stdout = '{"items": []}'

    monkeypatch.setattr(
        "steadystate.probe.kubectl.subprocess.run",
        lambda argv, **kw: calls.append(argv) or _Result(),
    )
    prober = KubectlProbe()
    prober.use_context("prod-cluster")
    prober.probe([_resource()])  # a kubernetes resource -> one `kubectl get pods`
    assert calls and all(c[-2:] == ["--context", "prod-cluster"] for c in calls)


def test_probe_without_context_omits_the_flag(monkeypatch):
    calls: list[list[str]] = []

    class _Result:
        stdout = '{"items": []}'

    monkeypatch.setattr(
        "steadystate.probe.kubectl.subprocess.run",
        lambda argv, **kw: calls.append(argv) or _Result(),
    )
    KubectlProbe().probe([_resource()])
    assert calls and all("--context" not in c for c in calls)


# -- log-content detection (`probe --deep`) -------------------------------------


def test_scan_log_text_fatal_trips_once_errors_need_a_threshold():
    # a FATAL-class signature raises on a single hit...
    fatal = scan_log_text("starting\npanic: runtime error: nil pointer\ngoroutine 1", threshold=3)
    assert fatal is not None and fatal.fatal and "panic" in fatal.sample[0]
    # ...while plain errors must clear the threshold (a healthy app logs the odd one).
    assert scan_log_text("ERROR a\nERROR b\nERROR c", threshold=3).error_count == 3
    assert scan_log_text("ERROR a\nERROR b", threshold=3) is None  # below the bar
    # case-sensitive ERROR/FATAL, so prose doesn't trip it.
    assert scan_log_text("no error occurred; all good\nnothing to report", threshold=3) is None
    assert scan_log_text("", threshold=3) is None


def _deep(monkeypatch, prober, pods, log_text):
    monkeypatch.setattr(prober, "_all_pods", lambda: {"prod": pods})
    monkeypatch.setattr(prober, "_run_text", lambda argv, best_effort=False: log_text)
    monkeypatch.setattr(prober, "_last_log_line", lambda namespace, pod: "")
    return prober


def test_deep_probe_flags_a_running_pod_erroring_in_its_logs(monkeypatch):
    # a status-HEALTHY pod (Running, no restarts) whose logs panic -> an Erroring symptom (HIGH).
    prober = KubectlProbe()
    prober.use_context("prod-cluster")
    prober.enable_log_scan()
    _deep(monkeypatch, prober, {"items": [_pod("web-abc", phase="Running")]}, "ok\npanic: boom\nx")
    [sym] = prober.probe([_resource()])
    assert sym.category == "Erroring" and sym.severity is Severity.HIGH
    assert sym.title == "web is Erroring in prod-cluster/prod"  # names where, like a status symptom
    assert "panic: boom" in sym.evidence["sample"] and sym.evidence["fatal"] == "yes"


def test_non_fatal_log_errors_are_medium(monkeypatch):
    prober = KubectlProbe()
    prober.enable_log_scan()
    _deep(
        monkeypatch,
        prober,
        {"items": [_pod("web-abc", phase="Running")]},
        "ERROR a\nERROR b\nERROR c",
    )
    [sym] = prober.probe([_resource()])
    assert sym.severity is Severity.MEDIUM and sym.evidence["fatal"] == "no"


def test_log_scan_is_off_unless_deep_is_enabled(monkeypatch):
    # without enable_log_scan(), a Running pod's logs are never read -- the fast path is unchanged.
    prober = KubectlProbe()
    argvs: list[list[str]] = []
    monkeypatch.setattr(prober, "_all_pods", lambda: {"prod": {"items": [_pod("web-abc")]}})
    monkeypatch.setattr(prober, "_node_symptoms", list)  # isolate the log-scan behavior
    monkeypatch.setattr(
        prober, "_run_text", lambda argv, best_effort=False: argvs.append(argv) or "panic: boom"
    )
    assert prober.probe([_resource()]) == []  # status-healthy -> no symptom
    assert not any("logs" in argv for argv in argvs)  # ...and no `kubectl logs` read


def test_deep_does_not_double_report_a_status_unhealthy_workload(monkeypatch):
    # a crash-looping pod already surfaces from STATUS; `--deep` must not add a second Erroring
    # symptom for the same workload (and shouldn't even scan its logs).
    prober = KubectlProbe()
    prober.enable_log_scan()
    crashing = _pod("web-abc", waiting="CrashLoopBackOff", restarts=9)
    monkeypatch.setattr(prober, "_all_pods", lambda: {"prod": {"items": [crashing]}})
    monkeypatch.setattr(prober, "_last_log_line", lambda namespace, pod: "panic: boom")
    [sym] = prober.probe([_resource()])
    assert sym.category == "CrashLoopBackOff"  # status wins; no Erroring duplicate


# -- node health ----------------------------------------------------------------


def _node(name: str, **conditions: tuple[str, str]) -> dict:
    conds = [{"type": t, "status": s, "message": m} for t, (s, m) in conditions.items()]
    return {"metadata": {"name": name}, "status": {"conditions": conds}}


def test_node_issues_flags_pressure_and_notready():
    from steadystate.probe.kubectl import node_issues

    doc = {
        "items": [
            _node("n1", DiskPressure=("True", "disk full"), Ready=("True", "")),
            _node("n2", Ready=("False", "kubelet stopped posting status")),  # NotReady
            _node("n3", DiskPressure=("False", ""), Ready=("True", "")),  # healthy -> nothing
        ]
    }
    assert {(i.node, i.category) for i in node_issues(doc)} == {
        ("n1", "DiskPressure"),
        ("n2", "NotReady"),
    }


def _nodes_probe(monkeypatch, nodes: dict) -> KubectlProbe:
    prober = KubectlProbe()
    monkeypatch.setattr(prober, "_all_pods", dict)  # no workload pods this test
    monkeypatch.setattr(
        prober,
        "_run_text",
        lambda argv, best_effort=False: __import__("json").dumps(nodes) if "nodes" in argv else "",
    )
    return prober


def test_probe_flags_a_node_with_disk_pressure(monkeypatch):
    # the user's case: logs fill the disk -> kubelet sets DiskPressure -> we flag it (the root cause
    # behind the evicted pods). Cluster-scoped, so the identity carries the context, no namespace.
    nodes = {"items": [_node("ip-10-0-1-5", DiskPressure=("True", "kubelet has disk pressure"))]}
    prober = _nodes_probe(monkeypatch, nodes)
    prober.use_context("prod-cluster")
    [sym] = prober.probe([_resource()])
    assert sym.kind == "Node" and sym.category == "DiskPressure" and sym.severity is Severity.HIGH
    assert sym.identity == "prod-cluster/Node/ip-10-0-1-5"
    assert "DiskPressure" in sym.title and sym.evidence["node"] == "ip-10-0-1-5"


def test_node_read_is_best_effort(monkeypatch):
    # a denied/failed `get nodes` (cluster-scoped RBAC) -> no node symptoms, never crashes a probe.
    prober = KubectlProbe()
    monkeypatch.setattr(prober, "_all_pods", dict)
    monkeypatch.setattr(prober, "_run_text", lambda argv, best_effort=False: "")
    assert prober.probe([_resource()]) == []


# -- node disk % (the proactive `--deep` pass) ----------------------------------


def test_node_disk_pct_takes_the_worst_filesystem():
    from steadystate.probe.kubectl import node_disk_pct

    assert node_disk_pct({"node": {"fs": {"capacityBytes": 100, "usedBytes": 85}}}) == 85
    # imageFs (computed from availableBytes) is worse -> it wins.
    worst = {
        "node": {
            "fs": {"capacityBytes": 100, "usedBytes": 50},
            "runtime": {"imageFs": {"capacityBytes": 100, "availableBytes": 8}},
        }
    }
    assert node_disk_pct(worst) == 92
    assert node_disk_pct({}) is None  # nothing readable -> no warning


def _deep_nodes_probe(monkeypatch, nodes: dict, summary: dict) -> KubectlProbe:
    prober = KubectlProbe()
    prober.enable_log_scan()  # --deep gates the per-node disk read
    monkeypatch.setattr(prober, "_all_pods", dict)

    def run(argv, best_effort=False):
        joined = " ".join(argv)
        if "summary" in joined:
            return __import__("json").dumps(summary)
        if "nodes" in joined:
            return __import__("json").dumps(nodes)
        return ""

    monkeypatch.setattr(prober, "_run_text", run)
    return prober


def test_deep_flags_a_node_filling_up_before_disk_pressure(monkeypatch):
    # condition-healthy node (no DiskPressure yet) but 88% full -> a proactive MEDIUM warning.
    nodes = {"items": [_node("n1", Ready=("True", ""))]}
    summary = {"node": {"fs": {"capacityBytes": 100, "usedBytes": 88}}}
    [sym] = _deep_nodes_probe(monkeypatch, nodes, summary).probe([_resource()])
    assert sym.category == "DiskFilling" and sym.severity is Severity.MEDIUM
    assert "88% full" in sym.title and sym.evidence["disk_percent"] == "88"


def test_deep_disk_near_full_is_high(monkeypatch):
    nodes = {"items": [_node("n1", Ready=("True", ""))]}
    summary = {"node": {"fs": {"capacityBytes": 100, "usedBytes": 95}}}
    [sym] = _deep_nodes_probe(monkeypatch, nodes, summary).probe([_resource()])
    assert sym.severity is Severity.HIGH  # near full -> HIGH


def test_disk_pct_is_off_without_deep(monkeypatch):
    # the per-node summary read is gated behind --deep; the fast path never makes it.
    nodes = {"items": [_node("n1", Ready=("True", ""))]}
    prober = KubectlProbe()  # NOT --deep
    monkeypatch.setattr(prober, "_all_pods", dict)
    argvs: list[list[str]] = []
    monkeypatch.setattr(
        prober,
        "_run_text",
        lambda argv, best_effort=False: (
            argvs.append(argv)
            or (__import__("json").dumps(nodes) if "nodes" in " ".join(argv) else "")
        ),
    )
    assert prober.probe([_resource()]) == []
    assert not any("summary" in " ".join(a) for a in argvs)  # no per-node summary call


def test_deep_does_not_double_report_a_node_already_at_disk_pressure(monkeypatch):
    # a node already flagged DiskPressure (HIGH condition) must NOT also get a DiskFilling symptom.
    nodes = {"items": [_node("n1", DiskPressure=("True", "disk pressure"), Ready=("True", ""))]}
    summary = {"node": {"fs": {"capacityBytes": 100, "usedBytes": 99}}}
    syms = _deep_nodes_probe(monkeypatch, nodes, summary).probe([_resource()])
    assert [s.category for s in syms] == ["DiskPressure"]  # one finding, not two


# -- the registry ---------------------------------------------------------------


def test_registry_builds_probes_and_rejects_unknown(tmp_path):
    assert isinstance(build_prober("kubectl", tmp_path), KubectlProbe)
    assert build_prober("none", tmp_path) is None  # the default: no probe step
    assert {"kubectl", "docker", "argocd"} <= set(PROBES)
    with pytest.raises(ValueError, match="unknown prober"):
        build_prober("nope", tmp_path)


def test_auto_maps_each_source_with_a_health_signal():
    # Keyed on the registered --source name: the Kubernetes source is "k8s", not "kubernetes".
    assert auto_prober_for("k8s") == "kubectl"
    assert auto_prober_for("docker-compose") == "docker"
    assert auto_prober_for("argocd") == "argocd"
    assert auto_prober_for("terraform") is None  # no health probe makes sense for terraform
    assert auto_prober_for("ansible") is None
    assert auto_prober_for("kubernetes") is None  # the old wrong key is NOT a registered source


def test_auto_keys_are_registered_sources():
    # The bug this guards: the auto-map keyed on "kubernetes", which no source registers as, so
    # `--source k8s --probe auto` silently ran no probe and the tests (keyed the same wrong way)
    # shipped it green. Every auto-map key must be a real --source name, every value a real probe.
    from steadystate.probe import _AUTO
    from steadystate.sources import DRIFT_SOURCES

    unknown_sources = set(_AUTO) - set(DRIFT_SOURCES)
    assert not unknown_sources, f"auto-map keys are not registered sources: {unknown_sources}"
    assert set(_AUTO.values()) <= set(PROBES), "auto-map points at an unregistered probe"


def test_probe_survives_a_pod_deleted_mid_probe(monkeypatch, caplog):
    # A crash-looping pod is in `get pods`, then deleted before we fetch its logs -> kubectl logs
    # errors (NotFound). The symptom must still surface (without a log tail), and the routine logs
    # failure must NOT be a scary WARNING -- it's expected churn.
    import json
    import logging
    import subprocess as sp

    pod = {
        "metadata": {"name": "web-abc", "namespace": "prod"},
        "status": {
            "phase": "Running",
            "containerStatuses": [
                {"restartCount": 9, "state": {"waiting": {"reason": "CrashLoopBackOff"}}}
            ],
        },
    }

    class _Ok:
        def __init__(self, out):
            self.stdout = out

    def fake_run(argv, **kw):
        if "logs" in argv:  # the pod is gone by the time we ask for its logs
            raise sp.CalledProcessError(
                1, argv, stderr='Error from server (NotFound): pods "web-abc" not found'
            )
        return _Ok(json.dumps({"items": [pod]}))

    monkeypatch.setattr("steadystate.probe.kubectl.subprocess.run", fake_run)
    with caplog.at_level(logging.WARNING, logger="steadystate.probe.kubectl"):
        [symptom] = KubectlProbe().probe([_resource()])
    assert symptom.category == "CrashLoopBackOff"
    assert "last log" not in symptom.detail  # no tail -- the pod was gone, handled cleanly
    assert caplog.records == []  # the logs failure was debug, not a warning
