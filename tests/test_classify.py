"""Platform vs. application classification: 'is my app healthy' means YOUR workloads, not the
Rancher/k8s plumbing. Pins the two signals (system namespace + platform-name heuristic), the
title-only fallback for findings with no namespace (the CIS capability findings), the additive
per-wall override, and the safe default (unknown -> application, so we never hide a finding)."""

from __future__ import annotations

from steadystate.classify import (
    APPLICATION,
    PLATFORM,
    finding_layer,
    is_platform,
    platform_namespaces,
)


def test_system_namespace_is_platform_application_namespace_is_not():
    assert is_platform(namespace="kube-system")
    assert is_platform(namespace="cattle-fleet-system")  # Rancher
    assert not is_platform(namespace="demo")
    assert not is_platform(namespace="mail")


def test_platform_name_heuristic_catches_components_without_a_namespace():
    # the signal of last resort -- a finding that only carries a workload name (a CIS finding).
    assert is_platform(workload="coredns")
    assert is_platform(workload="svclb-traefik-3f7211ed")  # prefix match
    assert is_platform(workload="cattle-cluster-agent")
    assert not is_platform(workload="postfix")
    assert not is_platform(workload="web")


def test_finding_layer_uses_details_then_falls_back_to_the_title():
    # a Symptom carries namespace/workload in details -> classified by namespace
    assert (
        finding_layer({"namespace": "demo", "workload": "web"}, "web is CrashLoopBackOff")
        == APPLICATION
    )
    assert finding_layer({"namespace": "kube-system"}, "x") == PLATFORM
    # a CIS finding has empty details -> workload parsed from a `workload '<name>'` title
    assert (
        finding_layer({}, "workload 'coredns' adds Linux capabilities: NET_BIND_SERVICE")
        == PLATFORM
    )
    assert finding_layer({}, "workload 'svclb-traefik-3f72' adds NET_ADMIN") == PLATFORM


def test_unknown_defaults_to_application_so_a_real_finding_is_never_hidden():
    assert finding_layer({}, "some drift with no namespace or known name") == APPLICATION
    assert finding_layer(None, "") == APPLICATION


def test_the_per_wall_override_is_additive(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_PLATFORM_NAMESPACES", "akeyless-system, my-operator")
    ns = platform_namespaces()
    assert "akeyless-system" in ns and "my-operator" in ns  # your additions
    assert "kube-system" in ns  # ...and the built-ins are still covered
    assert is_platform(namespace="akeyless-system")
    assert not is_platform(namespace="demo")  # an app namespace is still an app
