"""Platform vs. application: which findings are about YOUR workloads, and which are the Rancher/k8s
plumbing. "Is my app healthy" should mean the things you own -- not coredns, traefik, svclb, the
``cattle-*`` operators. A deterministic classifier tags every finding ``application`` | ``platform``
from two signals: a built-in **system-namespace** set, and a **platform-name** heuristic (so a
finding that only carries a workload name -- some policy findings -- is still placed). Both extend
per-wall via ``STEADYSTATE_PLATFORM_NAMESPACES`` (additive: you name only what's extra in *your*
cluster). Surfaces lead with your apps and set the plumbing aside -- never hide it (a coredns
crashloop is real, just not your app's problem). Pure given the environment."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

from .evidence import EvidenceKeys

APPLICATION = "application"
PLATFORM = "platform"

PLATFORM_NAMESPACES_ENV = "STEADYSTATE_PLATFORM_NAMESPACES"

# The k8s + Rancher/k3s control-plane namespaces. A workload here is plumbing, not your app.
_SYSTEM_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "kube-flannel",
        "ingress-nginx",
        "metrics-server",
        "local-path-storage",
        "cert-manager",
        "calico-system",
        "tigera-operator",
        "gatekeeper-system",
        "longhorn-system",
        "gpu-operator",
        # Rancher (cattle-*) + Fleet
        "cattle-system",
        "cattle-fleet-system",
        "cattle-fleet-local-system",
        "fleet-system",
        "cattle-impersonation-system",
        "cattle-global-data",
        "cattle-monitoring-system",
        "cattle-logging-system",
        "cattle-provisioning-capi-system",
        "cattle-ui-plugin-system",
    }
)

# Well-known platform component names (matched as a prefix, so `svclb-traefik-3f72` and
# `cattle-cluster-agent` are caught). The signal of last resort for a finding with no namespace.
_PLATFORM_NAME_PREFIXES = (
    "coredns",
    "svclb",
    "traefik",
    "metrics-server",
    "local-path",
    "cert-manager",
    "calico",
    "tigera",
    "flannel",
    "helm-install-",
    "system-upgrade-",
    "kube-",
    "cattle-",
    "fleet-",
    "rancher-",
)

_WORKLOAD_IN_TITLE = re.compile(r"workload '([^']+)'")


def platform_namespaces() -> frozenset[str]:
    """The system namespaces: the built-in k8s/Rancher set PLUS this wall's additions from
    ``STEADYSTATE_PLATFORM_NAMESPACES`` (a comma list). Additive -- you name only what's unusual in
    your cluster; the built-ins are always covered."""
    extra = os.environ.get(PLATFORM_NAMESPACES_ENV, "")
    return _SYSTEM_NAMESPACES | {n.strip().lower() for n in extra.split(",") if n.strip()}


def is_platform(namespace: str = "", workload: str = "") -> bool:
    """True iff this is platform/plumbing rather than your application: its namespace is a system
    one, or (with no namespace to go on) its workload name matches a known platform component."""
    if namespace and namespace.lower() in platform_namespaces():
        return True
    name = (workload or "").lower()
    return any(name.startswith(prefix) for prefix in _PLATFORM_NAME_PREFIXES)


def finding_layer(details: Mapping[str, str] | None, title: str = "") -> str:
    """Classify a stored finding as ``application`` or ``platform``. Namespace + workload come from
    the structured ``details`` when present (Symptoms carry them); for a finding that only has a
    title (some policy findings), the workload is parsed from a ``workload '<name>'`` title. The
    default is ``application`` -- never set a finding aside as plumbing unless we can place it."""
    namespace = (details or {}).get(EvidenceKeys.NAMESPACE, "")
    workload = (details or {}).get(EvidenceKeys.WORKLOAD, "") or _workload_from_title(title)
    return PLATFORM if is_platform(namespace, workload) else APPLICATION


def _workload_from_title(title: str) -> str:
    match = _WORKLOAD_IN_TITLE.search(title or "")
    return match.group(1) if match else ""
