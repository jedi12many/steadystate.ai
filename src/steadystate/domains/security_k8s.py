"""Kubernetes security pack -- a standing Pod Security baseline over declared manifests.

Like the Docker compliance pack (and unlike the cloud security packs, which *score drift*),
this *evaluates a baseline*: it audits the declared pod security posture and emits a
PolicyFinding for every rule a workload violates, whether or not anything drifted. A Deployment
that has run `privileged: true` since day one is flagged even though it never diverged.

Honest framing: **config-posture evaluation, NOT runtime/behavioral detection.** We read the
declared manifests' security fields (projected by the kubernetes source) and report the rules
they fail; we never watch a pod do anything. The posture lives on the declared side -- a pod
spec's securityContext, hostNetwork/PID/IPC, capabilities, hostPath volumes.

rule_id is a stable slug we own (it keys the finding's fingerprint); the framework ids (CIS
Kubernetes Benchmark section 5.2 "Pod Security Standards", MITRE ATT&CK) ride in `references`.
"""

from __future__ import annotations

from ..model import Drift, Provenance, Resource
from ..reason.alert import Severity
from .base import PolicyFinding, Reference

_CIS_URL = "https://www.cisecurity.org/benchmark/kubernetes"

# Capabilities that grant host-escape-grade power; their presence escalates the finding's framing.
_DANGEROUS_CAPS = frozenset({"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "BPF", "NET_ADMIN"})

_T1611 = Reference(
    framework="MITRE",
    id="T1611",
    name="Escape to Host",
    url="https://attack.mitre.org/techniques/T1611/",
)


def _cis(section: str, name: str) -> Reference:
    # The §5.2 Pod Security controls this pack checks are CIS Level 1.
    return Reference(framework="CIS", id=f"Kubernetes-{section}", name=name, url=_CIS_URL, level=1)


class KubernetesSecurityDomain:
    """A baseline Domain pack: it does not score drift (``score`` returns None), it
    ``evaluate``s the declared pod-security posture and generates findings."""

    name = "security-k8s"

    def score(self, drift: Drift) -> Severity | None:
        # A baseline pack, not a drift-scorer.
        return None

    def evaluate(self, resources: list[Resource]) -> list[PolicyFinding]:
        out: list[PolicyFinding] = []
        for resource in resources:
            if resource.provenance.source != "kubernetes":
                continue  # this pack only audits kubernetes resources
            security = (resource.properties or {}).get("security")
            if security:  # absent for clean workloads (and non-pod kinds)
                out.extend(self._evaluate(resource.identity, security))
        return out

    def _finding(
        self,
        identity: str,
        rule_id: str,
        severity: Severity,
        title: str,
        detail: str,
        references: list[Reference],
    ) -> PolicyFinding:
        return PolicyFinding(
            rule_id=rule_id,
            identity=identity,
            provenance=Provenance(source="kubernetes", address=identity),
            severity=severity,
            title=title,
            detail=detail,
            references=references,
        )

    def _evaluate(self, identity: str, security: dict) -> list[PolicyFinding]:
        out: list[PolicyFinding] = []
        name = identity.rsplit("/", 1)[-1] if "/" in identity else identity

        if security.get("privileged"):
            out.append(
                self._finding(
                    identity,
                    "k8s-privileged",
                    Severity.HIGH,
                    f"workload '{name}' runs a privileged container",
                    "A privileged container disables nearly all isolation (all capabilities, "
                    "device access); it is a direct path to escaping to the node.",
                    [_cis("5.2.1", "Minimize the admission of privileged containers"), _T1611],
                )
            )
        if security.get("host_pid"):
            out.append(
                self._finding(
                    identity,
                    "k8s-host-pid",
                    Severity.MEDIUM,
                    f"workload '{name}' shares the host PID namespace",
                    "hostPID lets the pod see and signal node processes, weakening isolation "
                    "and aiding escape to the host.",
                    [_cis("5.2.2", "Minimize the admission of hostPID containers"), _T1611],
                )
            )
        if security.get("host_ipc"):
            out.append(
                self._finding(
                    identity,
                    "k8s-host-ipc",
                    Severity.MEDIUM,
                    f"workload '{name}' shares the host IPC namespace",
                    "hostIPC shares the node's inter-process communication, exposing other "
                    "tenants' shared memory.",
                    [_cis("5.2.3", "Minimize the admission of hostIPC containers")],
                )
            )
        if security.get("host_network"):
            out.append(
                self._finding(
                    identity,
                    "k8s-host-network",
                    Severity.MEDIUM,
                    f"workload '{name}' shares the host network namespace",
                    "hostNetwork removes network isolation: the pod sees and binds node "
                    "interfaces directly, and can reach link-local cloud metadata.",
                    [_cis("5.2.4", "Minimize the admission of hostNetwork containers")],
                )
            )
        caps = security.get("added_capabilities") or []
        if caps:
            dangerous = sorted(set(caps) & _DANGEROUS_CAPS)
            note = f" including host-escape-grade {', '.join(dangerous)}" if dangerous else ""
            out.append(
                self._finding(
                    identity,
                    "k8s-added-capabilities",
                    Severity.HIGH if dangerous else Severity.MEDIUM,
                    f"workload '{name}' adds Linux capabilities: {', '.join(caps)}",
                    f"Added kernel capabilities{note} widen the container's privileges beyond "
                    "the restricted default; drop ALL and add back only what is required.",
                    [_cis("5.2.8", "Minimize the admission of containers with added capabilities")]
                    + ([_T1611] if dangerous else []),
                )
            )
        if security.get("host_path_volumes"):
            paths = ", ".join(security["host_path_volumes"])
            out.append(
                self._finding(
                    identity,
                    "k8s-host-path",
                    Severity.MEDIUM,
                    f"workload '{name}' mounts host path(s): {paths}",
                    "A hostPath volume mounts the node filesystem into the pod -- a common "
                    "escape and credential-theft vector (e.g. mounting / or the kubelet dir).",
                    [_cis("5.2.12", "Minimize the admission of HostPath volumes"), _T1611],
                )
            )
        if security.get("allow_privilege_escalation"):
            out.append(
                self._finding(
                    identity,
                    "k8s-allow-privilege-escalation",
                    Severity.LOW,
                    f"workload '{name}' allows privilege escalation",
                    "allowPrivilegeEscalation: true lets a process gain more privileges than "
                    "its parent (e.g. via setuid); set it to false.",
                    [_cis("5.2.5", "Minimize allowPrivilegeEscalation")],
                )
            )
        if security.get("runs_as_root"):
            out.append(
                self._finding(
                    identity,
                    "k8s-runs-as-root",
                    Severity.LOW,
                    f"workload '{name}' runs as root",
                    "The pod runs as UID 0 (runAsUser: 0 or runAsNonRoot: false); a breakout "
                    "then starts with root on the node. Set runAsNonRoot: true.",
                    [_cis("5.2.6", "Minimize the admission of root containers")],
                )
            )
        return out
