"""Docker compliance pack -- a standing CIS-Docker baseline over declared services.

Unlike the security pack (which *scores drift*), this pack *evaluates a baseline*: it
audits the declared compose configuration and emits a PolicyFinding for every rule a
service violates, whether or not anything drifted. That is Fork B -- true CIS: a service
that has run ``privileged: true`` since the first scan is flagged even though it never
diverged from its declared state.

Honest framing: this is **config-posture evaluation, NOT runtime/behavioral detection**.
We read the declared `docker compose config` and report the rules it fails; we do not watch
a container do anything. We audit the *declared* side on purpose -- the policy-relevant
fields (privileged, cap_add, user, security_opt, ...) live in the compose config, while
observed `docker compose ps` only carries image/state.

rule_id is a stable slug we own (it keys the finding's fingerprint); the framework
benchmark ids (CIS, MITRE) ride in `references`, so a rule can cite more than one and we
never overload our own id with a benchmark number we'd have to keep precise.

v1 covers the rules answerable from compose config alone. Dockerfile-level rules
(USER/HEALTHCHECK/pinned FROM/secrets) need a Dockerfile reader in the docker source and
are a deliberate follow-up.
"""

from __future__ import annotations

from ..model import Drift, Provenance, Resource
from ..reason.alert import Severity
from .base import PolicyFinding, Reference

_SERVICE_KIND = "docker_compose_service"

# Reusable framework references (the same Reference rail the security pack uses).
_CIS = "CIS"
_MITRE = "MITRE"


def _cis(section: str, name: str) -> Reference:
    # All the Docker controls this pack checks are CIS Level 1 (broadly-applicable hardening).
    return Reference(
        framework=_CIS,
        id=f"Docker-{section}",
        name=name,
        url="https://www.cisecurity.org/benchmark/docker",
        level=1,
    )


_T1611 = Reference(
    framework=_MITRE,
    id="T1611",
    name="Escape to Host",
    url="https://attack.mitre.org/techniques/T1611/",
)


def _as_list(value: object) -> list:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _truthy(value: object) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes")
    return bool(value)


def _finding(
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
        provenance=Provenance(source="docker-compose", address=identity),
        severity=severity,
        title=title,
        detail=detail,
        references=references,
    )


class DockerComplianceDomain:
    """A baseline Domain pack: it does not score drift (``score`` returns None), it
    ``evaluate``s the declared inventory and generates CIS-Docker findings."""

    name = "docker-compliance"

    def score(self, drift: Drift) -> Severity | None:
        # A baseline pack, not a drift-scorer: it never raises severity on a divergence.
        return None

    def evaluate(self, resources: list[Resource]) -> list[PolicyFinding]:
        out: list[PolicyFinding] = []
        for resource in resources:
            if resource.kind != _SERVICE_KIND:
                continue
            out.extend(self._evaluate_service(resource.identity, resource.properties or {}))
        return out

    def _evaluate_service(self, name: str, props: dict) -> list[PolicyFinding]:
        out: list[PolicyFinding] = []

        # CIS 5.4 -- privileged containers disable nearly all isolation; a clear host-escape
        # primitive. The most dangerous single flag, so HIGH.
        if _truthy(props.get("privileged")):
            out.append(
                _finding(
                    name,
                    "docker-privileged",
                    Severity.HIGH,
                    f"service '{name}' runs privileged",
                    "A privileged container disables Docker's isolation (all capabilities, "
                    "device access); it is a direct path to escaping to the host.",
                    [_cis("5.4", "Do not use privileged containers"), _T1611],
                )
            )

        # CIS 5.9 -- sharing the host network namespace removes network isolation.
        if str(props.get("network_mode", "")).lower() == "host":
            out.append(
                _finding(
                    name,
                    "docker-host-network",
                    Severity.MEDIUM,
                    f"service '{name}' shares the host network namespace",
                    "network_mode: host removes network isolation: the container sees and "
                    "binds host interfaces directly.",
                    [_cis("5.9", "Do not share the host's network namespace")],
                )
            )

        # CIS 5.15 -- sharing the host PID namespace exposes/affects host processes.
        if str(props.get("pid", "")).lower() == "host":
            out.append(
                _finding(
                    name,
                    "docker-host-pid",
                    Severity.MEDIUM,
                    f"service '{name}' shares the host PID namespace",
                    "pid: host lets the container see and signal host processes, weakening "
                    "isolation and aiding host escape.",
                    [_cis("5.15", "Do not share the host's process namespace"), _T1611],
                )
            )

        # CIS 5.3 -- added Linux capabilities widen the container's kernel privileges.
        added = [str(c) for c in _as_list(props.get("cap_add"))]
        if added:
            out.append(
                _finding(
                    name,
                    "docker-added-capabilities",
                    Severity.MEDIUM,
                    f"service '{name}' adds Linux capabilities: {', '.join(added)}",
                    "cap_add grants kernel capabilities beyond Docker's restricted default; "
                    "prefer dropping all and adding back only what's required.",
                    [_cis("5.3", "Restrict Linux kernel capabilities within containers")],
                )
            )

        # CIS 5.25 -- without no-new-privileges a process can gain privileges via setuid.
        # Ubiquitously unset, so LOW (default-quiet: a Signal under default tuning).
        security_opt = [str(o).lower() for o in _as_list(props.get("security_opt"))]
        if not any("no-new-privileges" in opt for opt in security_opt):
            out.append(
                _finding(
                    name,
                    "docker-no-new-privileges-missing",
                    Severity.LOW,
                    f"service '{name}' does not set no-new-privileges",
                    "Without security_opt: no-new-privileges, a process in the container can "
                    "still acquire new privileges (e.g. via setuid binaries).",
                    [_cis("5.25", "Restrict acquiring additional privileges")],
                )
            )

        # CIS 4.1 -- running as root. Also ubiquitous, so LOW.
        user = str(props.get("user", "")).strip().lower()
        if user in ("", "root", "0"):
            out.append(
                _finding(
                    name,
                    "docker-root-user",
                    Severity.LOW,
                    f"service '{name}' runs as root",
                    "No non-root user is set, so the container runs as root; a breakout then "
                    "starts with root on the host.",
                    [_cis("4.1", "Create a user for the container")],
                )
            )

        # Image pinning -- :latest (or no tag) makes the running image non-reproducible and
        # silently mutable. Skip services with no image (built locally). LOW (noisy).
        image = props.get("image")
        if isinstance(image, str) and image and "@sha256:" not in image:
            tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
            if tag in ("", "latest"):
                out.append(
                    _finding(
                        name,
                        "docker-image-unpinned",
                        Severity.LOW,
                        f"service '{name}' uses an unpinned image: {image}",
                        "An implicit or :latest tag is mutable -- the image that runs can "
                        "change without any config change. Pin by tag or digest.",
                        [],
                    )
                )

        return out
