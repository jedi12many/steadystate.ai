"""Docker (compose) health probe -- originate Symptoms for declared services.

The originating counterpart to the kubectl probe, for docker-compose: for each declared service
it finds the live container via `docker ps` on the `com.docker.compose.service` label (the same
engine access the source has) and -- when it's restarting, exited non-zero, dead, or failing a
healthcheck -- emits a `Symptom`, even with no drift. Classification (`unhealthy_containers`) is
pure + testable. Any docker failure degrades to "no symptoms".
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass

from ..model import Provenance, Resource
from ..reason.alert import Severity
from ..sources.base import Capabilities
from .base import Symptom

logger = logging.getLogger(__name__)

COMPOSE_SERVICE_LABEL = "com.docker.compose.service"
_EXITED_CODE = re.compile(r"Exited \((\d+)\)")  # the exit code inside `docker ps` Status


@dataclass(frozen=True)
class ContainerHealth:
    """One unhealthy container of a compose service: its name and why."""

    name: str
    reason: str  # "restarting", "exited (N)", "unhealthy", or "dead"


def _labels_to_dict(labels: object) -> dict[str, str]:
    """`docker ps --format json` renders labels as a comma-joined ``k=v,k=v`` string; some
    versions give a dict. Normalize both to a dict."""
    if isinstance(labels, dict):
        return {str(k): str(v) for k, v in labels.items()}
    out: dict[str, str] = {}
    for pair in str(labels or "").split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _container_reason(state: str, status: str) -> str:
    """Why a container is unhealthy, or "" if it's fine. ``state``/``status`` are `docker ps`'s
    State + Status. An exit code of 0 is a clean stop (not flagged); non-zero, restarting, dead,
    or a failing healthcheck (Status carries "(unhealthy)") are."""
    state = state.lower()
    if state == "restarting":
        return "restarting"
    if state == "dead":
        return "dead"
    if state == "exited":
        match = _EXITED_CODE.search(status)
        return f"exited ({match.group(1)})" if match and match.group(1) != "0" else ""
    if state == "running" and "unhealthy" in status.lower():
        return "unhealthy"
    return ""


def unhealthy_containers(entries: list[dict], service: str) -> list[ContainerHealth]:
    """The unhealthy containers of compose ``service`` in `docker ps --format json` entries.

    A container belongs to the service when its ``com.docker.compose.service`` label matches.
    Unhealthy = restarting, dead, exited non-zero, or a failing healthcheck. Pure + testable."""
    out: list[ContainerHealth] = []
    for entry in entries:
        if _labels_to_dict(entry.get("Labels")).get(COMPOSE_SERVICE_LABEL) != service:
            continue
        reason = _container_reason(str(entry.get("State") or ""), str(entry.get("Status") or ""))
        if reason:
            out.append(
                ContainerHealth(name=entry.get("Names") or entry.get("Name") or "?", reason=reason)
            )
    return out


def category_and_severity(sick: list[ContainerHealth]) -> tuple[str, Severity]:
    """The dominant reason + its severity. A container that's down (restarting / exited non-zero /
    dead) is HIGH; one that's only failing its healthcheck (still running) is MEDIUM. Pure."""
    down = [c for c in sick if c.reason != "unhealthy"]
    if down:
        return down[0].reason, Severity.HIGH
    return sick[0].reason, Severity.MEDIUM


class DockerProbe:
    """Produces a Symptom per declared docker-compose service whose container is failing now."""

    name = "docker"
    # Observe-only: a probe reads health, it never changes a container.
    commands = Capabilities(observe=("docker ps --format json", "docker logs --tail"))

    def __init__(self, log_tail: int = 20, timeout: float = 10.0) -> None:
        self.log_tail = log_tail
        self.timeout = timeout

    def probe(self, resources: list[Resource]) -> list[Symptom]:
        symptoms: list[Symptom] = []
        for resource in resources:
            if resource.provenance.source != "docker-compose":
                continue
            service = resource.identity  # the compose identity is the service name
            sick = unhealthy_containers(self._ps(service), service)
            if sick:
                symptoms.append(self._symptom(resource, sick))
        return symptoms

    def _symptom(self, resource: Resource, sick: list[ContainerHealth]) -> Symptom:
        category, severity = category_and_severity(sick)
        tail = self._last_log_line(sick[0].name)
        detail = f"{len(sick)} container(s) {category}" + (f"; last log: {tail}" if tail else "")
        return Symptom(
            identity=resource.identity,
            kind=resource.kind,
            category=category,
            severity=severity,
            title=f"{resource.identity} is {category}",
            detail=detail,
            provenance=Provenance(source="docker-compose", address=resource.identity),
        )

    def _ps(self, service: str) -> list[dict]:
        text = self._run_text(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label={COMPOSE_SERVICE_LABEL}={service}",
                "--format",
                "json",
            ]  # fmt: skip
        )
        entries: list[dict] = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            if isinstance(parsed, list):
                entries.extend(item for item in parsed if isinstance(item, dict))
            elif isinstance(parsed, dict):
                entries.append(parsed)
        return entries

    def _last_log_line(self, container: str) -> str:
        text = self._run_text(["docker", "logs", "--tail", str(self.log_tail), container])
        lines = [line for line in (text or "").splitlines() if line.strip()]
        return lines[-1][:200] if lines else ""

    def _run_text(self, argv: list[str]) -> str:
        try:
            result = subprocess.run(
                argv, check=True, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("docker probe (%s) failed: %s", " ".join(argv[:2]), exc)
            return ""
