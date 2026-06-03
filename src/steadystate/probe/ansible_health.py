"""Ansible health probe -- the malfunction axis for hosts that have no platform health API.

Kubernetes/Argo/Helm expose a health verdict steadystate just *reads*. A bare-metal/VM fleet has
no such API -- nothing says "haproxy is wedged on web01". So we read one ourselves, with a
**read-only** collection we fully control: the ad-hoc `service_facts` module (no playbook to audit,
nothing of the operator's that we have to vouch for), turned into Symptoms exactly like the kubectl
probe's pod health. This is observation, not remediation -- there is no command to gate, no
envelope, no bound: a probe never changes anything.

The generic, service-agnostic rule (slice 1): a unit in the **failed** systemd state is a Symptom
(HIGH), and a service that is **enabled** (meant to come up at boot) but is **not running** is a
Symptom (MEDIUM) -- it's supposed to be up and isn't. We don't need to know *what* the host runs;
a later slice can add operator-declared per-service checks (e.g. keepalived's VRRP state) on top.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from ..model import Provenance, Resource
from ..reason.alert import Severity
from ..sources.base import Capabilities
from .base import Symptom

logger = logging.getLogger(__name__)

# systemd states (lowercased) for a service that *should* be up but isn't -- the "enabled but not
# running" signal. "failed" is handled separately (it's a Symptom regardless of enabled-ness).
_DOWN_STATES = frozenset({"stopped", "inactive", "dead"})
_RUNNING_STATES = frozenset({"running", "active"})


def _services_by_host(doc: object) -> dict[str, dict]:
    """Pull ``{host: {service: {state, status}}}`` out of an `ansible ... -m service_facts` run
    rendered by the JSON stdout callback (plays -> tasks -> hosts -> ansible_facts.services).
    Defensive at every level so a partial/odd document yields what it can, never raises. Pure."""
    out: dict[str, dict] = {}
    if not isinstance(doc, dict):
        return out
    for play in doc.get("plays") or []:
        tasks = play.get("tasks") if isinstance(play, dict) else None
        for task in tasks or []:
            hosts = task.get("hosts") if isinstance(task, dict) else None
            if not isinstance(hosts, dict):
                continue
            for host, result in hosts.items():
                services = (result.get("ansible_facts") or {}).get("services")
                if isinstance(result, dict) and isinstance(services, dict):
                    out[host] = services
    return out


def host_health_symptoms(services_by_host: dict[str, dict]) -> list[Symptom]:
    """The health rule, pure: a Symptom per unhealthy service across the fleet. A `failed` unit ->
    HIGH; an `enabled`-but-not-running service -> MEDIUM. A running service, or a stopped one that
    isn't enabled (a `static`/`disabled` unit that's meant to be off), is healthy -> no Symptom."""
    symptoms: list[Symptom] = []
    for host in sorted(services_by_host):
        services = services_by_host[host]
        if not isinstance(services, dict):
            continue
        for name in sorted(services):
            info = services[name]
            if not isinstance(info, dict):
                continue
            state = str(info.get("state") or "").lower()
            status = str(info.get("status") or "").lower()
            if state == "failed":
                symptoms.append(_symptom(host, name, "ServiceFailed", Severity.HIGH, state, status))
            elif status == "enabled" and state not in _RUNNING_STATES:
                symptoms.append(_symptom(host, name, "ServiceDown", Severity.MEDIUM, state, status))
    return symptoms


def _symptom(host: str, service: str, category: str, severity: Severity, state: str, status: str):
    identity = f"{host}:{service}"
    detail = f"{service} on {host} is {state or 'unknown'}" + (
        f" (status: {status})" if status else ""
    )
    return Symptom(
        identity=identity,
        kind="Service",
        category=category,
        severity=severity,
        title=f"{service} is {category} on {host}",
        detail=detail,
        provenance=Provenance(source="ansible", address=identity),
        evidence={
            "host": host,
            "service": service,
            "state": state or "unknown",
            "status": status or "unknown",
        },
    )


class AnsibleHealthProbe:
    """Reads the live service health of an Ansible inventory into Symptoms. Read-only: it runs the
    ad-hoc `service_facts` module (gathers, never changes), so it carries no remediation and needs
    no bound. Any failure -- ansible absent, no inventory, an unreachable host -- degrades to "no
    symptoms" (never invent a problem, never break a scan), exactly like the kubectl probe."""

    name = "ansible"
    # Observe-only: one read-only ad-hoc module run across the inventory. Declared so the manifest
    # is honest and an operator can scope access.
    commands = Capabilities(observe=("ansible all -m service_facts",))

    def __init__(self, inventory: str | None = None, timeout: float = 30.0) -> None:
        self.inventory = inventory or os.environ.get("STEADYSTATE_ANSIBLE_INVENTORY")
        self.timeout = timeout

    def use_inventory(self, inventory: str) -> None:
        """Read host/service health from this inventory file (an ansible-live target carries its
        own, discovered from ``ansible.cfg``/cwd). '' falls back to the env var / ansible.cfg
        default. The seam `build_report(inventory=...)` drives -- parallel to the kubectl probe's
        ``use_context``."""
        self.inventory = inventory or os.environ.get("STEADYSTATE_ANSIBLE_INVENTORY")

    def probe(self, resources: list[Resource]) -> list[Symptom]:
        # Host health isn't tied to the declared k8s resources the seam passes (those are for the
        # kubectl probe); we read the fleet directly, like kubectl's node-level symptoms.
        doc = self._collect()
        return host_health_symptoms(_services_by_host(doc)) if doc is not None else []

    def _collect(self) -> object | None:
        """Run the read-only collection and parse the JSON-callback output. None on any failure
        (ansible missing / inventory unresolved / unparseable) -> the probe degrades to []."""
        if shutil.which("ansible") is None:
            return None
        argv = ["ansible", "all", "-m", "service_facts"]
        if self.inventory:
            argv += ["-i", self.inventory]
        # The JSON stdout callback gives structured output; ad-hoc runs need the load-callbacks
        # toggle to honor it. We don't gate on the return code -- a run with some unreachable hosts
        # exits non-zero but still reports the reachable ones, which we want.
        env = {
            **os.environ,
            "ANSIBLE_STDOUT_CALLBACK": "json",
            "ANSIBLE_LOAD_CALLBACK_PLUGINS": "true",
        }
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=self.timeout, env=env
            )
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning("ansible health probe failed: %s", exc)
            return None
        try:
            return json.loads(result.stdout)
        except ValueError:
            return None
