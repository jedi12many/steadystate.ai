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

Plus the second classic host malfunction: a **filling disk**. A second read-only gather (the
`setup` module's `ansible_mounts`) reports each filesystem's size; a mount at/over 80% used is a
Symptom (MEDIUM), 90% HIGH -- the same thresholds as the kubectl probe's node disk %. A full root
or /var is what *causes* a service to wedge, so this is the proactive signal under the service one.
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

# Filesystem-fill thresholds, mirroring the kubectl node disk % check: warn at 80% used, HIGH at
# 90%. A filling root/var is what tips a host into the failures the service check then sees.
_DISK_WARN_PCT = 80
_DISK_HIGH_PCT = 90


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


def _mounts_by_host(doc: object) -> dict[str, list]:
    """Pull ``{host: [mount, ...]}`` out of an `ansible ... -m setup` run (JSON callback): each
    host's ``ansible_facts.ansible_mounts`` list. Defensive at every level -- a partial/odd document
    yields what it can, never raises. Pure."""
    out: dict[str, list] = {}
    if not isinstance(doc, dict):
        return out
    for play in doc.get("plays") or []:
        tasks = play.get("tasks") if isinstance(play, dict) else None
        for task in tasks or []:
            hosts = task.get("hosts") if isinstance(task, dict) else None
            if not isinstance(hosts, dict):
                continue
            for host, result in hosts.items():
                mounts = (result.get("ansible_facts") or {}).get("ansible_mounts")
                if isinstance(result, dict) and isinstance(mounts, list):
                    out[host] = mounts
    return out


def _disk_pct(mount: dict) -> int | None:
    """Percent used of one ``ansible_mounts`` entry from ``size_total``/``size_available`` (bytes),
    or None when the numbers are missing/zero/non-numeric (a pseudo-fs, an odd fact) -- so a
    bad/partial mount is skipped, never miscounted. Pure."""
    total, avail = mount.get("size_total"), mount.get("size_available")
    if not isinstance(total, (int, float)) or not isinstance(avail, (int, float)):
        return None
    if total <= 0 or isinstance(total, bool) or isinstance(avail, bool):
        return None
    return int((total - avail) / total * 100)


def disk_symptoms(mounts_by_host: dict[str, list]) -> list[Symptom]:
    """A Symptom per filling filesystem across the fleet: a mount at/over 80% used -> MEDIUM, 90% ->
    HIGH. Mirrors the kubectl probe's node disk %. A mount below the warn line, or one whose size
    facts are missing, yields nothing. Pure + testable."""
    symptoms: list[Symptom] = []
    for host in sorted(mounts_by_host):
        for mount in mounts_by_host[host] or []:
            if not isinstance(mount, dict):
                continue
            pct = _disk_pct(mount)
            if pct is None or pct < _DISK_WARN_PCT:
                continue
            symptoms.append(_disk_symptom(host, str(mount.get("mount") or "?"), pct, mount))
    return symptoms


def _disk_symptom(host: str, mount: str, pct: int, info: dict) -> Symptom:
    identity = f"{host}:{mount}"
    evidence = {"host": host, "mount": mount, "percent_used": str(pct)}
    total, avail = info.get("size_total"), info.get("size_available")
    if isinstance(total, (int, float)) and not isinstance(total, bool):
        evidence["size_total"] = str(int(total))
    if isinstance(avail, (int, float)) and not isinstance(avail, bool):
        evidence["size_available"] = str(int(avail))
    return Symptom(
        identity=identity,
        kind="Filesystem",
        category="DiskFilling",
        severity=Severity.HIGH if pct >= _DISK_HIGH_PCT else Severity.MEDIUM,
        title=f"{mount} is {pct}% full on {host}",
        detail=f"{mount} on {host} is {pct}% full -- free space before it wedges services",
        provenance=Provenance(source="ansible", address=identity),
        evidence=evidence,
    )


class AnsibleHealthProbe:
    """Reads the live service health of an Ansible inventory into Symptoms. Read-only: it runs the
    ad-hoc `service_facts` module (gathers, never changes), so it carries no remediation and needs
    no bound. Any failure -- ansible absent, no inventory, an unreachable host -- degrades to "no
    symptoms" (never invent a problem, never break a scan), exactly like the kubectl probe."""

    name = "ansible"
    # Observe-only: two read-only ad-hoc gathers across the inventory (service health + disk fill).
    # Declared so the manifest is honest and an operator can scope access.
    commands = Capabilities(
        observe=(
            "ansible all -m service_facts",
            "ansible all -m setup -a gather_subset=hardware filter=ansible_mounts",
        )
    )

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
        # kubectl probe); we read the fleet directly, like kubectl's node-level symptoms. Two
        # independent read-only gathers: service health, then disk fill. Each degrades on its own --
        # a failed disk gather never sinks the service findings, and vice versa.
        symptoms: list[Symptom] = []
        services = self._run_module("service_facts")
        if services is not None:
            symptoms += host_health_symptoms(_services_by_host(services))
        disks = self._run_module("setup", "gather_subset=hardware filter=ansible_mounts")
        if disks is not None:
            symptoms += disk_symptoms(_mounts_by_host(disks))
        return symptoms

    def _run_module(self, module: str, args: str = "") -> object | None:
        """Run one read-only ad-hoc ansible module across the inventory and parse its JSON-callback
        output. None on any failure (ansible missing / inventory unresolved / unparseable) -> that
        gather degrades to nothing, never an invented problem or a broken scan."""
        if shutil.which("ansible") is None:
            return None
        argv = ["ansible", "all", "-m", module]
        if args:
            argv += ["-a", args]
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
            logger.warning("ansible health probe (%s) failed: %s", module, exc)
            return None
        try:
            return json.loads(result.stdout)
        except ValueError:
            return None
