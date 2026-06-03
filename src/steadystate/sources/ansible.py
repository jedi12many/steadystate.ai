"""Ansible source -- v0.

An Ansible playbook *declares* the desired state of a fleet; ``ansible-playbook --check``
reports what it *would* change against the hosts as they are now. Like Terraform's plan,
that check IS the reconcile, so this source rides it instead of re-deriving drift: parse the
JSON-callback output of a check run and turn every task that reports ``changed`` into a Drift.

Capture the structured output with Ansible's json stdout callback (no new dependency on our
side -- the operator runs ansible)::

    ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check --diff site.yml > drift.json

Each (host, task) that would change is one drift on that host. With ``--diff`` the before/after
ride along, so ``declared`` (after = what the playbook wants) and ``observed`` (before = the
host as it is) are populated; without it, the task name alone identifies the drift.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..model import ChangeType, Drift, Provenance
from .base import Capabilities, loads_json, run_tool


def _diff(diff: object) -> tuple[dict | None, dict | None]:
    """Pull (declared, observed) from an Ansible task diff. Ansible's ``before`` is the host
    as it is now (observed) and ``after`` is what the playbook would make it (declared)."""
    if not isinstance(diff, list):
        return None, None
    for entry in diff:
        if isinstance(entry, dict) and ("before" in entry or "after" in entry):
            declared = {"content": entry["after"]} if "after" in entry else None
            observed = {"content": entry["before"]} if "before" in entry else None
            return declared, observed
    return None, None


def drifts_from_ansible_check(result: dict) -> list[Drift]:
    """Parse ``ansible-playbook --check`` json-callback output into Drift records. Pure +
    testable. A task with ``changed: true`` on a host means the playbook would change that
    host -- i.e. it has drifted from the declared playbook."""
    out: list[Drift] = []
    for play in result.get("plays") or []:
        for task in play.get("tasks") or []:
            task_name = (task.get("task") or {}).get("name") or "task"
            for host, host_result in (task.get("hosts") or {}).items():
                if not isinstance(host_result, dict) or not host_result.get("changed"):
                    continue
                module = (
                    host_result.get("action")
                    or (host_result.get("invocation") or {}).get("module_name")
                    or "ansible_task"
                )
                identity = f"{host}:{task_name}"
                declared, observed = _diff(host_result.get("diff"))
                out.append(
                    Drift(
                        identity=identity,
                        kind=str(module),
                        change_type=ChangeType.MODIFIED,
                        provenance=Provenance(source="ansible", address=identity),
                        declared=declared,
                        observed=observed,
                    )
                )
    return out


class AnsibleSource:
    """A DriftSource. Construct with a captured json-callback result (testing / CI) or a
    playbook to run ``ansible-playbook --check`` live."""

    name = "ansible"
    commands = Capabilities(
        observe=("ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check --diff",),
        destructive=("ansible-playbook",),
    )

    def __init__(
        self,
        result: dict | None = None,
        playbook: str | None = None,
        working_dir: str | Path | None = None,
        inventory: str | None = None,
        timeout: float = 300.0,  # an ansible --check run across a fleet can take minutes
    ) -> None:
        self._result = result
        self.playbook = playbook
        self.working_dir = Path(working_dir) if working_dir else None
        self.inventory = inventory
        self.timeout = timeout

    def collect_drift(self) -> list[Drift]:
        result = self._result if self._result is not None else self._run_check()
        return drifts_from_ansible_check(result)

    def _run_check(self) -> dict:
        if not self.playbook:
            raise ValueError("AnsibleSource needs result or playbook")
        # The json stdout callback emits a single JSON document we parse; --check makes it a
        # dry run (no host is changed), so this stays an observe command.
        env = {**os.environ, "ANSIBLE_STDOUT_CALLBACK": "json"}
        cmd = ["ansible-playbook", "--check", "--diff", self.playbook]
        if self.inventory:
            cmd += ["-i", self.inventory]
        # check=False: --check exits non-zero when it *finds* changes (the normal drift case), and
        # we parse stdout regardless; run_tool still raises on a missing binary / timeout.
        stdout = run_tool(
            cmd,
            cwd=self.working_dir,
            env=env,
            check=False,
            timeout=self.timeout,
            tool="ansible-playbook",
        )
        parsed = loads_json(stdout, tool="ansible-playbook")
        return parsed if isinstance(parsed, dict) else {}


class AnsibleLiveSource:
    """A pathless live host-health source -- the ansible analog of ``k8s-live``.

    It reports NO config drift: the ansible *drift* source (``AnsibleSource``) reads a captured
    ``ansible-playbook --check`` instead. This exists purely so a **target** can run the read-only
    ansible health probe against an inventory -- live host/service health, no captured playbook run
    needed. Health is the probe's job (``ansible all -m service_facts`` via the auto-selected
    ``ansible`` probe); this source just makes a probe-only ansible target possible, mirroring how
    ``k8s-live`` hosts the kubectl probe. Pathless: it takes no input file, and the inventory is
    threaded to the probe via ``build_report(inventory=...)``."""

    name = "ansible-live"
    # The probe declares the real read command; the source itself runs nothing.
    commands = Capabilities(observe=("ansible all -m service_facts",))

    def collect_drift(self) -> list[Drift]:
        return []  # no declared playbook here -- drift is the captured-check source's job
