"""docker-compose source -- v0.

A Compose file *declares* the services a host should run; `docker compose ps`
reports what is *actually* running. Unlike Terraform, Compose has no built-in plan
diff, so this source enumerates both sides and reconciles them:

- declared: `docker compose config --format json` (Compose resolves
  extends/overrides/anchors/interpolation, so each service is the fully-merged truth).
- observed: `docker compose ps --format json` (the running containers).

Drift is reported on **presence + image tag**: a declared service that isn't running
(ADDED), a running container that isn't declared (REMOVED), or a service running a
different image than declared (MODIFIED). Services declared without an `image` (built
locally) are compared on presence only, so a local build never shows as false drift.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..model import Drift, Provenance, Resource
from ..reconcile import reconcile
from .base import Capabilities


def resources_from_compose_config(config: dict) -> list[Resource]:
    """Turn a `docker compose config --format json` document into declared Resources.
    Pure + testable."""
    out: list[Resource] = []
    for name, service in (config.get("services") or {}).items():
        out.append(
            Resource(
                kind="docker_compose_service",
                identity=name,
                provenance=Provenance(source="docker-compose", address=name),
                properties=service or {},
            )
        )
    return out


def observed_resources_from_ps(ps_entries: list[dict]) -> list[Resource]:
    """Turn `docker compose ps --format json` entries into observed Resources. Pure.
    Identity is the compose service name, so it aligns with the declared side."""
    out: list[Resource] = []
    for entry in ps_entries:
        name = entry.get("Service") or entry.get("Name")
        if not name:
            continue
        out.append(
            Resource(
                kind="docker_compose_service",
                identity=name,
                provenance=Provenance(source="docker-compose", address=name),
                properties={"image": entry.get("Image"), "state": entry.get("State")},
            )
        )
    return out


def _image_props(resource: Resource, *, compare_image: bool) -> dict:
    """Comparable projection: the image tag when we should compare it, else {} so the
    service is reconciled on presence alone (no false drift for built-locally services)."""
    image = resource.properties.get("image")
    return {"image": image} if (compare_image and image) else {}


def reconcile_compose(declared: list[Resource], observed: list[Resource]) -> list[Drift]:
    """Reconcile declared vs running compose services on presence + image tag. Pure."""
    declared_by = {r.identity: r for r in declared}
    declared_cmp = [
        Resource(
            kind=r.kind,
            identity=r.identity,
            provenance=r.provenance,
            properties=_image_props(r, compare_image=True),
        )
        for r in declared
    ]
    observed_cmp: list[Resource] = []
    for r in observed:
        d = declared_by.get(r.identity)
        # compare the image only when the declared side specified one (else presence-only)
        compare_image = d is None or bool(d.properties.get("image"))
        observed_cmp.append(
            Resource(
                kind=r.kind,
                identity=r.identity,
                provenance=r.provenance,
                properties=_image_props(r, compare_image=compare_image),
            )
        )
    return reconcile(declared_cmp, observed_cmp)


class DockerComposeSource:
    """A StateSource + ObservedSource + DriftSource for docker-compose. Construct with
    parsed `config`/`ps` (testing / CI) or a working dir to run Compose live."""

    name = "docker-compose"
    commands = Capabilities(
        observe=("docker compose config --format json", "docker compose ps --format json"),
        destructive=("docker compose up -d", "docker compose down", "docker compose restart"),
    )

    def __init__(
        self,
        working_dir: str | Path | None = None,
        config: dict | None = None,
        ps: list[dict] | None = None,
    ) -> None:
        self.working_dir = Path(working_dir) if working_dir else None
        self._config = config
        self._ps = ps

    def collect_declared(self) -> list[Resource]:
        config = self._config if self._config is not None else self._run_compose()
        return resources_from_compose_config(config)

    def collect_observed(self) -> list[Resource]:
        ps = self._ps if self._ps is not None else self._run_ps()
        return observed_resources_from_ps(ps)

    def collect_drift(self) -> list[Drift]:
        return reconcile_compose(self.collect_declared(), self.collect_observed())

    # -- live docker --------------------------------------------------------

    def _run_compose(self) -> dict:
        if self.working_dir is None:
            raise ValueError("DockerComposeSource needs working_dir or config")
        res = subprocess.run(
            ["docker", "compose", "config", "--format", "json"],
            cwd=self.working_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(res.stdout)

    def _run_ps(self) -> list[dict]:
        if self.working_dir is None:
            raise ValueError("DockerComposeSource needs working_dir or ps")
        res = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=self.working_dir,
            check=True,
            capture_output=True,
            text=True,
        )
        return _parse_ps_output(res.stdout)


def _parse_ps_output(stdout: str) -> list[dict]:
    """`docker compose ps --format json` emits either a JSON array or newline-delimited
    JSON objects, depending on the Compose version. Handle both."""
    text = stdout.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
