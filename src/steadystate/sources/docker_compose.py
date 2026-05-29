"""docker-compose source -- v0.

A Compose file *declares* the services a host should be running. Unlike Terraform
it does not reconcile against reality, so this is a plain StateSource: enumerate
the declared services as Resources and let the reconciler diff them against what
is actually running.

We read `docker compose config --format json` rather than the raw YAML: Compose
resolves extends/overrides/anchors/interpolation for us, so one service in the
output is the fully-merged truth instead of a fragment we'd have to re-merge.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ..model import Provenance, Resource


def resources_from_compose_config(config: dict) -> list[Resource]:
    """Turn a `docker compose config --format json` document into Resources. Pure + testable."""
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


class DockerComposeSource:
    """A StateSource. Construct with a parsed config dict (testing / CI) or a
    working dir to run `docker compose config` live."""

    name = "docker-compose"

    def __init__(
        self,
        working_dir: str | Path | None = None,
        config: dict | None = None,
    ) -> None:
        self.working_dir = Path(working_dir) if working_dir else None
        self._config = config

    def collect_declared(self) -> list[Resource]:
        config = self._config if self._config is not None else self._run_compose()
        return resources_from_compose_config(config)

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
