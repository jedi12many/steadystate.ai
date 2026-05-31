"""The plugin registries are the seam that keeps "add a pack, never edit core" true:
a new source/domain is one registry line, and these tests fail if a registered
plugin isn't actually reachable (the build-but-unwired trap that stranded the
docker-compose source as a comment)."""

import json

import pytest
import typer

from steadystate.act import EXECUTORS, build_executor
from steadystate.act.base import Executor
from steadystate.cli import _drift_source
from steadystate.domains import DEFAULT_DOMAINS, default_domains
from steadystate.domains.base import Domain
from steadystate.sources import DRIFT_SOURCES, build_drift_source
from steadystate.sources.base import DriftSource


def _sample(tmp_path, name, payload):
    f = tmp_path / name
    f.write_text(json.dumps(payload))
    return f


# Representative empty inputs per source -- enough to construct and run collect_drift.
def _inputs(tmp_path):
    return {
        "terraform": _sample(tmp_path, "plan.json", {"resource_changes": []}),
        "argocd": _sample(tmp_path, "app.json", {"status": {"resources": []}}),
        "ansible": _sample(tmp_path, "ansible.json", {"plays": []}),
        "docker-compose": _sample(tmp_path, "compose.json", {"config": {"services": {}}, "ps": []}),
        "k8s": _sample(tmp_path, "k8s.json", {"declared": [], "observed": []}),
        "rancher": _sample(tmp_path, "gitrepo.json", {"status": {"resources": []}}),
        "helm": _sample(tmp_path, "helm.json", []),
    }


def test_known_drift_sources_registered():
    assert {"terraform", "argocd"} <= set(DRIFT_SOURCES)


def test_every_registered_source_builds_and_conforms(tmp_path):
    # A broken/renamed factory, or a source registered without a test input, fails here.
    inputs = _inputs(tmp_path)
    for name in DRIFT_SOURCES:
        assert name in inputs, f"registered source {name!r} has no representative test input"
        src = build_drift_source(name, inputs[name])
        assert isinstance(src, DriftSource)
        assert src.collect_drift() == []


def test_every_registered_source_is_cli_dispatchable(tmp_path):
    # The wiring guard: every registered source must round-trip through the CLI helper,
    # so a built-but-unregistered source can never ship silently unreachable again.
    inputs = _inputs(tmp_path)
    for name in DRIFT_SOURCES:
        assert isinstance(_drift_source(name, inputs[name]), DriftSource)


def test_build_drift_source_unknown_raises_valueerror(tmp_path):
    with pytest.raises(ValueError, match="unknown source"):
        build_drift_source("nope", tmp_path / "x")


def test_cli_translates_unknown_source_to_badparameter(tmp_path):
    # Unknown --source is a clean CLI error, not a stack trace.
    with pytest.raises(typer.BadParameter):
        _drift_source("nope", tmp_path / "x")


def test_default_domains_conform_and_are_fresh():
    assert DEFAULT_DOMAINS, "pipeline would run with no domain packs"
    for dom in DEFAULT_DOMAINS:
        assert isinstance(dom, Domain)
    fresh = default_domains()
    assert fresh is not DEFAULT_DOMAINS  # a copy, so callers can't mutate the registry
    assert [type(d) for d in fresh] == [type(d) for d in DEFAULT_DOMAINS]


def test_every_executor_maps_to_a_real_source():
    # You can't act on a backend you can't observe -- executors are a subset of sources.
    assert set(EXECUTORS) <= set(DRIFT_SOURCES)


def test_build_executor_acts_for_terraform_and_is_none_for_observe_only(tmp_path):
    assert isinstance(build_executor("terraform", tmp_path), Executor)
    for name in set(DRIFT_SOURCES) - set(EXECUTORS):  # ansible/argocd/rancher/k8s/compose
        assert build_executor(name, tmp_path) is None


def test_fix_rejects_an_observe_only_source(tmp_path):
    # `fix --source rancher` is a clean CLI error, not a crash -- rancher has no executor.
    from steadystate.cli import app

    runner = pytest.importorskip("typer.testing").CliRunner()
    sample = tmp_path / "gitrepo.json"
    sample.write_text(json.dumps({"status": {"resources": []}}))
    result = runner.invoke(app, ["fix", str(sample), "--source", "rancher"])
    assert result.exit_code != 0
