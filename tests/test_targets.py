"""The named-target registry: load + default + reject, and the env entry point."""

from __future__ import annotations

import json

import pytest

from steadystate.targets import TARGETS_ENV, Target, load_targets, load_targets_from_env


def _write(tmp_path, data: dict):
    path = tmp_path / "targets.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_parses_and_defaults_label_to_name_and_probe_to_auto(tmp_path):
    path = _write(tmp_path, {"prod-k8s": {"source": "k8s", "path": "/m"}})
    assert load_targets(path)["prod-k8s"] == Target(
        name="prod-k8s", source="k8s", path="/m", label="prod-k8s", probe="auto"
    )


def test_load_keeps_explicit_label_and_probe(tmp_path):
    path = _write(
        tmp_path, {"x": {"source": "argocd", "path": "/a", "label": "prod", "probe": "argocd"}}
    )
    target = load_targets(path)["x"]
    assert target.label == "prod" and target.probe == "argocd"


def test_load_rejects_a_target_missing_required_fields(tmp_path):
    path = _write(tmp_path, {"bad": {"source": "k8s"}})  # no path
    with pytest.raises(ValueError, match="needs at least"):
        load_targets(path)


def test_load_rejects_a_non_object_document(tmp_path):
    path = tmp_path / "t.json"
    path.write_text('["nope"]', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_targets(path)


def test_from_env_is_empty_when_unset(monkeypatch):
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    assert load_targets_from_env() == {}


def test_from_env_loads_the_file(monkeypatch, tmp_path):
    path = _write(tmp_path, {"a": {"source": "k8s", "path": "/m"}})
    monkeypatch.setenv(TARGETS_ENV, str(path))
    assert "a" in load_targets_from_env()
