"""Targets resolution -- committed-first, like checks/solutions/mutes. Found in real deployment
testing: a committed silos/<wall>/steadystate/targets.json wasn't seen by a client-spawned MCP
server, because targets still resolved ONLY to the gitignored .steadystate/ default and the env
var doesn't reach a subprocess the MCP client launches. These pin the order (env > committed >
legacy > committed-for-a-fresh-write), the loud env-typo behavior, and that every entry point
shares the same resolution."""

from __future__ import annotations

import json

import pytest

from steadystate.targets import (
    COMMITTED_TARGETS_FILE,
    DEFAULT_TARGETS_FILE,
    load_targets_from_env,
    resolve_targets_path,
)


def _write(tmp_path, rel: str, entries: dict) -> None:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entries))


@pytest.fixture
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STEADYSTATE_TARGETS", raising=False)
    return tmp_path


def test_committed_targets_are_found_with_no_env(_cwd):
    # The deployment snag: a committed registry must be seen by an MCP server spawned with no env.
    _write(_cwd, COMMITTED_TARGETS_FILE, {"gw": {"source": "k8s-live", "context": "prod"}})
    assert resolve_targets_path() == COMMITTED_TARGETS_FILE
    assert list(load_targets_from_env()) == ["gw"]


def test_committed_wins_over_legacy_and_legacy_still_works_alone(_cwd):
    _write(_cwd, DEFAULT_TARGETS_FILE, {"old": {"source": "k8s-live"}})
    assert resolve_targets_path() == DEFAULT_TARGETS_FILE  # legacy-only repo: unchanged
    assert list(load_targets_from_env()) == ["old"]
    _write(_cwd, COMMITTED_TARGETS_FILE, {"new": {"source": "k8s-live"}})
    assert resolve_targets_path() == COMMITTED_TARGETS_FILE  # committed is the preferred home
    assert list(load_targets_from_env()) == ["new"]


def test_env_wins_and_a_typo_fails_loudly(_cwd, monkeypatch):
    _write(_cwd, COMMITTED_TARGETS_FILE, {"committed": {"source": "k8s-live"}})
    _write(_cwd, "elsewhere.json", {"env": {"source": "k8s-live"}})
    monkeypatch.setenv("STEADYSTATE_TARGETS", "elsewhere.json")
    assert resolve_targets_path() == "elsewhere.json"
    assert list(load_targets_from_env()) == ["env"]
    monkeypatch.setenv("STEADYSTATE_TARGETS", "typo.json")
    with pytest.raises(OSError):  # a set-but-missing registry is never silent "no targets"
        load_targets_from_env()


def test_a_fresh_write_lands_in_the_committed_location(_cwd):
    assert resolve_targets_path() == COMMITTED_TARGETS_FILE  # neither exists yet
    assert load_targets_from_env() == {}  # ... and reading that is a clean empty, not an error


def test_explicit_beats_everything(_cwd):
    _write(_cwd, COMMITTED_TARGETS_FILE, {"committed": {"source": "k8s-live"}})
    assert resolve_targets_path("given.json") == "given.json"
