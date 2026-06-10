"""Credential brokering -- `kubeconfig_from` mints a short-lived kubeconfig at probe time. These
pin the fail-closed discipline (a failed/missing/timed-out broker means the target is NOT probed,
with a secret-free reason), the credential's lifetime (a private temp file that dies with the
probe), the kubeconfig sanity check (an error message printed to stdout is never handed to kubectl
as creds), the registry round-trip + the kubeconfig/kubeconfig_from conflict, and both probe paths
(the fleet sweep and the single summon) actually consuming the brokered file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

import steadystate.sweep as sweep_mod
import steadystate.verbs as verbs_mod
from steadystate.broker import BrokerError, target_credentials
from steadystate.reason.report import Report
from steadystate.sweep import sweep_targets
from steadystate.targets import Target, load_targets, target_to_spec

PY = f'"{sys.executable}"'  # quoted -- the venv path survives shlex.split

# A broker that prints a minimal-but-shaped kubeconfig to stdout and exits 0.
GOOD_BROKER = f"{PY} -c \"print('apiVersion: v1\\\\nclusters: []')\""
# A broker that fails -- the SECRET on stdout must never appear in the error; stderr must.
BAD_BROKER = (
    f"{PY} -c \"import sys; print('SECRET-VALUE'); print('permission denied', "
    'file=sys.stderr); sys.exit(3)"'
)


def _target(**kw) -> Target:
    return Target(name=kw.pop("name", "demo"), source=kw.pop("source", "k8s-live"), **kw)


# -- the credential's lifetime ----------------------------------------------------------------


def test_a_static_target_passes_its_kubeconfig_through_untouched():
    with target_credentials(_target(kubeconfig="kube.yaml")) as kubeconfig:
        assert kubeconfig == "kube.yaml"
    with target_credentials(_target()) as kubeconfig:
        assert kubeconfig == ""  # ambient -- zero new behavior without kubeconfig_from


def test_a_brokered_credential_lives_exactly_one_probe():
    with target_credentials(_target(kubeconfig_from=GOOD_BROKER)) as kubeconfig:
        minted = Path(kubeconfig)
        assert minted.exists()
        assert "clusters" in minted.read_text(encoding="utf-8")
        assert "demo" in minted.name  # the temp file names its target (debuggable, not guessable)
    assert not minted.exists()  # deleted the moment the probe finishes


def test_the_brokered_file_is_deleted_even_when_the_probe_raises():
    with pytest.raises(RuntimeError, match="boom"):  # noqa: SIM117 -- the nesting IS the scenario
        with target_credentials(_target(kubeconfig_from=GOOD_BROKER)) as kubeconfig:
            minted = Path(kubeconfig)
            raise RuntimeError("boom")
    assert not minted.exists()


# -- fail closed, secret-free -----------------------------------------------------------------


def test_a_failing_broker_reports_stderr_and_exit_code_never_stdout():
    with (
        pytest.raises(BrokerError) as err,
        target_credentials(_target(kubeconfig_from=BAD_BROKER)),
    ):
        pytest.fail("the probe body must never run on a failed broker")
    message = str(err.value)
    assert "permission denied" in message and "exit 3" in message and "demo" in message
    assert "SECRET-VALUE" not in message  # stdout is the credential -- never quoted


def test_a_missing_broker_binary_is_a_clean_error():
    with (
        pytest.raises(BrokerError, match="not found.*on PATH"),
        target_credentials(_target(kubeconfig_from="no-such-broker-cli get --name x")),
    ):
        pass


def test_a_hung_broker_times_out(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_BROKER_TIMEOUT", "0.5")
    sleeper = f'{PY} -c "import time; time.sleep(10)"'
    with (
        pytest.raises(BrokerError, match="timed out"),
        target_credentials(_target(kubeconfig_from=sleeper)),
    ):
        pass


def test_output_that_is_not_a_kubeconfig_is_refused():
    # A vault error envelope printed to stdout with exit 0 must not reach kubectl as creds.
    not_kubeconfig = f"{PY} -c \"print('error: secret not found')\""
    with (
        pytest.raises(BrokerError, match="doesn't look like a kubeconfig"),
        target_credentials(_target(kubeconfig_from=not_kubeconfig)),
    ):
        pass


def test_an_empty_broker_command_is_refused():
    with (
        pytest.raises(BrokerError, match="empty"),
        target_credentials(_target(kubeconfig_from="   ")),
    ):
        pass


# -- the registry: round-trip + the conflict --------------------------------------------------


def test_kubeconfig_from_round_trips_through_the_registry(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text(
        json.dumps(
            {"prod": {"source": "k8s-live", "context": "prod", "kubeconfig_from": GOOD_BROKER}}
        )
    )
    loaded = load_targets(path)
    assert loaded["prod"].kubeconfig_from == GOOD_BROKER
    assert target_to_spec(loaded["prod"])["kubeconfig_from"] == GOOD_BROKER  # save writes it back


def test_setting_both_kubeconfig_and_kubeconfig_from_fails_at_load(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text(
        json.dumps(
            {"prod": {"source": "k8s-live", "kubeconfig": "kube.yaml", "kubeconfig_from": "x"}}
        )
    )
    with pytest.raises(ValueError, match="both 'kubeconfig' and 'kubeconfig_from'"):
        load_targets(path)


# -- the probe paths consume the brokered file ------------------------------------------------


def test_the_sweep_probes_with_the_brokered_kubeconfig(monkeypatch):
    seen: dict = {}

    def fake_build_report(source, path, **kw):
        seen["kubeconfig"] = kw["kubeconfig"]
        seen["existed"] = Path(kw["kubeconfig"]).exists()
        return Report()

    monkeypatch.setattr(sweep_mod, "build_report", fake_build_report)
    result = sweep_targets(
        {"prod": _target(name="prod", kubeconfig_from=GOOD_BROKER)}, "", stateless=True
    )
    assert result.results[0].ok
    assert seen["existed"] and seen["kubeconfig"].endswith(".kubeconfig")
    assert not Path(seen["kubeconfig"]).exists()  # gone the moment the probe finished


def test_a_failed_broker_marks_the_target_unreachable_not_the_sweep_dead(monkeypatch):
    monkeypatch.setattr(
        sweep_mod, "build_report", lambda *a, **k: pytest.fail("must not probe, fail closed")
    )
    result = sweep_targets(
        {"prod": _target(name="prod", kubeconfig_from=BAD_BROKER)}, "", stateless=True
    )
    assert result.unreachable == 1
    assert "permission denied" in result.results[0].detail
    assert "SECRET-VALUE" not in result.results[0].detail


def test_the_single_probe_brokers_too(monkeypatch, tmp_path):
    registry = tmp_path / "targets.json"
    registry.write_text(
        json.dumps({"prod": {"source": "k8s-live", "kubeconfig_from": GOOD_BROKER}})
    )
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(registry))
    seen: dict = {}

    def fake_build_report(source, path, **kw):
        seen["kubeconfig"] = kw["kubeconfig"]
        return Report()

    monkeypatch.setattr(verbs_mod, "build_report", fake_build_report)
    verbs_mod.probe_report("prod", "")
    assert seen["kubeconfig"].endswith(".kubeconfig")


def test_cli_targets_marks_a_brokered_target_too(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from steadystate.cli import app

    registry = tmp_path / "targets.json"
    registry.write_text(
        json.dumps({"prod": {"source": "k8s-live", "kubeconfig_from": GOOD_BROKER}})
    )
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(registry))
    result = CliRunner().invoke(app, ["targets"])
    assert result.exit_code == 0
    assert "[creds brokered at probe time]" in result.output


def test_targets_view_marks_a_brokered_target(monkeypatch, tmp_path):
    registry = tmp_path / "targets.json"
    registry.write_text(
        json.dumps(
            {
                "prod": {"source": "k8s-live", "kubeconfig_from": GOOD_BROKER},
                "staging": {"source": "k8s-live", "context": "stg"},
            }
        )
    )
    monkeypatch.setenv("STEADYSTATE_TARGETS", str(registry))
    view = verbs_mod._render_targets()
    prod_line = next(line for line in view.splitlines() if "prod" in line)
    staging_line = next(line for line in view.splitlines() if "staging" in line)
    assert "[creds brokered at probe time]" in prod_line
    assert "brokered" not in staging_line
