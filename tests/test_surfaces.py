"""Surface registry tests -- the wiring guard for notify, mirroring test_registry.

A surface registered without being reachable (or a renamed/broken constructor)
fails here, the same way the source registry fails on a built-but-unwired source.
"""

import json

import pytest

from steadystate.notify import SURFACES, build_surfaces
from steadystate.notify.base import Surface


def test_known_surfaces_registered():
    assert {"console", "slack", "teams", "discord", "prometheus", "grafana"} <= set(SURFACES)


def test_every_registered_surface_builds_and_conforms():
    # A broken/renamed zero-arg constructor fails here.
    for name in SURFACES:
        surface = SURFACES[name]()
        assert isinstance(surface, Surface)
        assert surface.name == name


def test_build_surfaces_maps_each_registered_name():
    names = sorted(SURFACES)
    built = build_surfaces(names)
    assert len(built) == len(names)
    for name, surface in zip(names, built, strict=True):
        assert isinstance(surface, Surface)
        assert callable(surface.emit)
        assert surface.name == name


def test_build_surfaces_preserves_order_and_duplicates():
    built = build_surfaces(["console", "console"])
    assert [s.name for s in built] == ["console", "console"]


def test_build_surfaces_unknown_raises_valueerror():
    with pytest.raises(ValueError):
        build_surfaces(["console", "nope"])


def test_alert_resources_and_label_cap():
    from steadystate.model import ChangeType, Drift, Provenance
    from steadystate.reason.alert import Alert, Severity

    def drift(i: int) -> Drift:
        return Drift(
            identity=f"aws_instance.web{i}",
            kind="aws_instance",
            change_type=ChangeType.MODIFIED,
            provenance=Provenance(source="terraform"),
        )

    one = Alert(title="t", severity=Severity.HIGH, drifts=[drift(0)], why_it_matters="w")
    assert one.resources == ["aws_instance.web0"]
    assert one.resource_label() == "aws_instance.web0"

    many = Alert(
        title="t", severity=Severity.HIGH, drifts=[drift(i) for i in range(7)], why_it_matters="w"
    )
    assert many.resource_label(limit=5).endswith("(+2 more)")  # caps the list, counts the rest


def test_alert_resources_fall_back_to_policy_findings():
    from steadystate.domains.base import PolicyFinding, Severity
    from steadystate.model import Provenance
    from steadystate.reason.alert import Alert

    finding = PolicyFinding(
        rule_id="CIS-Docker-5.4",
        identity="service:web",
        provenance=Provenance(source="docker-compose"),
        severity=Severity.HIGH,
        title="web runs privileged",
        detail="privileged: true",
    )
    alert = Alert(
        title="t", severity=Severity.HIGH, drifts=[], why_it_matters="w", findings=[finding]
    )
    assert alert.resources == ["service:web"]  # no drift -> the policy finding's identity


def test_cli_rejects_unknown_to_value(tmp_path):
    # Robust end-to-end check: an unknown --to is a clean non-zero CLI exit, not a
    # stack trace. Skipped only if the CLI test deps aren't importable.
    typer_testing = pytest.importorskip("typer.testing")
    from steadystate.cli import app

    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))  # valid, empty source input

    runner = typer_testing.CliRunner()
    result = runner.invoke(app, ["scan", str(plan), "--to", "nope"])
    assert result.exit_code != 0
    assert "nope" in result.output.lower()
