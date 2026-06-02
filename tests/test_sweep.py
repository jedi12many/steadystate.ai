"""The fleet sweep: probe every target, reconcile ONCE over the union, roll up a digest.

The correctness property a fleet must get right is here: one cluster recovering resolves *its*
finding without touching another cluster's (the union reconcile + per-cluster qualified identities),
and one unreachable cluster never sinks the sweep.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report
from steadystate.sweep import SweepResult, TargetResult, render_sweep
from steadystate.targets import TARGETS_ENV, Target


def _fire_report(identity: str, category: str = "CrashLoopBackOff") -> Report:
    """A Report with one malfunction Alert (a symptom) -- a cluster on fire."""
    symptom = Symptom(
        identity=identity,
        kind="Deployment",
        category=category,
        severity=Severity.HIGH,
        title=f"{identity} is {category}",
        detail="1 pod",
        provenance=Provenance(source="kubernetes", address=identity),
    )
    alert = Alert(
        title=f"{identity} is {category}",
        severity=Severity.HIGH,
        drifts=[],
        why_it_matters="pods failing",
        layer=Layer.ALERT,
        symptoms=[symptom],
    )
    return Report(items=[alert])


def _build_report(reports: dict[str, Report]):
    """A fake `build_report` keyed by context: returns the prepared Report, or raises for a context
    mapped to an Exception (an unreachable cluster)."""

    def fake(source, path, *, probe="auto", label="", context="", **_kw):
        value = reports[context]
        if isinstance(value, Exception):
            raise value
        return value

    return fake


# -- render_sweep -----------------------------------------------------------------------------


def test_render_sweep_tally_and_lines():
    result = SweepResult(
        results=(
            TargetResult("prod", ok=True, alerts=2, new=1, titles=("web crash", "api fail")),
            TargetResult("stg", ok=True, alerts=0),
            TargetResult("old", ok=False, detail="'kubectl get' not found"),
        ),
        resolved=("db fail",),
    )
    text = "\n".join(render_sweep(result, verbose=True))
    assert "3 cluster(s) -- 1 on fire, 1 clear, 1 unreachable" in text
    assert "2 alert(s) (1 new)" in text
    assert "web crash" in text  # verbose lists the fire titles
    assert "stg" in text and "clear" in text
    assert "old" in text and "unreachable -- 'kubectl get' not found" in text
    assert "resolved since last sweep (1)" in text and "db fail" in text


# -- sweep_targets ----------------------------------------------------------------------------


def test_sweep_counts_fire_clear_unreachable(monkeypatch):
    import steadystate.sweep as sweep

    reports = {"prod": _fire_report("prod/web"), "stg": Report(items=[]), "boom": RuntimeError("x")}
    monkeypatch.setattr(sweep, "build_report", _build_report(reports))
    targets = {
        "prod": Target("prod", "k8s-live", context="prod"),
        "stg": Target("stg", "k8s-live", context="stg"),
        "old": Target("old", "k8s-live", context="boom"),
    }
    result = sweep.sweep_targets(targets, ":memory:")
    assert (result.on_fire, result.clear, result.unreachable) == (1, 1, 1)
    byname = {r.name: r for r in result.results}
    assert byname["old"].ok is False and byname["old"].detail == "x"


def test_sweep_stateful_one_cluster_recovers_resolves_only_its_finding(monkeypatch, tmp_path):
    # The fleet correctness test: two clusters on fire, then prod recovers -- prod's finding must
    # resolve (the union reconcile sees it absent) while stg's stays (distinct qualified identity).
    import steadystate.sweep as sweep

    db = tmp_path / "state.db"
    now1 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    now2 = datetime(2026, 6, 2, 12, 0, 0, tzinfo=UTC)
    targets = {
        "prod": Target("prod", "k8s-live", context="prod"),
        "stg": Target("stg", "k8s-live", context="stg"),
    }

    monkeypatch.setattr(
        sweep,
        "build_report",
        _build_report({"prod": _fire_report("prod/web"), "stg": _fire_report("stg/web")}),
    )
    r1 = sweep.sweep_targets(targets, db, now1)
    assert r1.on_fire == 2
    assert all(tr.new == 1 for tr in r1.results)  # first sweep -> both new
    assert r1.resolved == ()

    # prod recovers; stg still on fire
    monkeypatch.setattr(
        sweep,
        "build_report",
        _build_report({"prod": Report(items=[]), "stg": _fire_report("stg/web")}),
    )
    r2 = sweep.sweep_targets(targets, db, now2)
    byname = {r.name: r for r in r2.results}
    assert byname["prod"].alerts == 0 and byname["stg"].alerts == 1
    assert byname["stg"].new == 0  # recurring across sweeps, not new
    assert any("prod/web" in t for t in r2.resolved)  # prod's fire resolved fleet-wide
    assert not any("stg/web" in t for t in r2.resolved)  # stg's was NOT cross-resolved


# -- CLI `sweep` ------------------------------------------------------------------------------


def test_cli_sweep_renders_a_fleet_digest(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    import steadystate.sweep as sweep
    from steadystate.cli import app

    (tmp_path / "steadystate.targets.json").write_text(
        json.dumps(
            {
                "prod": {"source": "k8s-live", "context": "prod"},
                "stg": {"source": "k8s-live", "context": "stg"},
            }
        )
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    monkeypatch.setattr(
        sweep,
        "build_report",
        _build_report({"prod": _fire_report("prod/web"), "stg": Report(items=[])}),
    )
    result = CliRunner().invoke(app, ["sweep", "--stateless"], env={"COLUMNS": "200"})
    assert result.exit_code == 0, result.output
    assert "1 on fire, 1 clear" in result.output


def test_cli_sweep_no_targets_file(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from steadystate.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    result = CliRunner().invoke(app, ["sweep"])
    assert result.exit_code == 0
    assert "no targets file" in result.output


# -- chat `probe all` -------------------------------------------------------------------------


def test_chat_probe_all_runs_a_stateful_sweep(monkeypatch, tmp_path):
    import steadystate.sweep as sweep
    from steadystate.inbound.base import command_from_text
    from steadystate.inbound.server import run_command

    tf = tmp_path / "targets.json"
    tf.write_text(json.dumps({"prod": {"source": "k8s-live", "context": "prod"}}))
    monkeypatch.setenv(TARGETS_ENV, str(tf))
    monkeypatch.setattr(sweep, "build_report", _build_report({"prod": _fire_report("prod/web")}))

    command = command_from_text("probe all", "tester")
    assert command is not None and command.argument == "all"  # parsed as a normal probe target
    out = run_command(command, "")  # empty state path -> the sweep degrades to stateless
    assert "Fleet sweep" in out and "1 on fire" in out


# -- sweep --to: push the fleet's fires to surfaces -------------------------------------------


def test_sweep_result_report_is_the_union_of_alerts(monkeypatch):
    import steadystate.sweep as sweep

    monkeypatch.setattr(
        sweep,
        "build_report",
        _build_report({"prod": _fire_report("prod/web"), "stg": _fire_report("stg/api")}),
    )
    targets = {
        "prod": Target("prod", "k8s-live", context="prod"),
        "stg": Target("stg", "k8s-live", context="stg"),
    }
    result = sweep.sweep_targets(targets, ":memory:")
    titles = {a.title for a in result.report.alerts}
    assert titles == {"prod/web is CrashLoopBackOff", "stg/api is CrashLoopBackOff"}


def test_cli_sweep_to_pushes_the_fleet_alerts_to_surfaces(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    import steadystate.sweep as sweep
    from steadystate import cli
    from steadystate.cli import app

    emitted: list = []

    class _Recorder:
        name = "rec"

        def emit(self, report, resolved=None):
            emitted.append(report)

    monkeypatch.setattr(cli, "_surfaces", lambda names: [_Recorder()] if names else [])
    (tmp_path / "steadystate.targets.json").write_text(
        json.dumps({"prod": {"source": "k8s-live", "context": "prod"}})
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(TARGETS_ENV, raising=False)
    monkeypatch.setattr(sweep, "build_report", _build_report({"prod": _fire_report("prod/web")}))

    result = CliRunner().invoke(
        app, ["sweep", "--to", "rec", "--stateless"], env={"COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    assert "1 on fire" in result.output  # the digest still prints to stdout
    assert emitted and [a.title for a in emitted[0].alerts] == ["prod/web is CrashLoopBackOff"]


# -- single probe now records (record-only, no cross-resolution) ------------------------------


def test_probe_records_findings_but_resolves_no_other_target(monkeypatch, tmp_path):
    import steadystate.inbound.server as server
    from steadystate.state import StateStore

    tf = tmp_path / "targets.json"
    tf.write_text(json.dumps({"prod": {"source": "k8s-live", "context": "prod"}}))
    monkeypatch.setenv(TARGETS_ENV, str(tf))
    db = str(tmp_path / "state.db")

    # Pre-seed another target's finding, so we can prove a single probe doesn't resolve it.
    with StateStore(db) as store:
        store.record(
            {"other-fp": ("high", "stg/api is CrashLoopBackOff")}, datetime(2026, 6, 1, tzinfo=UTC)
        )

    monkeypatch.setattr(server, "build_report", _build_report({"prod": _fire_report("prod/web")}))
    out = server._run_probe("prod", db, frozenset())
    assert "CrashLoopBackOff" in out  # still reports

    with StateStore(db) as store:
        findings = {f.fingerprint: f for f in store.all_findings()}
    # prod's finding was recorded (the db now persists it)...
    assert any("prod/web" in f.last_title for f in findings.values())
    # ...and the other target's finding is untouched -- record-only never resolves it.
    assert "other-fp" in findings and findings["other-fp"].status != "resolved"


def test_probe_creates_the_state_db_from_scratch(monkeypatch, tmp_path):
    import steadystate.inbound.server as server
    from steadystate.state import StateStore

    tf = tmp_path / "targets.json"
    tf.write_text(json.dumps({"prod": {"source": "k8s-live", "context": "prod"}}))
    monkeypatch.setenv(TARGETS_ENV, str(tf))
    db = tmp_path / "state.db"
    assert not db.exists()

    monkeypatch.setattr(server, "build_report", _build_report({"prod": _fire_report("prod/web")}))
    server._run_probe("prod", str(db), frozenset())
    assert db.exists()  # the probe created it
    with StateStore(str(db)) as store:
        assert store.all_findings()  # with the finding recorded
