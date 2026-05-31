"""`--autonomy suggest` carries the accept-reality patch (codify folded into suggest).

A suggestion records the enforce command when apply-eligible AND/OR an accept-reality patch when
the executor can render one. The point: a REMOVED drift -- which `suggest` recorded *nothing* for
before (it's never apply-eligible) -- is now recorded with its restore patch, and `pending` shows
it. It is never returned for auto-apply, so `auto` still never destroys.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from steadystate import cli
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.alert import Alert, Severity
from steadystate.reason.report import Report
from steadystate.state import PENDING, PendingAction, StateStore


def _report(*drifts: Drift) -> Report:
    return Report(items=[Alert("t", Severity.MEDIUM, list(drifts), "why")])


def _drift(change: ChangeType, identity: str = "aws_s3_bucket.logs") -> Drift:
    return Drift(
        identity=identity,
        kind=identity.split(".")[0],
        change_type=change,
        provenance=Provenance(source="terraform", address=identity),
        observed={"id": "b", "acl": "private"} if change is ChangeType.REMOVED else None,
        declared={"acl": "public"} if change is ChangeType.MODIFIED else None,
    )


def test_removed_drift_recorded_with_patch_but_not_auto_applied(tmp_path):
    store = StateStore(":memory:")
    report = _report(_drift(ChangeType.REMOVED))

    eligible = cli._record_suggestions(
        store, "terraform", tmp_path, report, datetime.now(UTC), None
    )

    assert eligible == []  # REMOVED is never apply-eligible -> never reaches auto-apply
    [pending] = store.all_pending()
    assert pending.command == ""  # no enforce direction
    assert pending.patch is not None and 'resource "aws_s3_bucket" "logs"' in pending.patch
    assert "import {" not in pending.patch


def test_eligible_drift_recorded_with_command_and_returned(tmp_path):
    store = StateStore(":memory:")
    report = _report(_drift(ChangeType.MODIFIED))

    eligible = cli._record_suggestions(
        store, "terraform", tmp_path, report, datetime.now(UTC), None
    )

    assert eligible == [_drift(ChangeType.MODIFIED).fingerprint]  # enforce path unchanged
    [pending] = store.all_pending()
    assert "terraform apply" in pending.command
    assert pending.patch is None  # MODIFIED has no codify renderer yet


def test_observe_only_source_records_nothing(tmp_path):
    store = StateStore(":memory:")
    eligible = cli._record_suggestions(
        store, "k8s", tmp_path, _report(_drift(ChangeType.REMOVED)), datetime.now(UTC), None
    )
    assert eligible == []
    assert store.all_pending() == []  # no executor -> nothing to enforce or accept


def test_pending_shows_the_accept_patch(tmp_path):
    typer_testing = pytest.importorskip("typer.testing")
    db = tmp_path / "state.db"
    with StateStore(db) as store:
        store.record_pending(
            PendingAction(
                fingerprint="fp1",
                source="terraform",
                path=str(tmp_path),
                drift_identity="aws_s3_bucket.logs",
                command="",
                status=PENDING,
                patch='resource "aws_s3_bucket" "logs" {\n}\n',
            ),
            datetime.now(UTC),
        )

    result = typer_testing.CliRunner().invoke(cli.app, ["pending", "--state", str(db)])
    assert result.exit_code == 0, result.output
    assert "accept reality" in result.output
    assert 'resource "aws_s3_bucket" "logs"' in result.output
