"""Delivery adapters: the patch-file (Level 0) adapter + the registry.

patch-file is the auth-free floor -- it writes the artifact's diff to disk so a human runs
`git apply`. The registry mirrors notify/SURFACES (build_deliveries, unknown -> ValueError).
"""

from __future__ import annotations

import pytest

from steadystate.act.artifact import RemediationArtifact
from steadystate.act.deliver import build_deliveries
from steadystate.act.deliver.patch_file import PatchFileDelivery
from steadystate.model import ChangeType


def _artifact() -> RemediationArtifact:
    return RemediationArtifact(
        drift_identity="aws_s3_bucket.logs",
        change_type=ChangeType.REMOVED,
        path="steadystate-adopted/aws_s3_bucket.logs.tf",
        patch="diff --git a/x b/x\n",
        state_ops=["imports it"],
        title="Adopt unmanaged aws_s3_bucket `logs`",
    )


def test_patch_file_writes_the_diff(tmp_path):
    adapter = PatchFileDelivery(out_dir=tmp_path)
    assert adapter.ready() is True  # no external config -- always available
    receipt = adapter.deliver(_artifact())
    assert receipt.delivered is True
    dest = tmp_path / "aws_s3_bucket.logs.patch"
    assert dest.read_text(encoding="utf-8") == "diff --git a/x b/x\n"
    assert receipt.ref == str(dest)


def test_patch_file_slug_is_filesystem_safe(tmp_path):
    art = _artifact()
    art.drift_identity = "module.a/weird name"
    PatchFileDelivery(out_dir=tmp_path).deliver(art)
    written = list(tmp_path.glob("*.patch"))
    assert len(written) == 1
    assert written[0].name == "module.a_weird_name.patch"


def test_patch_file_honors_env_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("STEADYSTATE_PATCH_DIR", str(tmp_path / "out"))
    adapter = PatchFileDelivery()
    receipt = adapter.deliver(_artifact())
    assert receipt.ref.startswith(str(tmp_path / "out"))


def test_build_deliveries_resolves_builtin_and_rejects_unknown():
    [adapter] = build_deliveries(["patch-file"])
    assert adapter.name == "patch-file"
    with pytest.raises(ValueError, match="unknown delivery 'nope'"):
        build_deliveries(["nope"])
