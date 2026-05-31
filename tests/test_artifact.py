"""Remediation artifacts: the deterministic codify renderer + a git-apply-able patch.

A remediation expressed as a *code change* (act/artifact.py, act/codify.py). The patch must be a
real unified diff `git apply` accepts, and the Terraform adopt renderer must turn a not-in-state
(REMOVED) drift into a non-destructive import -- never a destroy -- and decline everything else.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from steadystate.act.artifact import new_file_patch
from steadystate.act.codify import terraform_adopt
from steadystate.act.terraform import TerraformExecutor
from steadystate.model import ChangeType, Drift, Provenance


def _removed(identity: str = "aws_s3_bucket.logs", observed: dict | None = None) -> Drift:
    return Drift(
        identity=identity,
        kind=identity.split(".")[0],
        change_type=ChangeType.REMOVED,
        provenance=Provenance(source="terraform", address=identity),
        observed={"id": "my-logs-bucket", "acl": "private"} if observed is None else observed,
    )


# -- new_file_patch: a valid whole-file-addition unified diff --------------------


def test_new_file_patch_shape():
    patch = new_file_patch("dir/x.tf", "a\nb\n")
    assert patch.startswith("diff --git a/dir/x.tf b/dir/x.tf\n")
    assert "new file mode 100644\n--- /dev/null\n+++ b/dir/x.tf\n" in patch
    assert "@@ -0,0 +1,2 @@\n+a\n+b\n" in patch


def test_new_file_patch_normalizes_missing_trailing_newline():
    # No trailing newline in content -> still a clean patch (one normalized newline, no marker).
    patch = new_file_patch("x", "only-line")
    assert patch.endswith("@@ -0,0 +1,1 @@\n+only-line\n")
    assert "No newline" not in patch


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_patch_applies_cleanly_with_git(tmp_path):
    # The real proof: git must accept and apply the generated diff in a fresh repo.
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    artifact = terraform_adopt(_removed())
    patch_file = tmp_path / "fix.patch"
    patch_file.write_text(artifact.patch, encoding="utf-8")

    subprocess.run(["git", "apply", "--check", "fix.patch"], cwd=tmp_path, check=True)
    subprocess.run(["git", "apply", "fix.patch"], cwd=tmp_path, check=True)
    written = (tmp_path / artifact.path).read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket" "logs"' in written
    assert "import {" in written


# -- terraform_adopt: only the not-in-state case, and always non-destructive -----


def test_adopt_renders_import_and_resource_blocks():
    artifact = terraform_adopt(_removed())
    assert artifact is not None
    assert artifact.path == "steadystate-adopted/aws_s3_bucket.logs.tf"
    assert artifact.change_type is ChangeType.REMOVED
    assert artifact.destructive is False  # adopt imports; it never destroys
    body = artifact.patch
    assert "import {" in body and "to = aws_s3_bucket.logs" in body
    assert 'id = "my-logs-bucket"' in body  # taken from observed.id, not a placeholder
    assert 'resource "aws_s3_bucket" "logs" {' in body
    assert 'acl = "private"' in body  # a scalar observed attr is rendered
    assert any("imports" in op for op in artifact.state_ops)


def test_adopt_flags_unknown_import_id():
    artifact = terraform_adopt(_removed(observed={"acl": "private"}))  # no id in observed
    assert artifact is not None
    assert "REPLACE_WITH_IMPORT_ID" in artifact.patch
    assert any("Set the import `id`" in op for op in artifact.state_ops)
    assert "Set the import `id`" in artifact.body


def test_adopt_omits_nested_attrs_with_a_pointer_to_generate_config():
    artifact = terraform_adopt(_removed(observed={"id": "b", "tags": {"team": "infra"}}))
    assert artifact is not None
    assert "generate-config-out" in artifact.patch  # nested attr omitted, pointer left
    assert "tags" not in artifact.patch  # the nested dict itself is not rendered


def test_adopt_declines_non_removed_drift():
    for change in (ChangeType.MODIFIED, ChangeType.ADDED):
        drift = Drift(
            identity="aws_s3_bucket.logs",
            kind="aws_s3_bucket",
            change_type=change,
            provenance=Provenance(source="terraform"),
            observed={"id": "b"},
        )
        assert terraform_adopt(drift) is None  # apply direction / HCL edit -- out of this slice


def test_adopt_declines_malformed_address():
    assert terraform_adopt(_removed(identity="not-an-address")) is None


# -- the executor exposes it as the optional Proposer capability -----------------


def test_terraform_executor_is_a_proposer():
    from steadystate.act.base import Proposer

    executor = TerraformExecutor()
    assert isinstance(executor, Proposer)
    assert executor.propose(_removed()) is not None
