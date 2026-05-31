"""Remediation artifacts: the deterministic codify renderer + a git-apply-able patch.

A remediation expressed as an *accept-reality* code change (act/artifact.py, act/codify.py). The
patch must be a real unified diff `git apply` accepts. For steadystate's terraform `REMOVED`
(config deleted while the resource is still in state, so apply would destroy it), the renderer
must **re-add the resource block with NO `import` block** -- importing an in-state address is a
hard terraform error -- and must decline addresses whose blocks can't be reconstructed safely.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from steadystate.act.artifact import new_file_patch
from steadystate.act.codify import terraform_restore
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
    patch = new_file_patch("x", "only-line")
    assert patch.endswith("@@ -0,0 +1,1 @@\n+only-line\n")
    assert "No newline" not in patch


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_patch_applies_cleanly_with_git(tmp_path):
    # Proves the diff is valid git (NOT that `terraform apply` of it is a no-op -- that needs a
    # provider + state, an integration concern; see the module docstring's generate-config caveat).
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    artifact = terraform_restore(_removed())
    (tmp_path / "fix.patch").write_text(artifact.patch, encoding="utf-8")

    subprocess.run(["git", "apply", "--check", "fix.patch"], cwd=tmp_path, check=True)
    subprocess.run(["git", "apply", "fix.patch"], cwd=tmp_path, check=True)
    written = (tmp_path / artifact.path).read_text(encoding="utf-8")
    assert 'resource "aws_s3_bucket" "logs"' in written


# -- terraform_restore: re-add the block, never an import, never a destroy -------


def test_restore_renders_a_resource_block_and_no_import():
    artifact = terraform_restore(_removed())
    assert artifact is not None
    assert artifact.path == "steadystate-restored/aws_s3_bucket.logs.tf"
    assert artifact.change_type is ChangeType.REMOVED
    assert artifact.destructive is False  # edits files only -- never live infra
    body = artifact.patch
    assert 'resource "aws_s3_bucket" "logs" {' in body
    assert "import {" not in body  # the bug this fixes: in-state import is a hard tf error
    assert 'acl = "private"' in body  # a scalar observed attr, as a starting point
    assert "id =" not in body  # id is read-only -- never emitted as config
    assert any("does NOT destroy" in op or "destroy" in op for op in artifact.state_ops)


def test_restore_omits_nested_attrs_and_points_at_generate_config():
    artifact = terraform_restore(_removed(observed={"id": "b", "tags": {"team": "infra"}}))
    assert artifact is not None
    assert "tags" not in artifact.patch  # the nested dict is not rendered
    assert "generate-config-out" in artifact.patch  # the honest way to complete the block


def test_restore_escapes_hcl_interpolation():
    artifact = terraform_restore(_removed(observed={"name": "live-${env}-bkt"}))
    assert artifact is not None
    assert "$${env}" in artifact.patch  # not interpreted as terraform interpolation


def test_restore_declines_non_removed_drift():
    for change in (ChangeType.MODIFIED, ChangeType.ADDED):
        drift = Drift(
            identity="aws_s3_bucket.logs",
            kind="aws_s3_bucket",
            change_type=change,
            provenance=Provenance(source="terraform"),
            observed={"id": "b"},
        )
        assert terraform_restore(drift) is None  # accept-change needs an HCL edit -- out of slice


@pytest.mark.parametrize(
    "address",
    [
        "not-an-address",  # no dot
        "module.foo.aws_s3_bucket.bar",  # module-nested
        "aws_instance.web[0]",  # count index
        'aws_instance.web["k"]',  # for_each key
    ],
)
def test_restore_declines_addresses_it_cannot_reconstruct(address):
    assert terraform_restore(_removed(identity=address)) is None


# -- the executor exposes it as the optional Proposer capability -----------------


def test_terraform_executor_is_a_proposer():
    from steadystate.act.base import Proposer

    executor = TerraformExecutor()
    assert isinstance(executor, Proposer)
    assert executor.propose(_removed()) is not None
