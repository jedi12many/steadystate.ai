"""Deterministic codify renderers: a drift -> the *accept-reality* code change.

Every drift is ``declared != observed``, so it always has two fixes: **enforce** the config (a
live apply -- sometimes destructive, gated by ``plan.py``) or **accept reality** in code (edit the
files so config matches what's actually there). The second only ever edits files, never live
infra, so it's the safe complement the apply path can't always offer -- and it's what an operator
reviews and merges.

The first (and, for now, only) renderer covers steadystate's terraform ``REMOVED``: a plan
``delete`` -- the resource is **in state**, its config was removed, so the next apply would
*destroy* it. The accept-reality change is to **re-add the resource block** (NOT an ``import``
block: the resource is already managed, and importing an in-state address is a hard terraform
error). Restoring the declaration is additive -- a new file -- so it needs no HCL parser, which is
why REMOVED is the natural first case. MODIFIED/ADDED need to locate and edit an existing block
(the plan JSON doesn't say which file declares it), so ``terraform_restore`` returns ``None`` for
them today.

Honesty about limits: ``observed`` is the resource's full state, including read-only/computed
attributes terraform won't accept in a ``resource`` block, so the rendered block is a reviewed
*starting point*, not a guaranteed plan no-op -- complete it with ``terraform plan
-generate-config-out`` or restore the original from version control before applying.
"""

from __future__ import annotations

import re

from ..model import ChangeType, Drift
from .artifact import RemediationArtifact, new_file_patch

# A bare ``type.name`` terraform address -- exactly one dot, identifier on each side. This rejects
# module-nested (``module.foo.aws_s3_bucket.bar``) and indexed (``aws_instance.web[0]`` /
# ``["k"]``) addresses, whose blocks can't be faithfully reconstructed parser-free; those decline.
_BARE_ADDRESS = re.compile(r"^[a-z][a-z0-9_]*\.[A-Za-z_][A-Za-z0-9_-]*$")


def terraform_restore(drift: Drift) -> RemediationArtifact | None:
    """Render an accept-reality artifact for a terraform REMOVED drift, or None.

    REMOVED == config deleted while the resource is still in state, so apply would destroy it.
    The artifact re-adds the resource block (no import) so the declaration exists again and the
    destroy is averted. MODIFIED/ADDED -> None (their accept-change needs an HCL edit, out of this
    slice); a non-bare address -> None (can't reconstruct the block safely)."""
    if drift.change_type is not ChangeType.REMOVED:
        return None
    if not _BARE_ADDRESS.match(drift.identity):
        return None
    kind, _, name = drift.identity.partition(".")
    observed = drift.observed or {}

    content = _render_hcl(kind, name, drift.identity, observed)
    rel_path = f"steadystate-restored/{kind}.{name}.tf"

    return RemediationArtifact(
        drift_identity=drift.identity,
        change_type=drift.change_type,
        path=rel_path,
        patch=new_file_patch(rel_path, content),
        state_ops=[
            f"Re-adds the deleted declaration for {drift.identity} so the next apply does NOT "
            "destroy it. Review/complete the block before applying (see its comments).",
        ],
        destructive=False,  # editing files only -- never touches live infra
        title=f"Restore deleted declaration for {kind} `{name}`",
        body=_render_body(drift.identity),
    )


def _render_hcl(kind: str, name: str, address: str, observed: dict) -> str:
    lines = [
        f"# Restored by steadystate: {address} is still live but its Terraform config was removed,",
        "# so the next `terraform apply` would DESTROY it. Re-adding this declaration averts that.",
        "#",
        "# This is a reviewed STARTING POINT, not a guaranteed plan no-op: observed state can",
        "# include read-only/computed attributes terraform rejects in a resource block. Complete",
        "# it with `terraform plan -generate-config-out=generated.tf`, or restore the original",
        "# block from version control, before applying.",
        "",
        f'resource "{kind}" "{name}" {{',
    ]
    rendered, omitted = _render_attrs(observed)
    lines += [f"  {attr}" for attr in rendered]
    if omitted:
        lines.append(f"  # {omitted} attribute(s) omitted (nested/computed) -- see the note above.")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_attrs(observed: dict) -> tuple[list[str], int]:
    """Render the scalar attributes of ``observed`` as ``key = value`` HCL lines (a starting
    point); count the non-scalar ones skipped. ``id`` is read-only -- terraform always rejects it
    in config -- so it is never emitted."""
    rendered: list[str] = []
    omitted = 0
    for key in sorted(observed):
        if key == "id":
            continue
        hcl = _scalar(observed[key])
        if hcl is None:
            omitted += 1
        else:
            rendered.append(f"{key} = {hcl}")
    return rendered, omitted


def _scalar(value: object) -> str | None:
    """An HCL literal for a scalar, or None for a value too complex to render deterministically
    (dict/list/None) -- summarized as an omitted count and left to generate-config-out."""
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return f'"{_escape(value)}"'
    return None


def _escape(value: str) -> str:
    """Escape a string for an HCL double-quoted literal: backslashes and quotes, plus terraform's
    template markers ``${`` and ``%{`` (doubled), so an observed value containing them is rendered
    literally instead of being interpreted as interpolation."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${").replace("%{", "%%{")


def _render_body(address: str) -> str:
    return "\n".join(
        [
            f"`{address}` is still live, but its Terraform configuration was removed -- so the "
            "next `terraform apply` would **destroy** it.",
            "",
            "This change **re-adds the resource block** (no `import` -- the resource is already in "
            "state), so the declaration exists again and the destroy is averted. It only edits "
            "files; it never touches live infrastructure.",
            "",
            "⚠️ **Review before applying.** The block is a starting point reconstructed from "
            "observed state, which can include read-only/computed attributes. Complete it with "
            "`terraform plan -generate-config-out`, or restore the original block from version "
            "control, to reach a clean plan no-op.",
            "",
            "_Generated deterministically by steadystate -- no model authored this change._",
        ]
    )
