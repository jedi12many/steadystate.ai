"""Deterministic codify renderers: a drift -> the code change that reconciles it.

Pure functions, no infra and no model -- the artifact equivalent of ``plan.py``. The first
(and only, for now) case is the one that motivated artifacts: a Terraform resource that exists
in reality but is **not in state**. Reconciling it as a live apply would *destroy* it (never
auto-eligible, by design); the safe inverse is to **adopt** it -- add the resource block plus a
Terraform ``import`` block so ``terraform apply`` imports it into state instead of creating or
destroying anything.

Adopt is deliberately additive (a new file), so it needs no HCL parser -- steadystate rides
tool output, not raw-file surgery. Editing an existing block to *accept* a MODIFIED drift, and
the destroy variant, are follow-ups; ``terraform_adopt`` returns ``None`` for anything but the
not-in-state case so callers offer an artifact only where a safe one exists.
"""

from __future__ import annotations

from ..model import ChangeType, Drift
from .artifact import RemediationArtifact, new_file_patch

_IMPORT_ID_PLACEHOLDER = "REPLACE_WITH_IMPORT_ID"


def terraform_adopt(drift: Drift) -> RemediationArtifact | None:
    """Render an adopt artifact for a REMOVED (in-reality, not-in-state) Terraform drift, or None.

    REMOVED is the orphan case: the resource is live but unmanaged. The artifact imports it
    (non-destructive); MODIFIED/ADDED return None (their fix is the apply direction or needs an
    HCL edit, both out of this slice)."""
    if drift.change_type is not ChangeType.REMOVED:
        return None
    kind, _, name = drift.identity.partition(".")
    if not kind or not name:
        return None  # not a "type.name" address -- can't form a resource block safely
    observed = drift.observed or {}

    raw_id = observed.get("id")
    id_known = isinstance(raw_id, str) and bool(raw_id)
    import_id = raw_id if id_known else _IMPORT_ID_PLACEHOLDER

    content = _render_hcl(kind, name, drift.identity, str(import_id), id_known, observed)
    rel_path = f"steadystate-adopted/{kind}.{name}.tf"

    state_ops = [
        f"Adds a Terraform `import` block: `terraform apply` imports {drift.identity} into "
        "state instead of creating it -- nothing is created or destroyed.",
    ]
    if not id_known:
        state_ops.append(
            "Set the import `id` before applying -- steadystate could not determine it from "
            "observed state."
        )

    return RemediationArtifact(
        drift_identity=drift.identity,
        change_type=drift.change_type,
        path=rel_path,
        patch=new_file_patch(rel_path, content),
        state_ops=state_ops,
        destructive=False,  # adopt never destroys; a destroy variant is a separate, opt-in path
        title=f"Adopt unmanaged {kind} `{name}` into Terraform",
        body=_render_body(drift.identity, id_known, observed),
    )


def _render_hcl(
    kind: str, name: str, address: str, import_id: str, id_known: bool, observed: dict
) -> str:
    lines = [
        f"# Adopted by steadystate: {address} exists in the environment but is not in Terraform.",
        "# Merging this and running `terraform apply` IMPORTS it into state --",
        "# nothing is created or destroyed.",
    ]
    if not id_known:
        lines.append("# NOTE: set the import id below -- it could not be read from observed state.")
    lines += [
        "",
        "import {",
        f"  to = {address}",
        f'  id = "{_escape(import_id)}"',
        "}",
        "",
        f'resource "{kind}" "{name}" {{',
    ]
    rendered, omitted = _render_attrs(observed)
    lines += [f"  {attr}" for attr in rendered]
    if omitted:
        lines += [
            f"  # {omitted} attribute(s) omitted (nested/computed). To fill the full config, run:",
            "  #   terraform plan -generate-config-out=generated.tf",
            "  # then merge the generated block here.",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_attrs(observed: dict) -> tuple[list[str], int]:
    """Render the scalar attributes of ``observed`` as ``key = value`` HCL lines; count the
    non-scalar ones skipped. ``id`` is handled by the import block, never emitted as an attr."""
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
    (dict/list/None) -- those are summarized as an omitted count and left to generate-config-out."""
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return f'"{_escape(value)}"'
    return None


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _render_body(address: str, id_known: bool, observed: dict) -> str:
    parts = [
        f"`{address}` exists in the live environment but is **not managed by Terraform** "
        "(absent from your configuration and state).",
        "",
        "This change **adopts** it: it adds the resource block plus a Terraform `import` block, "
        "so applying imports the existing resource into state. **Nothing is created or "
        "destroyed** -- the safe, non-destructive direction (reconciling this as an apply would "
        "instead *delete* the live resource, which steadystate never does automatically).",
    ]
    if not id_known:
        parts += [
            "",
            "⚠️ **Set the import `id` before applying** -- steadystate could not determine it "
            "from observed state.",
        ]
    parts += [
        "",
        "_Generated deterministically by steadystate -- no model authored this change._",
    ]
    return "\n".join(parts)
