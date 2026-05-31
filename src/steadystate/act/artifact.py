"""Remediation artifacts -- a remediation expressed as a *code change*, not a live apply.

The deterministic counterpart to the live executors. Where ``terraform.py`` reconciles by
changing reality to match the repo (``terraform apply``), an artifact reconciles the *other*
direction: it proposes a repo change a human reviews and merges. The canonical form is a
**patch** (a git-apply-able unified diff) -- auth-free, VCS-agnostic, and a pure string, so it
is fully testable and provably *not* model-authored. A branch / PR is a way to *deliver* a
patch (see ``act/deliver/``), never the artifact itself.

The artifact is honest about **state**: a code change for a resource that isn't in state can't
just edit files -- it must import the resource (the safe, non-destructive direction) or destroy
it (never automatic). ``state_ops`` records that effect in plain language and ``destructive``
flags the dangerous direction, so the dimension the apply path glosses over is explicit here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..model import ChangeType


@dataclass
class RemediationArtifact:
    """A remediation rendered as a reviewable repo change.

    ``patch`` is the deterministic fix (a unified diff); ``state_ops`` and ``destructive`` make
    the state effect explicit (an import vs a destroy); ``title`` / ``body`` narrate it -- today
    deterministic, later LLM-authored when reasoning is enabled (the seam is the same)."""

    drift_identity: str  # the resource the change concerns, e.g. "aws_s3_bucket.logs"
    change_type: ChangeType
    path: str  # repo-relative file the patch creates or edits
    patch: str  # git-apply-able unified diff -- the canonical, auth-free fix
    state_ops: list[str] = field(default_factory=list)  # plain-language state effects (imports)
    destructive: bool = False  # True only for a destroy variant; gates labeling + delivery
    title: str = ""  # PR / commit title
    body: str = ""  # PR body: what changes, why, and the import/destroy implication

    @property
    def slug(self) -> str:
        """A filesystem-safe id for this artifact (used to name a delivered ``.patch``)."""
        return re.sub(r"[^A-Za-z0-9._-]", "_", self.drift_identity)


def new_file_patch(path: str, content: str) -> str:
    """A git-apply-able unified diff that *creates* ``path`` with ``content``.

    The whole-file-addition form (``--- /dev/null`` -> ``+++ b/<path>``) -- what ``git apply``
    expects for a new file. ``content`` is normalized to end in a newline so every added line,
    including the last, terminates cleanly and no ``\\ No newline at end of file`` marker is
    needed. Pure string assembly: deterministic and unit-testable, no git invoked."""
    if not content.endswith("\n"):
        content += "\n"
    lines = content.split("\n")[:-1]  # drop the empty trailing element from the final newline
    hunk = "".join(f"+{line}\n" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{hunk}"
    )
