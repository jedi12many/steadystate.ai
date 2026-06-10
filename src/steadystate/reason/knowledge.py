"""The committed knowledge base: ``steadystate/kb/*.md`` -- the team's own docs, answerable in chat.

The Tier-1 half of the chat surface. The live half ("are the runners ok?") is answered from state
(`summary` / `health` / `findings`); this answers the *process* half ("how do I request a new
project?", "what services does this team offer?") from markdown the team already writes -- committed
beside the IaC and reviewed in PRs, the same convention as ``checks.json`` / ``solutions.json`` /
``config.toml``. The repo IS the knowledge base; there is no second system to keep in sync.

Retrieval is deterministic and stdlib: docs are split into heading-delimited sections and scored by
keyword overlap -- a KB is a folder of docs, not a corpus, so there's no index and no embeddings.
The model never free-recalls: it answers ONLY from the retrieved sections and cites the file. With
no model configured, ``ask`` degrades honestly to the matching sections verbatim, with their
sources -- still a useful Tier-1 answer, never a fabricated one.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..config import config_table

DEFAULT_KB_DIR = "steadystate/kb"  # the committed convention, beside config.toml / solutions.json
KB_ENV = "STEADYSTATE_KB"

_ASK_CALLER = "ask"  # the cost-ledger tag; the answer is the product, so it rides the default model
_MAX_SECTIONS = 4  # how many retrieved sections ground one answer
_CLIP = 2400  # chars of one section fed to the model / shown in the degrade -- keeps prompts sane


def kb_dir() -> Path:
    """Where the knowledge base lives: ``STEADYSTATE_KB`` > ``[knowledge] dir`` in the committed
    config > the ``steadystate/kb`` convention -- bare ``./kb`` inside a ``steadystate/`` tree (a
    silo), where the committed prefix would stutter. CWD-relative like the other intent files, so
    ``--silo`` (which chdirs) gets a per-silo KB."""
    from ..config import in_steadystate_tree

    env = os.environ.get(KB_ENV, "").strip()
    if env:
        return Path(env)
    configured = config_table("knowledge").get("dir")
    if isinstance(configured, str) and configured.strip():
        return Path(configured.strip())
    default = Path(DEFAULT_KB_DIR)
    if default.is_dir() or not in_steadystate_tree():
        return default
    return Path("kb")


@dataclass(frozen=True)
class Section:
    """One heading-delimited slice of a KB doc -- the unit retrieval scores and an answer cites."""

    source: str  # the file, relative to the KB root (the citation an answer carries)
    heading: str  # the section's heading (the filename stem for a doc's preamble)
    text: str  # the body under that heading


_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


def _split_sections(source: str, text: str) -> list[Section]:
    """Split one markdown doc into its heading-delimited sections. Content before the first heading
    belongs to a section named after the file, so a heading-less doc is still one findable section.
    Pure."""
    sections: list[Section] = []
    heading = Path(source).stem
    lines: list[str] = []

    def flush() -> None:
        body = "\n".join(lines).strip()
        if body:
            sections.append(Section(source, heading, body))

    for line in text.splitlines():
        match = _HEADING.match(line)
        if match:
            flush()
            heading = match.group(2).strip() or heading
            lines = []
        else:
            lines.append(line)
    flush()
    return sections


def load_kb(root: Path | None = None) -> list[Section]:
    """Every section of every ``*.md`` under the KB root (recursive), in path order. ``[]`` when
    the folder doesn't exist -- the caller renders the convention hint. Read-only; an unreadable
    file is skipped, never a crash."""
    base = root if root is not None else kb_dir()
    if not base.is_dir():
        return []
    sections: list[Section] = []
    for path in sorted(base.rglob("*.md")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sections.extend(_split_sections(path.relative_to(base).as_posix(), text))
    return sections


# Words that carry no signal in a question ("how do I ...?"). Deliberately tiny -- a KB query is a
# handful of content words, and over-stripping hurts more than under-stripping.
_STOPWORDS = frozenset(
    {"a", "an", "and", "are", "can", "do", "does", "for", "get", "how", "i", "if", "in", "is",
     "it", "me", "my", "new", "of", "on", "or", "our", "the", "to", "want", "we", "what", "when",
     "where", "which", "who", "why", "with", "you", "your"}
)  # fmt: skip


def _terms(text: str) -> list[str]:
    """The content words of a question, lowercased -- what retrieval scores against. Pure."""
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 1 and t not in _STOPWORDS]


def _score(section: Section, terms: list[str]) -> int:
    """How well one section matches the question's terms. A filename/heading hit outweighs body
    hits (a doc ABOUT openstack beats a doc that mentions it), and body hits are capped per term so
    a long doc can't win on repetition alone. Pure."""
    name = f"{section.source.lower()} {section.heading.lower()}"
    body = section.text.lower()
    score = 0
    for term in terms:
        if term in name:
            score += 4
        score += min(body.count(term), 3)
    return score


def search(sections: list[Section], question: str, *, limit: int = _MAX_SECTIONS) -> list[Section]:
    """The ``limit`` best-matching sections for ``question``, best first; only real matches (score
    over zero) -- an unanswerable question returns ``[]``, it never pads with noise. Pure."""
    terms = _terms(question)
    if not terms:
        return []
    scored = [(sec, _score(sec, terms)) for sec in sections]
    matched = [(sec, sc) for sec, sc in scored if sc > 0]
    matched.sort(key=lambda pair: -pair[1])  # stable: path order breaks ties
    return [sec for sec, _ in matched[:limit]]


_ASK_SYSTEM = (
    "You are this team's Tier-1 service-desk assistant in chat. Answer the question using ONLY "
    "the documentation excerpts provided -- they are the team's committed docs (services offered, "
    "how-tos, onboarding). Be concrete and complete: when the doc gives steps, give the steps; "
    "when it names a contact, a link, or a form, repeat it exactly. End with the source in "
    "parentheses, e.g. (from openstack.md). If the excerpts do not answer the question, say so "
    "plainly and name the closest doc you were given -- NEVER invent a policy, a link, a name, or "
    "a step that is not in the excerpts."
)


def _excerpts(found: list[Section]) -> str:
    """The retrieved sections as cited blocks -- the grounding fed to the model, and the verbatim
    degrade shown when there's no model. Pure."""
    blocks = []
    for sec in found:
        body = sec.text[:_CLIP] + (" ..." if len(sec.text) > _CLIP else "")
        blocks.append(f"--- {sec.source} # {sec.heading}\n{body}")
    return "\n\n".join(blocks)


def ask_kb(
    question: str, complete: Callable[[str, str, str], str | None] | None, root: Path | None = None
) -> str:
    """Answer ``question`` from the committed KB: deterministic retrieval, then -- via ``complete``,
    the analyst's LLM seam -- a synthesized answer grounded ONLY in the retrieved sections. Every
    miss is honest: no KB names the convention to start one, no match says what was searched, and
    no model (or a failed call) shows the matching sections verbatim instead of guessing."""
    question = question.strip()
    if not question:
        return "ask what? -- `ask <question>`, e.g. `ask how do I request a new project`."
    where = (root if root is not None else kb_dir()).as_posix()
    sections = load_kb(root)
    if not sections:
        return (
            f"no knowledge base here -- commit the team's docs as markdown under {where}/ "
            "(services offered, how-tos, onboarding); `ask` answers from them, citing the file."
        )
    found = search(sections, question)
    if not found:
        docs = len({sec.source for sec in sections})
        return (
            f"nothing in the knowledge base matches that ({docs} doc(s) loaded from {where}/). "
            "Try different words, or add the doc."
        )
    if complete is None:
        return (
            "no LLM configured -- the closest sections verbatim (set ANTHROPIC_API_KEY for a "
            f"synthesized answer):\n\n{_excerpts(found)}"
        )
    user = f"Documentation excerpts:\n\n{_excerpts(found)}\n\nQuestion: {question}"
    reply = complete(_ASK_SYSTEM, user, _ASK_CALLER)
    if not reply or not reply.strip():
        return f"the model call failed -- the closest sections verbatim:\n\n{_excerpts(found)}"
    return reply.strip()
