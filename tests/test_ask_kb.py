"""`ask` -- the committed knowledge base (steadystate/kb/*.md) answers process questions in chat.
These pin the retrieval (heading-delimited sections, keyword scoring, heading-beats-body), the
honest degrades (no KB / no match / no model / failed call -- never an invented answer), the
verbatim-question grammar (a flag word inside a question isn't eaten), and the confident-parse
guard (a sentence merely containing 'ask' goes to the model whole)."""

from __future__ import annotations

from pathlib import Path

import pytest

from steadystate.inbound.base import ASK, command_from_text, tool_schema
from steadystate.inbound.translate import confident_command
from steadystate.reason.knowledge import (
    Section,
    _split_sections,
    ask_kb,
    kb_dir,
    load_kb,
    search,
)


def _kb(tmp_path: Path) -> Path:
    """A small two-doc knowledge base: a projects how-to and a services overview."""
    root = tmp_path / "kb"
    root.mkdir()
    (root / "projects.md").write_text(
        "# Projects\n\nThe platform team provisions tenant projects.\n\n"
        "## Requesting a new project\n\nOpen a ticket in the SERVICE-DESK queue with the project "
        "name and quota. Approval takes one business day.\n\n"
        "## Quota increases\n\nMail the platform list with the project name and the new quota.\n",
        encoding="utf-8",
    )
    (root / "services.md").write_text(
        "Intro without a heading: we run the shared platform.\n\n"
        "# Services we offer\n\nManaged clusters, CI runners, and object storage. A project is "
        "the unit of tenancy; project requests go through the service desk.\n",
        encoding="utf-8",
    )
    return root


# -- splitting & loading ----------------------------------------------------------------------


def test_split_sections_by_heading_with_filename_preamble():
    sections = _split_sections("services.md", "intro text\n\n# Offer\nclusters\n## Sub\nrunners\n")
    assert [(s.heading, s.text) for s in sections] == [
        ("services", "intro text"),  # pre-heading content is findable under the file's name
        ("Offer", "clusters"),
        ("Sub", "runners"),
    ]
    assert all(s.source == "services.md" for s in sections)


def test_load_kb_missing_dir_is_empty(tmp_path):
    assert load_kb(tmp_path / "nowhere") == []


def test_load_kb_reads_nested_docs(tmp_path):
    root = _kb(tmp_path)
    (root / "teams").mkdir()
    (root / "teams" / "runners.md").write_text("# Runner escalation\npage the platform on-call\n")
    sections = load_kb(root)
    assert "teams/runners.md" in {s.source for s in sections}  # recursive, posix-relative source


# -- retrieval --------------------------------------------------------------------------------


def test_search_prefers_a_heading_hit_over_body_mentions(tmp_path):
    sections = load_kb(_kb(tmp_path))
    found = search(sections, "how do I request a new project?")
    # The section ABOUT requesting a project outranks the services doc that mentions projects.
    assert found[0].heading == "Requesting a new project"
    assert "SERVICE-DESK" in found[0].text


def test_search_with_no_content_words_finds_nothing(tmp_path):
    sections = load_kb(_kb(tmp_path))
    assert search(sections, "how do I?") == []
    assert search(sections, "") == []


def test_search_never_pads_with_non_matches():
    sections = [Section("a.md", "alpha", "nothing relevant here")]
    assert search(sections, "openstack quota") == []


# -- the honest degrades ----------------------------------------------------------------------


def test_ask_without_a_kb_names_the_convention(tmp_path):
    reply = ask_kb("how do I request a project?", None, root=tmp_path / "kb")
    assert "no knowledge base here" in reply and "kb" in reply


def test_ask_with_no_match_says_what_was_searched(tmp_path):
    reply = ask_kb("zebra xylophone", None, root=_kb(tmp_path))
    assert "nothing in the knowledge base matches" in reply
    assert "2 doc(s)" in reply


def test_ask_without_a_model_returns_the_sections_verbatim(tmp_path):
    reply = ask_kb("how do I request a new project?", None, root=_kb(tmp_path))
    assert "no LLM configured" in reply
    assert "projects.md # Requesting a new project" in reply  # the citation
    assert "SERVICE-DESK" in reply  # the verbatim doc text -- still a usable Tier-1 answer


def test_ask_with_a_failed_model_call_degrades_to_verbatim(tmp_path):
    reply = ask_kb("request a new project", lambda *_a: None, root=_kb(tmp_path))
    assert "the model call failed" in reply and "SERVICE-DESK" in reply


def test_ask_with_an_empty_question_asks_back(tmp_path):
    assert "ask what?" in ask_kb("   ", None, root=_kb(tmp_path))


# -- grounded synthesis -----------------------------------------------------------------------


def test_ask_grounds_the_model_in_the_retrieved_sections_and_tags_spend(tmp_path):
    seen: dict = {}

    def complete(system: str, user: str, caller: str) -> str:
        seen["system"], seen["user"], seen["caller"] = system, user, caller
        return "Open a SERVICE-DESK ticket with the name and quota. (from projects.md)"

    reply = ask_kb("how do I request a new project?", complete, root=_kb(tmp_path))
    assert reply.startswith("Open a SERVICE-DESK ticket")
    assert seen["caller"] == "ask"  # its own cost-ledger tag
    assert "SERVICE-DESK" in seen["user"]  # the retrieved doc text IS the grounding
    assert "how do I request a new project?" in seen["user"]
    assert "ONLY" in seen["system"] and "invent" in seen["system"].lower()  # the honesty rule


# -- the chat grammar -------------------------------------------------------------------------


def test_ask_takes_the_question_verbatim_even_with_flag_words():
    command = command_from_text("ask how much does the llm cost", "amy")
    assert command is not None and command.verb == ASK
    assert command.argument == "how much does the llm cost"  # 'cost' stays in the question
    assert command.flags == frozenset()


def test_a_bare_ask_is_not_actionable():
    assert command_from_text("ask", "amy") is None


def test_confident_ask_must_lead_the_line():
    # A typed `ask ...` is a confident command; a sentence that merely contains the word goes to
    # the model whole, so the question keeps its lead-in.
    confident = confident_command("ask how do I get more quota", "amy")
    assert confident is not None and confident.argument == "how do I get more quota"
    assert confident_command("how do I ask for more quota?", "amy") is None


def test_ask_is_a_read_only_tool_with_a_required_question():
    tool = next(t for t in tool_schema()["tools"] if t["name"] == ASK)
    assert tool["effect"] == "read-only"  # exposed over MCP without any grant
    assert tool["args"] == [{"name": "question", "required": True}]


# -- the verb surface (run_command path, no model configured) ---------------------------------


@pytest.fixture
def _no_llm(monkeypatch):
    for var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "STEADYSTATE_LLM_BASE_URL",
        "STEADYSTATE_LLM_API_KEY",
        "STEADYSTATE_LLM_MODEL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_render_ask_degrades_without_an_analyst(tmp_path, monkeypatch, _no_llm):
    from steadystate.inbound.base import Command
    from steadystate.verbs import run_command

    monkeypatch.setenv("STEADYSTATE_KB", str(_kb(tmp_path)))
    reply = run_command(Command(ASK, "amy", "how do I request a new project?"), "")
    assert "no LLM configured" in reply and "SERVICE-DESK" in reply


def test_kb_dir_precedence_env_over_config_over_default(tmp_path, monkeypatch):
    monkeypatch.delenv("STEADYSTATE_KB", raising=False)
    monkeypatch.chdir(tmp_path)
    assert kb_dir() == Path("steadystate/kb")  # the committed convention
    (tmp_path / "steadystate").mkdir()
    (tmp_path / "steadystate" / "config.toml").write_text('[knowledge]\ndir = "docs/kb"\n')
    assert kb_dir() == Path("docs/kb")  # config.toml overrides the default
    monkeypatch.setenv("STEADYSTATE_KB", "elsewhere/kb")
    assert kb_dir() == Path("elsewhere/kb")  # env overrides config
