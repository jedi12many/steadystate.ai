"""_analyze_with_claude path in reason/llm.py -- otherwise never imported in CI
(the `anthropic` extra is not installed on the runner).

We inject a fake `anthropic` module so `from anthropic import Anthropic` resolves
to a stub whose messages.create returns a response in the exact shape llm.py
parses (content = list of blocks with .type / .text). No network, no real key.
"""

import sys
import types

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.llm import LLMAnalyst


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )


class _FakeBlock:
    # llm.py keeps only blocks whose .type == "text", joining their .text
    def __init__(self, text: str, type: str = "text") -> None:
        self.text = text
        self.type = type


class _FakeMessage:
    def __init__(self, blocks):
        self.content = blocks


def _install_fake_anthropic(monkeypatch, blocks, captured=None):
    """Inject a fake `anthropic` module exposing an Anthropic client.

    The client's messages.create returns _FakeMessage(blocks); call kwargs are
    recorded into `captured` so we can assert llm.py passes model + the prompt.
    """

    class _FakeMessages:
        def create(self, **kwargs):
            if captured is not None:
                captured.update(kwargs)
            return _FakeMessage(blocks)

    class _FakeAnthropic:
        def __init__(self, *args, **kwargs):
            self.messages = _FakeMessages()

    fake_mod = types.ModuleType("anthropic")
    fake_mod.Anthropic = _FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)


def test_analyze_with_claude_is_llm_backed(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
    captured: dict = {}
    _install_fake_anthropic(
        monkeypatch,
        [_FakeBlock("This bucket went public; lock the ACL back to private.")],
        captured=captured,
    )

    analysis = LLMAnalyst(model="claude-test").analyze(_drift())

    assert analysis.llm_backed is True
    # why_it_matters comes straight from the mocked text content
    assert "lock the ACL back to private" in analysis.why_it_matters
    # _analyze_with_claude hardcodes recommended_action=None today (honest)
    assert analysis.recommended_action is None
    # the analyst forwarded the configured model to the client
    assert captured.get("model") == "claude-test"


def test_analyze_with_claude_keeps_only_text_blocks(monkeypatch):
    # Non-text blocks are filtered out; only text content forms why_it_matters.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
    _install_fake_anthropic(
        monkeypatch,
        [
            _FakeBlock("", type="thinking"),
            _FakeBlock("Drift matters because access widened."),
        ],
    )

    analysis = LLMAnalyst().analyze(_drift())

    assert analysis.llm_backed is True
    assert analysis.why_it_matters == "Drift matters because access widened."


def test_degrades_honestly_without_key(monkeypatch):
    # No key -> deterministic, honest summary; never fabricated, never llm_backed.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    analysis = LLMAnalyst(api_key=None).analyze(_drift())

    assert analysis.llm_backed is False
    assert analysis.recommended_action is None
    assert "ANTHROPIC_API_KEY" in analysis.why_it_matters  # tells the operator how to enable it
    assert "modified" in analysis.why_it_matters  # built from drift.summary()
