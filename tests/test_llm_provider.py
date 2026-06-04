"""The OpenAI-compatible provider path + provider selection in reason/llm.py.

The endpoint is any /chat/completions service (OpenAI, Azure OpenAI, GitHub Models,
internal gateway); we mock urllib so nothing leaves the process.
"""

import json
import sys
import types
import urllib.error

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.llm import LLMAnalyst, _llm_enabled


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )


class _FakeResp:
    """Minimal stand-in for the urlopen context manager."""

    def __init__(self, payload: dict) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _set_openai_env(monkeypatch, base_url="https://models.example.test/v1", model="gpt-4o-mini"):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("STEADYSTATE_LLM_BASE_URL", base_url)
    monkeypatch.setenv("STEADYSTATE_LLM_API_KEY", "tok-xyz")
    monkeypatch.setenv("STEADYSTATE_LLM_MODEL", model)


def test_openai_compatible_path_is_llm_backed(monkeypatch):
    _set_openai_env(monkeypatch)
    captured: dict = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data)
        captured["auth"] = request.get_header("Authorization")
        return _FakeResp(
            {"choices": [{"message": {"content": "Bucket is public; restore the private ACL."}}]}
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    analysis = LLMAnalyst().analyze(_drift())

    assert analysis.llm_backed is True
    assert "restore the private ACL" in analysis.why_it_matters
    assert captured["url"] == "https://models.example.test/v1/chat/completions"
    assert captured["body"]["model"] == "gpt-4o-mini"
    assert captured["auth"] == "Bearer tok-xyz"


def test_anthropic_wins_when_both_configured(monkeypatch):
    # Both providers configured -> Anthropic is chosen (its key present); OpenAI untouched.
    _set_openai_env(monkeypatch)  # sets OpenAI env, clears ANTHROPIC
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    fake = types.ModuleType("anthropic")

    class _Block:
        type = "text"
        text = "From Claude."

    class _Msg:
        content = [_Block()]

    class _Anthropic:
        def __init__(self, *a, **k):
            self.messages = types.SimpleNamespace(create=lambda **kw: _Msg())

    fake.Anthropic = _Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    def boom(*a, **k):
        raise AssertionError("must not call the OpenAI path when an Anthropic key is present")

    monkeypatch.setattr("urllib.request.urlopen", boom)

    analysis = LLMAnalyst().analyze(_drift())
    assert analysis.llm_backed is True
    assert analysis.why_it_matters == "From Claude."


def test_forced_openai_without_config_degrades(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_BASE_URL", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_API_KEY", raising=False)
    monkeypatch.delenv("STEADYSTATE_LLM_MODEL", raising=False)
    monkeypatch.setenv("STEADYSTATE_LLM_PROVIDER", "openai")

    analysis = LLMAnalyst().analyze(_drift())
    assert analysis.llm_backed is False
    assert "modified" in analysis.why_it_matters  # honest summary from drift facts


def test_openai_unreachable_degrades_honestly(monkeypatch):
    _set_openai_env(monkeypatch)

    def boom(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)

    analysis = LLMAnalyst().analyze(_drift())
    assert analysis.llm_backed is False
    assert analysis.recommended_action is None
    assert "modified" in analysis.why_it_matters  # never crashes, never fabricates


# -- the live kill switch -------------------------------------------------------


def test_llm_enabled_parses_env(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_LLM_ENABLED", raising=False)
    assert _llm_enabled() is True  # default on
    for off in ("false", "0", "no", "off", "False", ""):
        monkeypatch.setenv("STEADYSTATE_LLM_ENABLED", off)
        assert _llm_enabled() is False
    monkeypatch.setenv("STEADYSTATE_LLM_ENABLED", "true")
    assert _llm_enabled() is True


def test_kill_switch_disables_provider_even_with_a_key():
    # An explicit key is present, yet the kill switch wins: no provider, honest degrade.
    assert LLMAnalyst(api_key="sk-test", enabled=False)._provider() == "none"


def test_kill_switch_via_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("STEADYSTATE_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("STEADYSTATE_LLM_ENABLED", "false")
    assert LLMAnalyst()._provider() == "none"
    monkeypatch.setenv("STEADYSTATE_LLM_ENABLED", "true")
    assert LLMAnalyst()._provider() == "anthropic"


def test_kill_switch_makes_no_call_and_records_no_spend():
    analyst = LLMAnalyst(api_key="sk-test", enabled=False)
    clusters = analyst.correlate([_drift(), _drift()])  # degrades to deterministic grouping
    assert all(not c.llm_backed for c in clusters)
    assert analyst.calls == []  # nothing attempted -> no spend rows


# -- per-caller model tiering ---------------------------------------------------


def test_cheap_caller_routes_to_the_cheap_model(monkeypatch):
    monkeypatch.delenv("STEADYSTATE_MODEL_CHAT_NL", raising=False)
    monkeypatch.delenv("STEADYSTATE_MODEL_CHEAP", raising=False)
    analyst = LLMAnalyst(model="claude-sonnet-4-6", api_key="sk-test")
    # chat-nl is intent routing -> cheap tier; analyze/decide/correlate keep the reasoning model.
    assert analyst._model_for_caller("chat-nl", "anthropic") == "claude-haiku-4-5"
    assert analyst._model_for_caller("decide", "anthropic") == "claude-sonnet-4-6"
    assert analyst._model_for_caller("correlate", "anthropic") == "claude-sonnet-4-6"


def test_per_caller_model_env_override_wins(monkeypatch):
    monkeypatch.setenv("STEADYSTATE_MODEL_CHAT_NL", "claude-opus-4-8")
    analyst = LLMAnalyst(model="claude-sonnet-4-6", api_key="sk-test")
    assert analyst._model_for_caller("chat-nl", "anthropic") == "claude-opus-4-8"


def test_tiering_is_anthropic_only(monkeypatch):
    _set_openai_env(monkeypatch, model="gpt-4o-mini")
    analyst = LLMAnalyst()
    # An OpenAI-compatible endpoint has a single configured model -- chat-nl isn't re-tiered.
    assert analyst._model_for_caller("chat-nl", "openai") == "gpt-4o-mini"


def test_chat_nl_call_actually_sends_and_records_the_cheap_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("STEADYSTATE_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("STEADYSTATE_MODEL_CHAT_NL", raising=False)
    monkeypatch.delenv("STEADYSTATE_MODEL_CHEAP", raising=False)

    captured: dict = {}
    fake = types.ModuleType("anthropic")

    class _Block:
        type = "text"
        text = "{}"

    class _Msg:
        content = [_Block()]
        usage = types.SimpleNamespace(
            input_tokens=10,
            output_tokens=2,
            cache_creation_input_tokens=0,
            cache_read_input_tokens=0,
        )

    class _Anthropic:
        def __init__(self, *a, **k):
            self.messages = types.SimpleNamespace(create=self._create)

        def _create(self, **kw):
            captured["model"] = kw["model"]
            return _Msg()

    fake.Anthropic = _Anthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    analyst = LLMAnalyst(model="claude-sonnet-4-6")
    out = analyst._complete("sys", "user", "chat-nl")
    assert out == "{}"
    assert captured["model"] == "claude-haiku-4-5"  # the cheap tier was the model actually sent
    assert analyst.calls[-1].model == "claude-haiku-4-5"  # and recorded as such -- honest spend
