"""LLM spend accounting: pricing, the per-call store, and usage capture in the analyst."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.cost import LlmCall, cost_usd, pricing_for, roll_up
from steadystate.reason.llm import LLMAnalyst
from steadystate.state import StateStore

# -- pricing + cost -------------------------------------------------------------


def test_pricing_matches_model_family():
    assert pricing_for("claude-opus-4-8").label == "opus"
    assert pricing_for("claude-sonnet-4-5").label == "sonnet"
    assert pricing_for("claude-haiku-4-5").label == "haiku"
    assert pricing_for("gpt-4o").label == "other"  # unknown -> sonnet-class default


def test_cost_usd_prices_every_token_kind():
    # Haiku: input 1, output 5, cache_creation 1.25, cache_read 0.10 USD per million.
    call = LlmCall(
        caller="correlate",
        provider="anthropic",
        model="claude-haiku-4-5",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        cache_creation_tokens=1_000_000,
        cache_read_tokens=1_000_000,
    )
    assert cost_usd(call) == 1.0 + 5.0 + 1.25 + 0.10


def test_cache_read_is_far_cheaper_than_input():
    # The whole point of tracking cache tokens: a read is ~10% of an input token (Haiku).
    read = LlmCall("c", "anthropic", "claude-haiku-4-5", cache_read_tokens=1_000_000)
    inp = LlmCall("c", "anthropic", "claude-haiku-4-5", input_tokens=1_000_000)
    assert cost_usd(read) == 0.10
    assert cost_usd(inp) == 1.0


def test_failure_row_costs_nothing():
    call = LlmCall("c", "anthropic", "claude-sonnet-4-5", succeeded=False)
    assert cost_usd(call) == 0.0


def test_roll_up_groups_by_caller_counts_failures_and_sorts_by_spend():
    calls = [
        LlmCall(
            "correlate", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=500
        ),
        LlmCall("correlate", "anthropic", "claude-sonnet-4-5", succeeded=False),  # retry failure
        LlmCall("analyze", "anthropic", "claude-opus-4-8", input_tokens=1000, output_tokens=1000),
    ]
    rows = roll_up(calls)
    by = {r.caller: r for r in rows}
    assert by["correlate"].calls == 2
    assert by["correlate"].failures == 1
    # Opus is pricier than Sonnet, so the analyze row outspends correlate and sorts first.
    assert rows[0].caller == "analyze"


# -- the per-call store ---------------------------------------------------------


def _t(day: int) -> datetime:
    return datetime(2026, 1, day, 12, 0, 0, tzinfo=UTC)


def test_store_records_and_reads_back_within_window():
    store = StateStore()
    store.record_llm_call(
        LlmCall("correlate", "anthropic", "claude-sonnet-4-5", input_tokens=10), _t(1)
    )
    store.record_llm_call(
        LlmCall("correlate", "anthropic", "claude-sonnet-4-5", output_tokens=20), _t(2)
    )

    assert len(store.llm_calls_since(None)) == 2  # all of history
    recent = store.llm_calls_since(_t(2))  # windowed
    assert len(recent) == 1
    assert recent[0].output_tokens == 20 and recent[0].caller == "correlate"


# -- usage capture in the analyst ----------------------------------------------


def test_anthropic_usage_extracted_including_cache():
    class _Usage:
        input_tokens = 100
        output_tokens = 40
        cache_creation_input_tokens = 10
        cache_read_input_tokens = 5

    class _Message:
        usage = _Usage()

    assert LLMAnalyst._anthropic_usage(_Message()) == {
        "input": 100,
        "output": 40,
        "cache_creation": 10,
        "cache_read": 5,
    }


def test_openai_usage_splits_cached_tokens_out_of_input():
    payload = {
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 30,
            "prompt_tokens_details": {"cached_tokens": 20},
        }
    }
    assert LLMAnalyst._openai_usage(payload) == {
        "input": 80,  # 100 prompt - 20 cached
        "output": 30,
        "cache_creation": 0,
        "cache_read": 20,
    }


def test_record_appends_a_call():
    analyst = LLMAnalyst(model="claude-sonnet-4-5")
    analyst._record("correlate", "anthropic", {"input": 5, "output": 3}, succeeded=True)
    assert len(analyst.calls) == 1
    call = analyst.calls[0]
    assert call.caller == "correlate"
    assert call.model == "claude-sonnet-4-5"
    assert call.input_tokens == 5 and call.output_tokens == 3 and call.succeeded


def test_degraded_correlate_records_nothing(monkeypatch):
    for var in (
        "ANTHROPIC_API_KEY",
        "STEADYSTATE_LLM_BASE_URL",
        "STEADYSTATE_LLM_API_KEY",
        "STEADYSTATE_LLM_MODEL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    analyst = LLMAnalyst(api_key=None)
    drift = Drift(
        identity="x", kind="k", change_type=ChangeType.MODIFIED, provenance=Provenance(source="t")
    )
    analyst.correlate([drift])  # no provider -> deterministic degrade, no model call
    assert analyst.calls == []
