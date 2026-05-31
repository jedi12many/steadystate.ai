"""LLM spend accounting: pricing, the per-call store, and usage capture in the analyst."""

from __future__ import annotations

from datetime import UTC, datetime

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.reason.cost import (
    LlmCall,
    cost_usd,
    pricing_for,
    roll_up,
    roll_up_by_period,
    scan_cost_line,
)
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


# -- inline scan footer (scan_cost_line) ----------------------------------------


def test_scan_cost_line_summarizes_calls_and_is_none_when_empty():
    calls = [
        LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=12000, output_tokens=800),
        LlmCall(
            "correlate", "anthropic", "claude-sonnet-4-5", input_tokens=3000, output_tokens=200
        ),
    ]
    line = scan_cost_line(calls)
    assert line.startswith("LLM: 2 call(s)") and "16.0k tokens" in line and "$0.06" in line
    assert scan_cost_line([]) is None  # a --no-llm run stays silent


def test_scan_cost_line_flags_failures():
    calls = [
        LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100),
        LlmCall("analyze", "anthropic", "claude-sonnet-4-5", succeeded=False),
    ]
    assert "(1 failed)" in scan_cost_line(calls)


# -- spend over time (roll_up_by_period) ----------------------------------------


def test_roll_up_by_day_buckets_and_sorts_oldest_first():
    s = LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    timed = [
        ("2026-05-31T10:00:00+00:00", s),
        ("2026-05-31T18:00:00+00:00", s),
        ("2026-05-29T09:00:00+00:00", s),
    ]
    periods = roll_up_by_period(timed, "day")
    assert [p.period for p in periods] == ["2026-05-29", "2026-05-31"]  # sorted, oldest first
    assert periods[1].calls == 2  # both 05-31 calls bucketed together


def test_roll_up_by_week_uses_iso_year_week():
    s = LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    periods = roll_up_by_period([("2026-05-31T10:00:00+00:00", s)], "week")
    assert periods[0].period == "2026-W22" and periods[0].calls == 1


def test_roll_up_by_period_counts_failures():
    ok = LlmCall("c", "anthropic", "claude-sonnet-4-5", input_tokens=100, output_tokens=10)
    bad = LlmCall("c", "anthropic", "claude-sonnet-4-5", succeeded=False)
    periods = roll_up_by_period(
        [("2026-05-31T10:00:00+00:00", ok), ("2026-05-31T11:00:00+00:00", bad)], "day"
    )
    assert periods[0].calls == 2 and periods[0].failures == 1


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


def test_timed_llm_calls_pairs_each_call_with_its_timestamp():
    store = StateStore()
    store.record_llm_call(LlmCall("c", "anthropic", "claude-sonnet-4-5", input_tokens=10), _t(1))
    store.record_llm_call(LlmCall("c", "anthropic", "claude-sonnet-4-5", output_tokens=20), _t(2))
    timed = store.timed_llm_calls_since(None)
    assert len(timed) == 2
    at, call = timed[0]
    assert at.startswith("2026-01-01") and call.input_tokens == 10  # oldest first, paired with `at`
    # the day bucketing then sees two distinct days
    assert {p.period for p in roll_up_by_period(timed, "day")} == {"2026-01-01", "2026-01-02"}


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


# -- the CLI surfaces (cost --by, scan --cost footer) ---------------------------


def _runner():
    import pytest

    return pytest.importorskip("typer.testing").CliRunner()


def test_cli_cost_by_day(tmp_path):
    from steadystate.cli import app

    db = str(tmp_path / "s.db")
    with StateStore(db) as store:
        store.record_llm_call(
            LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=1000), _t(1)
        )
        store.record_llm_call(
            LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=2000), _t(2)
        )
    result = _runner().invoke(app, ["cost", "--by", "day", "--state", db])
    assert result.exit_code == 0
    assert (
        "by day" in result.stdout
        and "2026-01-01" in result.stdout
        and "2026-01-02" in result.stdout
    )


def test_cli_scan_prints_cost_footer_and_breakdown(tmp_path, monkeypatch):
    import json

    from steadystate.cli import app
    from steadystate.reason.report import Report

    report = Report(items=[])
    report.llm_calls = [
        LlmCall("analyze", "anthropic", "claude-sonnet-4-5", input_tokens=1000, output_tokens=100)
    ]
    monkeypatch.setattr("steadystate.cli.build_report", lambda *a, **k: report)
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": []}))

    # the one-line footer prints by default when calls were made
    out = _runner().invoke(app, ["scan", str(plan), "--stateless"]).stdout
    assert "LLM: 1 call(s)" in out
    # --cost adds the per-caller breakdown
    detailed = _runner().invoke(app, ["scan", str(plan), "--stateless", "--cost"]).stdout
    assert "LLM: 1 call(s)" in detailed and "analyze" in detailed
