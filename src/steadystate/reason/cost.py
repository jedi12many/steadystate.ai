"""LLM spend accounting -- store raw token counts, price at read time.

We record one :class:`LlmCall` per model request (including failures and retries), with
the raw token counts and nothing else. Dollars are computed *at read time* from the price
table below, so history can be re-priced for free when a provider changes its rates -- we
never bake a dollar figure into a stored row. This mirrors the approach proven in myconaid.

Cache tokens are first-class: a cache *read* costs ~10% of an input token, a cache *write*
~25% more, so they move the bill enough to track separately. Visibility only here -- no
budgets or enforcement (you cap spend after you can see it).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LlmCall:
    """One model request's raw usage -- the durable, re-priceable record.

    ``caller`` is the steadystate subsystem that made the call (e.g. "correlate"), so spend
    can be attributed. Failure rows carry ``succeeded=False`` and zeroed tokens, so a stuck
    retry loop is visible as a burst of failures, not hidden."""

    caller: str
    provider: str  # "anthropic" | "openai"
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0
    succeeded: bool = True


@dataclass(frozen=True)
class ModelPricing:
    label: str
    input_per_million: float
    output_per_million: float
    cache_creation_per_million: float
    cache_read_per_million: float


# Anthropic list prices, USD per million tokens, as of 2026-05. Cost is computed at read
# time from stored token counts, so re-pricing history is just editing this table.
_OPUS = ModelPricing("opus", 15.0, 75.0, 18.75, 1.50)
_SONNET = ModelPricing("sonnet", 3.0, 15.0, 3.75, 0.30)
_HAIKU = ModelPricing("haiku", 1.0, 5.0, 1.25, 0.10)
# Unknown / OpenAI-compatible models: assume a Sonnet-class rate rather than guess wildly.
_DEFAULT = ModelPricing("other", 3.0, 15.0, 3.75, 0.30)


def pricing_for(model: str) -> ModelPricing:
    """The price table for ``model``, matched by family substring (Anthropic), else default."""
    m = model.lower()
    if "opus" in m:
        return _OPUS
    if "sonnet" in m:
        return _SONNET
    if "haiku" in m:
        return _HAIKU
    return _DEFAULT


def cost_usd(call: LlmCall) -> float:
    """Estimated USD for one call, priced now from its stored token counts."""
    p = pricing_for(call.model)
    return (
        call.input_tokens * p.input_per_million
        + call.output_tokens * p.output_per_million
        + call.cache_creation_tokens * p.cache_creation_per_million
        + call.cache_read_tokens * p.cache_read_per_million
    ) / 1_000_000


@dataclass(frozen=True)
class CallerSpend:
    """A per-caller rollup over some window -- what the cost report displays."""

    caller: str
    calls: int
    failures: int
    input_tokens: int
    output_tokens: int
    cache_creation_tokens: int
    cache_read_tokens: int
    cost_usd: float


def roll_up(calls: Iterable[LlmCall]) -> list[CallerSpend]:
    """Group calls by caller, summing tokens + cost and counting failures. Sorted by
    spend descending, so the loudest caller is first -- the one to look at."""
    acc: dict[str, dict] = {}
    for call in calls:
        row = acc.setdefault(
            call.caller,
            {"calls": 0, "failures": 0, "in": 0, "out": 0, "cc": 0, "cr": 0, "usd": 0.0},
        )
        row["calls"] += 1
        if not call.succeeded:
            row["failures"] += 1
        row["in"] += call.input_tokens
        row["out"] += call.output_tokens
        row["cc"] += call.cache_creation_tokens
        row["cr"] += call.cache_read_tokens
        row["usd"] += cost_usd(call)
    out = [
        CallerSpend(
            caller=caller,
            calls=row["calls"],
            failures=row["failures"],
            input_tokens=row["in"],
            output_tokens=row["out"],
            cache_creation_tokens=row["cc"],
            cache_read_tokens=row["cr"],
            cost_usd=row["usd"],
        )
        for caller, row in acc.items()
    ]
    out.sort(key=lambda s: s.cost_usd, reverse=True)
    return out


def scan_cost_line(calls: Iterable[LlmCall]) -> str | None:
    """A one-line spend summary for a single scan, or None if no calls were made (so a
    ``--no-llm`` run stays silent). What the scan footer prints so a paid call never goes
    unseen: ``LLM: 3 call(s) - 13.2k tokens - ~$0.0420``."""
    calls = list(calls)
    if not calls:
        return None
    total = sum(cost_usd(c) for c in calls)
    tokens = sum(
        c.input_tokens + c.output_tokens + c.cache_creation_tokens + c.cache_read_tokens
        for c in calls
    )
    failures = sum(1 for c in calls if not c.succeeded)
    fail = f" ({failures} failed)" if failures else ""
    return f"LLM: {len(calls)} call(s){fail} - {tokens / 1000:.1f}k tokens - ~${total:.4f}"


@dataclass(frozen=True)
class PeriodSpend:
    """Spend bucketed into one time period (a day or an ISO week) -- a row of the trend."""

    period: str  # "2026-05-31" (day) or "2026-W22" (ISO week)
    calls: int
    failures: int
    total_tokens: int
    cost_usd: float


def _period_key(at: str, period: str) -> str:
    """The bucket key for a stored ``at`` timestamp: its date (day) or ISO year-week (week)."""
    moment = datetime.fromisoformat(at)
    if period == "week":
        iso = moment.isocalendar()
        return f"{iso[0]}-W{iso[1]:02d}"
    return moment.date().isoformat()


def roll_up_by_period(
    timed_calls: Iterable[tuple[str, LlmCall]], period: str = "day"
) -> list[PeriodSpend]:
    """Bucket ``(at, call)`` pairs into day/week periods, summing cost + tokens (priced now).
    Oldest first, so spend reads as a trend down the column. Complements ``roll_up`` (by caller)
    with a 'how is this growing over time' view; Prometheus/Grafana is the richer time series."""
    acc: dict[str, dict] = {}
    for at, call in timed_calls:
        row = acc.setdefault(
            _period_key(at, period), {"calls": 0, "failures": 0, "tok": 0, "usd": 0.0}
        )
        row["calls"] += 1
        if not call.succeeded:
            row["failures"] += 1
        row["tok"] += (
            call.input_tokens
            + call.output_tokens
            + call.cache_creation_tokens
            + call.cache_read_tokens
        )
        row["usd"] += cost_usd(call)
    return [
        PeriodSpend(key, row["calls"], row["failures"], row["tok"], row["usd"])
        for key, row in sorted(acc.items())
    ]
