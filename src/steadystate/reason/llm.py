"""Honest LLM analysis.

If no API key is configured, we degrade *honestly*: a clearly-deterministic
summary that says reasoning was unavailable, never fabricated risk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..model import Drift

_DEFAULT_MODEL = os.environ.get("STEADYSTATE_MODEL", "claude-sonnet-4-5")


@dataclass
class Analysis:
    why_it_matters: str
    recommended_action: str | None
    llm_backed: bool


class LLMAnalyst:
    """Wraps Claude to explain why a drift matters. Degrades honestly without a key."""

    def __init__(self, model: str = _DEFAULT_MODEL, api_key: str | None = None) -> None:
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    def analyze(self, drift: Drift) -> Analysis:
        if not self.api_key:
            return Analysis(
                why_it_matters=(
                    f"{drift.summary()}: declared and observed state diverge. "
                    "(Set ANTHROPIC_API_KEY for AI reasoning on why this matters.)"
                ),
                recommended_action=None,
                llm_backed=False,
            )
        try:
            return self._analyze_with_claude(drift)
        except ImportError:
            return Analysis(
                why_it_matters=(
                    f"{drift.summary()}: declared and observed state diverge. "
                    "(Install the 'llm' extra for AI reasoning: pip install steadystate[llm])"
                ),
                recommended_action=None,
                llm_backed=False,
            )

    def _analyze_with_claude(self, drift: Drift) -> Analysis:
        from anthropic import Anthropic

        client = Anthropic(api_key=self.api_key)
        prompt = (
            "You are steadystate.ai's drift analyst. A resource has drifted from its "
            "declared state. In 1-2 plain sentences, explain why an operator should care, "
            "then suggest one concrete next step. Be honest about uncertainty; never invent "
            "risk the data does not support.\n\n"
            f"Drift:\n{drift.to_json()}"
        )
        message = client.messages.create(
            model=self.model,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        ).strip()
        return Analysis(why_it_matters=text, recommended_action=None, llm_backed=True)
