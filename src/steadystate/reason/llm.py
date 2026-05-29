"""Honest LLM analysis.

The analyst is a thin, swappable seam: it asks an LLM why a drift matters and what
to do next, and degrades *honestly* when no model is configured -- a clearly
deterministic summary that says reasoning was unavailable, never fabricated risk.

Two providers, selected from the environment (no new dependency for either):

- Anthropic: set ANTHROPIC_API_KEY (uses the `anthropic` SDK from the [llm] extra).
- OpenAI-compatible: set STEADYSTATE_LLM_BASE_URL + STEADYSTATE_LLM_API_KEY +
  STEADYSTATE_LLM_MODEL. Works against any /chat/completions endpoint -- OpenAI,
  Azure OpenAI, GitHub Models, or an internal gateway -- over stdlib urllib.

When both are configured, Anthropic wins unless STEADYSTATE_LLM_PROVIDER forces one.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from ..model import Drift

_DEFAULT_MODEL = os.environ.get("STEADYSTATE_MODEL", "claude-sonnet-4-5")
_HTTP_TIMEOUT = float(os.environ.get("STEADYSTATE_LLM_TIMEOUT", "30"))

_INSTRUCTION = (
    "You are steadystate.ai's drift analyst. A resource has drifted from its declared "
    "state. In 1-2 plain sentences, explain why an operator should care, then suggest one "
    "concrete next step. Be honest about uncertainty; never invent risk the data does not support."
)

_NO_PROVIDER_HINT = (
    "Set ANTHROPIC_API_KEY, or configure STEADYSTATE_LLM_BASE_URL + STEADYSTATE_LLM_MODEL "
    "(+ STEADYSTATE_LLM_API_KEY), for AI reasoning on why this matters."
)
_LLM_EXTRA_HINT = "Install the 'llm' extra for AI reasoning: pip install steadystate[llm]"
_UNREACHABLE_HINT = (
    "AI reasoning is configured but the model call failed; showing the drift facts only."
)


def _drift_prompt(drift: Drift) -> str:
    return f"Drift:\n{drift.to_json()}"


@dataclass
class Analysis:
    why_it_matters: str
    recommended_action: str | None
    llm_backed: bool


class LLMAnalyst:
    """Explains why a drift matters via Anthropic or any OpenAI-compatible endpoint.
    Degrades honestly when nothing is configured."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        # Anthropic (back-compat): explicit api_key or ANTHROPIC_API_KEY; `model` is
        # the Anthropic model name.
        self.model = model or _DEFAULT_MODEL
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        # OpenAI-compatible provider (OpenAI / Azure OpenAI / GitHub Models / gateway).
        self.openai_base_url = os.environ.get("STEADYSTATE_LLM_BASE_URL") or os.environ.get(
            "OPENAI_BASE_URL"
        )
        self.openai_api_key = os.environ.get("STEADYSTATE_LLM_API_KEY") or os.environ.get(
            "OPENAI_API_KEY"
        )
        self.openai_model = os.environ.get("STEADYSTATE_LLM_MODEL")
        self.timeout = _HTTP_TIMEOUT

    # -- provider selection -------------------------------------------------

    def _openai_ready(self) -> bool:
        return bool(self.openai_base_url and self.openai_api_key and self.openai_model)

    def _provider(self) -> str:
        forced = (os.environ.get("STEADYSTATE_LLM_PROVIDER") or "").strip().lower()
        if forced == "anthropic":
            return "anthropic" if self.api_key else "none"
        if forced == "openai":
            return "openai" if self._openai_ready() else "none"
        # auto: Anthropic wins when its key is present, else OpenAI-compatible.
        if self.api_key:
            return "anthropic"
        if self._openai_ready():
            return "openai"
        return "none"

    # -- entry point --------------------------------------------------------

    def analyze(self, drift: Drift) -> Analysis:
        provider = self._provider()
        if provider == "anthropic":
            try:
                return self._analyze_with_claude(drift)
            except ImportError:
                # SDK missing; fall through to an OpenAI-compatible endpoint if set.
                if self._openai_ready():
                    return self._try_openai(drift)
                return self._degrade(drift, _LLM_EXTRA_HINT)
        if provider == "openai":
            return self._try_openai(drift)
        return self._degrade(drift, _NO_PROVIDER_HINT)

    def _degrade(self, drift: Drift, hint: str) -> Analysis:
        return Analysis(
            why_it_matters=f"{drift.summary()}: declared and observed state diverge. ({hint})",
            recommended_action=None,
            llm_backed=False,
        )

    # -- providers ----------------------------------------------------------

    def _analyze_with_claude(self, drift: Drift) -> Analysis:
        from anthropic import Anthropic

        client = Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=400,
            messages=[{"role": "user", "content": f"{_INSTRUCTION}\n\n{_drift_prompt(drift)}"}],
        )
        text = "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        ).strip()
        return Analysis(why_it_matters=text, recommended_action=None, llm_backed=True)

    def _try_openai(self, drift: Drift) -> Analysis:
        try:
            return self._analyze_with_openai(drift)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, KeyError, IndexError):
            return self._degrade(drift, _UNREACHABLE_HINT)

    def _analyze_with_openai(self, drift: Drift) -> Analysis:
        assert self.openai_base_url and self.openai_api_key and self.openai_model  # _openai_ready()
        url = self.openai_base_url.rstrip("/") + "/chat/completions"
        body = json.dumps(
            {
                "model": self.openai_model,
                "messages": [
                    {"role": "system", "content": _INSTRUCTION},
                    {"role": "user", "content": _drift_prompt(drift)},
                ],
                "max_tokens": 400,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.openai_api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read())
        text = payload["choices"][0]["message"]["content"].strip()
        return Analysis(why_it_matters=text, recommended_action=None, llm_backed=True)
