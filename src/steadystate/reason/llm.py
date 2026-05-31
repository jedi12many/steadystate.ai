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

from .._http import safe_urlopen
from ..model import Drift
from .cost import LlmCall

_DEFAULT_MODEL = os.environ.get("STEADYSTATE_MODEL", "claude-sonnet-4-5")
_HTTP_TIMEOUT = float(os.environ.get("STEADYSTATE_LLM_TIMEOUT", "30"))


def _llm_enabled() -> bool:
    """The live kill switch. ``STEADYSTATE_LLM_ENABLED=false`` (or 0/no/off) disables every
    model call -- the analyst degrades honestly, exactly as if no provider were configured.
    Enabled by default; a single env flip cuts all LLM spend without touching keys."""
    value = os.environ.get("STEADYSTATE_LLM_ENABLED")
    if value is None:
        return True
    return value.strip().lower() not in ("0", "false", "no", "off", "")


_INSTRUCTION = (
    "You are steadystate.ai's drift analyst. A resource has drifted from its declared "
    "state. In 1-2 plain sentences, explain why an operator should care, then suggest one "
    "concrete next step. Be honest about uncertainty; never invent risk the data does not support. "
    "Recommend the infrastructure fix only; do NOT speculate about what steadystate itself can or "
    "cannot do, or whether a command is allowed -- steadystate determines that on its own."
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


@dataclass
class Cluster:
    """A group of drifts the correlator believes share one root cause."""

    drift_indexes: list[int]
    title: str
    why_it_matters: str
    recommended_action: str | None
    llm_backed: bool


_CORRELATE_INSTRUCTION = (
    "You are steadystate.ai's drift correlator. Below is a numbered list of infrastructure "
    "drifts from one scan. Group the drifts that share a SINGLE root cause (e.g. several "
    "symptoms of one node running out of storage). Most drifts are unrelated -- only group when "
    "there is a real common cause; otherwise a drift is its own group of one. For each group give "
    "a short title naming the cause, 1-2 plain sentences on why it matters, and one concrete next "
    "step (or null if you cannot act). Be honest; never invent a cause the data does not support. "
    "Recommend the infrastructure fix only; do NOT speculate about what steadystate itself can or "
    "cannot do, or whether a command is allowed -- steadystate determines that deterministically. "
    'Return ONLY JSON, no prose: {"groups": [{"drift_indexes": [int, ...], "title": str, '
    '"why_it_matters": str, "recommended_action": str or null}]} -- every index from 0 to N-1 '
    "must appear in exactly one group."
)


def _correlate_prompt(drifts: list[Drift]) -> str:
    blocks = [
        f"[{i}] {d.summary()} (source={d.provenance.source})\n{d.to_json()}"
        for i, d in enumerate(drifts)
    ]
    return "Drifts:\n\n" + "\n\n".join(blocks)


def _extract_json(text: str) -> dict | None:
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _parse_clusters(text: str, n: int) -> list[Cluster] | None:
    """Parse the correlator's JSON. Returns None (so the caller degrades) unless it
    cleanly covers every drift index 0..n-1 exactly once -- never drop or dup a drift."""
    data = _extract_json(text)
    groups = data.get("groups") if data else None
    if not isinstance(groups, list) or not groups:
        return None
    clusters: list[Cluster] = []
    seen: set[int] = set()
    for group in groups:
        if not isinstance(group, dict):
            return None
        idxs, title = group.get("drift_indexes"), group.get("title")
        why, action = group.get("why_it_matters"), group.get("recommended_action")
        if not isinstance(idxs, list) or not idxs:
            return None
        if not isinstance(title, str) or not isinstance(why, str):
            return None
        if action is not None and not isinstance(action, str):
            return None
        norm: list[int] = []
        for x in idxs:
            if not isinstance(x, int) or isinstance(x, bool) or x < 0 or x >= n or x in seen:
                return None
            seen.add(x)
            norm.append(x)
        clusters.append(
            Cluster(
                drift_indexes=norm,
                title=title,
                why_it_matters=why,
                recommended_action=action,
                llm_backed=True,
            )
        )
    if seen != set(range(n)):
        return None
    return clusters


class LLMAnalyst:
    """Explains why a drift matters via Anthropic or any OpenAI-compatible endpoint.
    Degrades honestly when nothing is configured."""

    def __init__(
        self, model: str | None = None, api_key: str | None = None, enabled: bool | None = None
    ) -> None:
        # The kill switch: explicit `enabled`, else the STEADYSTATE_LLM_ENABLED env var.
        # When off, _provider() reports "none" and every call degrades honestly.
        self.enabled = _llm_enabled() if enabled is None else enabled
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
        # Per-scan spend telemetry, accumulated in memory as calls are made; the CLI
        # persists it after the run (best-effort, never on the critical path).
        self.calls: list[LlmCall] = []

    # -- provider selection -------------------------------------------------

    def _model_for(self, provider: str) -> str:
        return self.model if provider == "anthropic" else (self.openai_model or "")

    def _record(self, caller: str, provider: str, usage: dict, *, succeeded: bool) -> None:
        """Append one call's usage to the in-memory log. Failures carry zeroed tokens."""
        self.calls.append(
            LlmCall(
                caller=caller,
                provider=provider,
                model=self._model_for(provider),
                input_tokens=usage.get("input", 0),
                output_tokens=usage.get("output", 0),
                cache_creation_tokens=usage.get("cache_creation", 0),
                cache_read_tokens=usage.get("cache_read", 0),
                succeeded=succeeded,
            )
        )

    @staticmethod
    def _anthropic_usage(message: object) -> dict:
        u = getattr(message, "usage", None)
        return {
            "input": getattr(u, "input_tokens", 0) or 0,
            "output": getattr(u, "output_tokens", 0) or 0,
            "cache_creation": getattr(u, "cache_creation_input_tokens", 0) or 0,
            "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0,
        }

    @staticmethod
    def _openai_usage(payload: dict) -> dict:
        u = payload.get("usage") or {}
        prompt = u.get("prompt_tokens", 0) or 0
        cached = (u.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        # OpenAI folds cached tokens into prompt_tokens; split them out so cache reads
        # price at the cheaper rate instead of being counted as full-price input.
        return {
            "input": max(prompt - cached, 0),
            "output": u.get("completion_tokens", 0) or 0,
            "cache_creation": 0,  # OpenAI has no separate cache-write line
            "cache_read": cached,
        }

    def _openai_ready(self) -> bool:
        return bool(self.openai_base_url and self.openai_api_key and self.openai_model)

    def _provider(self) -> str:
        if not self.enabled:  # kill switch -> behave exactly as if no provider were configured
            return "none"
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
        self._record("analyze", "anthropic", self._anthropic_usage(message), succeeded=True)
        text = "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        ).strip()
        return Analysis(why_it_matters=text, recommended_action=None, llm_backed=True)

    def _try_openai(self, drift: Drift) -> Analysis:
        try:
            return self._analyze_with_openai(drift)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError, KeyError, IndexError):
            self._record("analyze", "openai", {}, succeeded=False)
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
        with safe_urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read())
        self._record("analyze", "openai", self._openai_usage(payload), succeeded=True)
        text = payload["choices"][0]["message"]["content"].strip()
        return Analysis(why_it_matters=text, recommended_action=None, llm_backed=True)

    # -- correlation --------------------------------------------------------

    def correlate(self, drifts: list[Drift]) -> list[Cluster]:
        """Group drifts by root cause via the LLM. Without a provider -- or on any
        failure / malformed reply -- degrades honestly to deterministic grouping by
        shared attribute (see reason/correlate.py), never one-per-drift noise."""
        if not drifts:
            return []
        text = self._complete(_CORRELATE_INSTRUCTION, _correlate_prompt(drifts), caller="correlate")
        clusters = _parse_clusters(text, len(drifts)) if text is not None else None
        return clusters if clusters is not None else self._uncorrelated(drifts)

    def _uncorrelated(self, drifts: list[Drift]) -> list[Cluster]:
        # Honest degrade: deterministic shared-attribute grouping, not singleton noise.
        from .correlate import correlate as deterministic_correlate

        return deterministic_correlate(drifts)

    def _complete(self, system: str, user: str, caller: str) -> str | None:
        """Raw model text from the configured provider, or None if unavailable/failed."""
        provider = self._provider()
        if provider == "none":
            return None
        try:
            if provider == "anthropic":
                return self._complete_anthropic(system, user, caller)
            return self._complete_openai(system, user, caller)
        except ImportError:
            # anthropic SDK missing (no call made; not a spend event); fall through to an
            # OpenAI-compatible endpoint if set.
            if provider == "anthropic" and self._openai_ready():
                try:
                    return self._complete_openai(system, user, caller)
                except Exception:
                    self._record(caller, "openai", {}, succeeded=False)
                    return None
            return None
        except Exception:
            # any model/network/parse failure -> caller degrades honestly; never crash a scan.
            # Record a failure row so a stuck retry loop is visible in the spend report.
            self._record(caller, provider, {}, succeeded=False)
            return None

    def _complete_anthropic(self, system: str, user: str, caller: str) -> str:
        from anthropic import Anthropic

        client = Anthropic(api_key=self.api_key)
        message = client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        self._record(caller, "anthropic", self._anthropic_usage(message), succeeded=True)
        return "".join(
            block.text for block in message.content if getattr(block, "type", None) == "text"
        ).strip()

    def _complete_openai(self, system: str, user: str, caller: str) -> str:
        assert self.openai_base_url and self.openai_api_key and self.openai_model
        url = self.openai_base_url.rstrip("/") + "/chat/completions"
        body = json.dumps(
            {
                "model": self.openai_model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "max_tokens": 1024,
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
        with safe_urlopen(request, timeout=self.timeout) as response:
            payload = json.loads(response.read())
        self._record(caller, "openai", self._openai_usage(payload), succeeded=True)
        return payload["choices"][0]["message"]["content"].strip()
