"""Slack surface -- outbound v1.

Posts a compact message per Case to a Slack incoming webhook. Outbound only for
now (no operator replies yet); the webhook URL comes from the constructor or the
SLACK_WEBHOOK_URL env var. Uses stdlib urllib so we take on no new dependency.

Honest degrade: if no webhook is configured we say so once and do nothing, rather
than pretending we delivered anything.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

from ..reason.case import Case

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "low": ":white_circle:",
    "medium": ":large_yellow_circle:",
    "high": ":red_circle:",
    "critical": ":rotating_light:",
}


def format_slack_message(case: Case) -> dict:
    """Build the webhook payload for one Case. Pure + testable (no network)."""
    emoji = _SEVERITY_EMOJI.get(case.severity.value, ":white_circle:")
    backed = "LLM" if case.llm_backed else "deterministic"
    header = f"{emoji} *{case.title}*  ({case.severity.value.upper()} | {backed})"
    lines = [header, case.why_it_matters]
    if case.recommended_action:
        lines.append(f"*Next:* {case.recommended_action}")
    text = "\n\n".join(lines)
    return {"text": text}


class SlackSurface:
    """A Surface that POSTs each Case to a Slack incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str | None = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.timeout = timeout

    def emit(self, cases: list[Case]) -> None:
        if not self.webhook_url:
            logger.warning(
                "Slack surface enabled but no webhook configured "
                "(set SLACK_WEBHOOK_URL or pass webhook_url); skipping %d case(s).",
                len(cases),
            )
            return
        for case in cases:
            self._post(format_slack_message(case))

    def _post(self, payload: dict) -> None:
        assert self.webhook_url is not None  # emit() guards a configured webhook
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Slack delivery failed: %s", exc)
