"""Microsoft Teams surface -- outbound v1.

Posts one Adaptive Card per Case to a Teams incoming webhook. Outbound only for
now (no operator replies yet); the webhook URL comes from the constructor or the
TEAMS_WEBHOOK_URL env var. Uses stdlib urllib so we take on no new dependency.

Unlike a Slack bot token, a Teams incoming-webhook URL is itself the secret, so
we send no Authorization header -- the URL carries the auth.

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

# Case severity -> Adaptive Card TextBlock color (its named-color vocabulary).
_SEVERITY_COLOR = {
    "critical": "attention",
    "high": "attention",
    "medium": "warning",
    "low": "good",
}


def format_teams_message(case: Case) -> dict:
    """Build the webhook payload for one Case. Pure + testable (no network).

    Returns a Teams "message" wrapping a single Adaptive Card attachment.
    """
    color = _SEVERITY_COLOR.get(case.severity.value, "default")

    facts = [
        {"title": "Severity", "value": case.severity.value},
        {"title": "Layer", "value": case.layer.value},
    ]
    if case.drifts:  # source lives on the first drift's provenance, if we have one
        facts.append({"title": "Source", "value": case.drifts[0].provenance.source})
    if case.flagged_by is not None:  # omit the fact entirely when nothing flagged it
        facts.append({"title": "Flagged by", "value": case.flagged_by})

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": f"{case.severity.value.upper()}: {case.title}",
            "weight": "bolder",
            "wrap": True,
            "color": color,
        },
        {"type": "FactSet", "facts": facts},
        {"type": "TextBlock", "text": case.why_it_matters, "wrap": True},
    ]
    if case.recommended_action is not None:  # omit the block when there's no next step
        body.append({"type": "TextBlock", "text": case.recommended_action, "wrap": True})

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
            }
        ],
    }


class TeamsSurface:
    """A Surface that POSTs each Case as an Adaptive Card to a Teams webhook."""

    name = "teams"

    def __init__(self, webhook_url: str | None = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url or os.environ.get("TEAMS_WEBHOOK_URL")
        self.timeout = timeout

    def emit(self, cases: list[Case]) -> None:
        if not self.webhook_url:
            logger.warning(
                "Teams surface enabled but no webhook configured "
                "(set TEAMS_WEBHOOK_URL or pass webhook_url); skipping %d case(s).",
                len(cases),
            )
            return
        for case in cases:
            self._post(format_teams_message(case))

    def _post(self, payload: dict) -> None:
        assert self.webhook_url is not None  # emit() guards a configured webhook
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},  # URL is the secret; no auth header
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response.read()
        except (urllib.error.URLError, OSError) as exc:
            logger.warning("Teams delivery failed: %s", exc)
