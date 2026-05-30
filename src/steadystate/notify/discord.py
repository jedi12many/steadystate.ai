"""Discord surface -- outbound v1.

Posts one rich embed per Alert to a Discord channel webhook. Outbound only; the webhook
URL comes from the constructor or the DISCORD_WEBHOOK_URL env var. Stdlib urllib, no new
dependency.

Like a Teams incoming webhook (and unlike a Slack bot token), a Discord channel-webhook URL
is itself the secret, so we send no Authorization header. A standard channel webhook is
send-only and can't carry interactive buttons -- approving from Discord needs an application
+ the inbound adapter (inbound/discord.py), not this surface.

Honest degrade: if no webhook is configured we say so once and do nothing, rather than
pretending we delivered anything.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import TYPE_CHECKING

from ..reason.alert import Alert
from ..reason.report import Report

if TYPE_CHECKING:
    from ..reconcile_state import ResolvedFinding

logger = logging.getLogger(__name__)

# Severity -> embed sidebar color (Discord wants a decimal RGB int). Red/yellow/green track
# the same urgency the other surfaces show.
_SEVERITY_COLOR = {
    "critical": 0x992D22,  # dark red
    "high": 0xED4245,  # red
    "medium": 0xFEE75C,  # yellow
    "low": 0x57F287,  # green
}
_DEFAULT_COLOR = 0x95A5A6  # grey


def format_discord_message(alert: Alert) -> dict:
    """Build the webhook payload for one Alert. Pure + testable (no network).

    Returns a Discord message wrapping a single embed (title + why-it-matters + fact fields).
    """
    fields: list[dict] = [
        {"name": "Severity", "value": alert.severity.value, "inline": True},
        {"name": "Tier", "value": alert.layer.value, "inline": True},
    ]
    if alert.drifts:  # source lives on the first drift's provenance, if we have one
        fields.append(
            {"name": "Source", "value": alert.drifts[0].provenance.source, "inline": True}
        )
    elif alert.findings:  # a standing-policy Alert has no drift; source is on the finding
        fields.append(
            {"name": "Source", "value": alert.findings[0].provenance.source, "inline": True}
        )
    if alert.flagged_by is not None:  # omit the field entirely when nothing flagged it
        fields.append({"name": "Flagged by", "value": alert.flagged_by, "inline": True})
    if alert.references:  # omit the field entirely when nothing mapped
        # Config-exposure -> technique mapping, not behavioral detection.
        chips = ", ".join(f"{ref.framework} {ref.id}" for ref in alert.references)
        fields.append({"name": "References", "value": chips, "inline": False})
    if alert.recommended_action is not None:  # omit when there's no next step
        fields.append({"name": "Next", "value": alert.recommended_action, "inline": False})

    embed = {
        "title": f"{alert.severity.value.upper()}: {alert.title}"[:256],  # Discord caps titles
        "description": alert.why_it_matters[:4096],
        "color": _SEVERITY_COLOR.get(alert.severity.value, _DEFAULT_COLOR),
        "fields": fields,
    }
    return {"embeds": [embed]}


class DiscordSurface:
    """A Surface that POSTs each Alert as an embed to a Discord channel webhook."""

    name = "discord"

    def __init__(self, webhook_url: str | None = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL")
        self.timeout = timeout

    def emit(self, report: Report, resolved: Sequence[ResolvedFinding] | None = None) -> None:
        # Page only on Alerts -- the top tier. Events/signals stay on the console.
        # ``resolved`` is console-first in Phase 0; Discord ignores it for now.
        if not self.webhook_url:
            logger.warning(
                "Discord surface enabled but no webhook configured "
                "(set DISCORD_WEBHOOK_URL or pass webhook_url); skipping %d alert(s).",
                len(report.alerts),
            )
            return
        for alert in report.alerts:
            self._post(format_discord_message(alert))

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
            logger.warning("Discord delivery failed: %s", exc)
