"""Discord surface tests -- pure-format assertions plus a network-mocked emit.

Mirrors test_teams.py: format_discord_message is exercised without any network, and the
emit path is checked by monkeypatching urllib so no socket is ever opened.
"""

import json
import logging

from steadystate.domains.base import Reference
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.discord import DiscordSurface, format_discord_message
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report


def _drift() -> Drift:
    return Drift(
        identity="aws_s3_bucket.logs",
        kind="aws_s3_bucket",
        change_type=ChangeType.MODIFIED,
        provenance=Provenance(source="terraform", address="aws_s3_bucket.logs"),
        declared={"acl": "private"},
        observed={"acl": "public-read"},
    )


def _case(**overrides) -> Alert:
    base = {
        "title": "Public S3 bucket",
        "severity": Severity.HIGH,
        "drifts": [_drift()],
        "why_it_matters": "aws_s3_bucket.logs went from private to public-read.",
        "recommended_action": "Re-apply terraform to restore the private ACL.",
    }
    base.update(overrides)
    return Alert(**base)


def _embed(payload: dict) -> dict:
    embeds = payload["embeds"]
    assert len(embeds) == 1
    return embeds[0]


def _fields(embed: dict) -> dict[str, str]:
    return {f["name"]: f["value"] for f in embed["fields"]}


# --- format_discord_message --------------------------------------------------


def test_format_returns_single_embed():
    embed = _embed(format_discord_message(_case()))
    assert _case().title in embed["title"]
    assert embed["title"].startswith("HIGH:")  # severity prefix
    assert embed["description"] == _case().why_it_matters


def test_format_carries_core_facts():
    fields = _fields(_embed(format_discord_message(_case())))
    assert fields["Severity"] == "high"
    assert fields["Tier"] == _case().layer.value
    assert fields["Source"] == "terraform"  # drifts[0].provenance.source


def test_format_includes_recommended_action_when_present():
    fields = _fields(_embed(format_discord_message(_case())))
    assert fields["Next"] == "Re-apply terraform to restore the private ACL."


def test_format_omits_next_when_action_none():
    assert "Next" not in _fields(_embed(format_discord_message(_case(recommended_action=None))))


def test_format_omits_flagged_by_when_none():
    assert "Flagged by" not in _fields(_embed(format_discord_message(_case(flagged_by=None))))


def test_format_includes_flagged_by_when_set():
    fields = _fields(_embed(format_discord_message(_case(flagged_by="security-aws"))))
    assert fields["Flagged by"] == "security-aws"


def test_format_references_chips_when_present():
    refs = [Reference(framework="MITRE", id="T1530"), Reference(framework="MITRE", id="T1190")]
    value = _fields(_embed(format_discord_message(_case(references=refs))))["References"]
    assert "MITRE T1530" in value and "MITRE T1190" in value


def test_format_omits_references_when_absent():
    assert "References" not in _fields(_embed(format_discord_message(_case())))


def test_severity_color_map():
    expected = {
        Severity.CRITICAL: 0x992D22,
        Severity.HIGH: 0xED4245,
        Severity.MEDIUM: 0xFEE75C,
        Severity.LOW: 0x57F287,
    }
    for severity, color in expected.items():
        assert _embed(format_discord_message(_case(severity=severity)))["color"] == color


def test_format_payload_is_json_serializable():
    payload = format_discord_message(_case(severity=Severity.CRITICAL, layer=Layer.ALERT))
    assert json.loads(json.dumps(payload)) == payload


def test_format_truncates_an_overlong_title():
    embed = _embed(format_discord_message(_case(title="x" * 1000)))
    assert len(embed["title"]) <= 256  # Discord's embed-title cap


# --- DiscordSurface.emit (no network) ----------------------------------------


def test_emit_posts_once_per_case(monkeypatch):
    surface = DiscordSurface(webhook_url="https://discord.test/api/webhooks/abc")
    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))
    surface.emit(Report(items=[_case(), _case(severity=Severity.CRITICAL)]))
    assert len(posted) == 2
    for payload in posted:
        assert "embeds" in payload


def test_emit_post_uses_urllib_with_configured_url(monkeypatch):
    surface = DiscordSurface(webhook_url="https://discord.test/api/webhooks/abc")
    seen: dict[str, object] = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b""

    def _fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["content_type"] = request.headers.get("Content-type")
        seen["has_auth"] = request.has_header("Authorization")
        seen["data"] = request.data
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    surface.emit(Report(items=[_case()]))
    assert seen["url"] == "https://discord.test/api/webhooks/abc"
    assert seen["content_type"] == "application/json"
    assert seen["has_auth"] is False  # the webhook URL is itself the secret
    assert isinstance(seen["data"], bytes) and seen["data"]


def test_no_webhook_is_a_noop(monkeypatch, caplog):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    surface = DiscordSurface()
    assert surface.webhook_url is None
    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))
    with caplog.at_level(logging.WARNING, logger="steadystate.notify.discord"):
        surface.emit(Report(items=[_case(), _case()]))
    assert posted == []
    assert len(caplog.records) == 1
    assert "webhook" in caplog.text.lower()


def test_constructor_arg_overrides_missing_env(monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    surface = DiscordSurface(webhook_url="https://discord.test/api/webhooks/xyz")
    assert surface.webhook_url == "https://discord.test/api/webhooks/xyz"
