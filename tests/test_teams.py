"""Teams surface tests -- pure-format assertions plus a network-mocked emit.

Mirrors test_slack.py: format_* is exercised without any network, and the emit
path is checked by monkeypatching urllib so no socket is ever opened.
"""

import logging

from steadystate.domains.base import Reference
from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.teams import TeamsSurface, format_teams_message
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report


def _drift() -> Drift:
    # A real Drift so case.drifts[0].provenance.source has a value to surface.
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


# --- structural walkers over the Adaptive Card (order-independent) -----------


def _card(payload: dict) -> dict:
    """The single AdaptiveCard content out of the message/attachments envelope."""
    attachments = payload["attachments"]
    assert len(attachments) == 1
    attachment = attachments[0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    return attachment["content"]


def _facts(card: dict) -> dict[str, str]:
    """All FactSet facts in the card body, flattened to title -> value."""
    out: dict[str, str] = {}
    for block in card["body"]:
        if block.get("type") == "FactSet":
            for fact in block["facts"]:
                out[fact["title"]] = fact["value"]
    return out


def _textblock_colors(card: dict) -> list[str]:
    """Every explicit color on a TextBlock (the title carries the severity color)."""
    return [
        block["color"]
        for block in card["body"]
        if block.get("type") == "TextBlock" and "color" in block
    ]


def _card_text(card: dict) -> str:
    """Concatenated text of every TextBlock -- for substring assertions."""
    return "\n".join(
        block.get("text", "") for block in card["body"] if block.get("type") == "TextBlock"
    )


# --- format_teams_message ---------------------------------------------------


def test_format_returns_message_attachment_envelope():
    payload = format_teams_message(_case())
    assert payload["type"] == "message"
    assert isinstance(payload["attachments"], list)
    card = _card(payload)
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.4"
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"


def test_format_card_carries_title_and_severity_and_reasoning():
    case = _case()
    card = _card(format_teams_message(case))

    # Title appears in the body (the bold title TextBlock combines severity + title).
    assert case.title in _card_text(card)

    facts = _facts(card)
    assert facts["Severity"] == case.severity.value  # enum .value per contract
    assert facts["Tier"] == case.layer.value
    assert facts["Source"] == "terraform"  # drifts[0].provenance.source

    assert case.why_it_matters in _card_text(card)


def test_format_includes_recommended_action_when_present():
    card = _card(format_teams_message(_case()))
    assert "Re-apply terraform to restore the private ACL." in _card_text(card)


def test_format_omits_recommended_action_when_none():
    card = _card(format_teams_message(_case(recommended_action=None)))
    assert "Re-apply terraform to restore the private ACL." not in _card_text(card)


def test_format_omits_flagged_by_fact_when_none():
    card = _card(format_teams_message(_case(flagged_by=None)))
    assert "Flagged by" not in _facts(card)


def test_format_includes_flagged_by_fact_when_set():
    card = _card(format_teams_message(_case(flagged_by="security")))
    assert _facts(card)["Flagged by"] == "security"


def test_format_omits_references_fact_when_absent():
    card = _card(format_teams_message(_case()))  # references defaults to []
    assert "References" not in _facts(card)


def test_resource_fact_shows_which_resource_drifted():
    assert _facts(_card(format_teams_message(_case())))["Resource"] == "aws_s3_bucket.logs"


def test_environment_fact_when_labeled():
    facts = _facts(_card(format_teams_message(_case(environment="staging"))))
    assert facts["Environment"] == "staging"


def test_no_environment_fact_by_default():
    assert "Environment" not in _facts(_card(format_teams_message(_case())))


def test_format_includes_references_fact_when_present():
    refs = [
        Reference(framework="MITRE", id="T1530"),
        Reference(framework="MITRE", id="T1190"),
    ]
    card = _card(format_teams_message(_case(references=refs)))
    value = _facts(card)["References"]
    assert "MITRE T1530" in value
    assert "MITRE T1190" in value


def test_severity_color_map():
    # CRITICAL/HIGH -> attention, MEDIUM -> warning, LOW -> good.
    expected = {
        Severity.CRITICAL: "attention",
        Severity.HIGH: "attention",
        Severity.MEDIUM: "warning",
        Severity.LOW: "good",
    }
    all_colors = set(expected.values())
    for severity, color in expected.items():
        card = _card(format_teams_message(_case(severity=severity)))
        colors = _textblock_colors(card)
        assert color in colors  # the title TextBlock is colored by severity
        # no contradicting severity color leaks in
        assert not (all_colors - {color}) & set(colors)


def test_format_payload_is_json_serializable():
    import json

    payload = format_teams_message(_case(severity=Severity.CRITICAL, layer=Layer.ALERT))
    # Round-trips cleanly -- no enums or datetimes leaked into the payload.
    assert json.loads(json.dumps(payload)) == payload


# --- TeamsSurface.emit (no network) -----------------------------------------


def test_emit_posts_once_per_case(monkeypatch):
    surface = TeamsSurface(webhook_url="https://outlook.office.test/webhook/abc")

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    surface.emit(Report(items=[_case(), _case(severity=Severity.CRITICAL)]))
    assert len(posted) == 2
    for payload in posted:
        assert payload["type"] == "message"


def test_emit_post_uses_urllib_with_configured_url(monkeypatch):
    # Drive the real _post but stub urlopen so nothing hits the network.
    surface = TeamsSurface(webhook_url="https://outlook.office.test/webhook/abc")

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
        seen["data"] = request.data
        seen["content_type"] = request.headers.get("Content-type")
        seen["has_auth"] = request.has_header("Authorization")
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    surface.emit(Report(items=[_case()]))
    assert seen["url"] == "https://outlook.office.test/webhook/abc"
    assert seen["content_type"] == "application/json"
    assert seen["has_auth"] is False  # the webhook URL is itself the secret
    assert isinstance(seen["data"], bytes) and seen["data"]  # JSON body present


def test_no_webhook_is_a_noop(monkeypatch, caplog):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    surface = TeamsSurface()
    assert surface.webhook_url is None

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    with caplog.at_level(logging.WARNING, logger="steadystate.notify.teams"):
        surface.emit(Report(items=[_case(), _case()]))

    assert posted == []  # nothing sent, no network touched
    assert len(caplog.records) == 1  # one honest line, no crash
    assert "webhook" in caplog.text.lower()


def test_constructor_arg_overrides_missing_env(monkeypatch):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    surface = TeamsSurface(webhook_url="https://outlook.office.test/webhook/xyz")
    assert surface.webhook_url == "https://outlook.office.test/webhook/xyz"
