import logging

from steadystate.notify.slack import SlackSurface, format_slack_message
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report


def _case(**overrides) -> Alert:
    base = {
        "title": "Public S3 bucket",
        "severity": Severity.HIGH,
        "drifts": [],
        "why_it_matters": "aws_s3_bucket.logs went from private to public-read.",
        "recommended_action": "Re-apply terraform to restore the private ACL.",
    }
    base.update(overrides)
    return Alert(**base)


def test_format_includes_title_severity_and_action():
    payload = format_slack_message(_case())
    text = payload["text"]
    assert "Public S3 bucket" in text
    assert "HIGH" in text
    assert "aws_s3_bucket.logs went from private to public-read." in text
    assert "Re-apply terraform to restore the private ACL." in text
    assert "deterministic" in text  # llm_backed defaults to False -> honest label


def test_format_marks_llm_backed():
    payload = format_slack_message(_case(llm_backed=True))
    assert "LLM" in payload["text"]
    assert "deterministic" not in payload["text"]


def test_format_omits_next_when_no_action():
    payload = format_slack_message(_case(recommended_action=None))
    assert "Next:" not in payload["text"]


def test_format_payload_is_json_serializable_dict():
    payload = format_slack_message(_case(severity=Severity.CRITICAL, layer=Layer.ALERT))
    assert isinstance(payload, dict)
    assert set(payload) == {"text"}


def test_no_webhook_degrades_honestly(monkeypatch, caplog):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    surface = SlackSurface()
    assert surface.webhook_url is None

    posted = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    with caplog.at_level(logging.WARNING, logger="steadystate.notify.slack"):
        surface.emit(Report(items=[_case(), _case()]))

    assert posted == []  # nothing sent, no network touched
    assert len(caplog.records) == 1  # exactly one clear line
    assert "webhook" in caplog.text.lower()


def test_constructor_arg_overrides_missing_env(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    surface = SlackSurface(webhook_url="https://hooks.slack.test/abc")
    assert surface.webhook_url == "https://hooks.slack.test/abc"
