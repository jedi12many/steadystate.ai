"""Grafana surface tests -- pure-format assertions plus a network-mocked emit.

Mirrors test_slack.py / test_teams.py: format_* is exercised without any network
(time pinned), and the emit path is checked by monkeypatching urllib so no socket
is ever opened.
"""

import logging
from datetime import UTC, datetime

from steadystate.model import ChangeType, Drift, Provenance
from steadystate.notify.grafana import GrafanaSurface, format_grafana_annotation
from steadystate.reason.alert import Alert, Layer, Severity
from steadystate.reason.report import Report

_PINNED = datetime(2026, 5, 30, 12, 0, 0, tzinfo=UTC)


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


# --- format_grafana_annotation ----------------------------------------------


def test_format_shape_and_text():
    ann = format_grafana_annotation(_case(), now=_PINNED)
    assert set(ann) == {"time", "tags", "text"}
    expected = "Public S3 bucket — aws_s3_bucket.logs went from private to public-read."
    assert ann["text"] == expected


def test_format_time_is_ms_epoch():
    ann = format_grafana_annotation(_case(), now=_PINNED)
    assert ann["time"] == int(_PINNED.timestamp() * 1000)
    assert isinstance(ann["time"], int)


def test_format_time_defaults_to_created_at():
    case = _case(created_at=_PINNED)
    ann = format_grafana_annotation(case)  # now omitted -> use the Alert's created_at
    assert ann["time"] == int(_PINNED.timestamp() * 1000)


def test_format_tags_carry_steadystate_and_severity():
    ann = format_grafana_annotation(_case(severity=Severity.CRITICAL), now=_PINNED)
    assert "steadystate" in ann["tags"]
    assert "severity:critical" in ann["tags"]


def test_format_tags_include_source_from_drift():
    ann = format_grafana_annotation(_case(), now=_PINNED)
    assert "source:terraform" in ann["tags"]


def test_format_tags_include_flagged_by_when_set():
    ann = format_grafana_annotation(_case(flagged_by="security"), now=_PINNED)
    assert "flagged_by:security" in ann["tags"]


def test_format_tags_omit_flagged_by_when_none():
    ann = format_grafana_annotation(_case(flagged_by=None), now=_PINNED)
    assert not any(t.startswith("flagged_by:") for t in ann["tags"])


def test_format_payload_is_json_serializable():
    import json

    case = _case(severity=Severity.CRITICAL, layer=Layer.ALERT)
    ann = format_grafana_annotation(case, now=_PINNED)
    assert json.loads(json.dumps(ann)) == ann


# --- GrafanaSurface.emit (no network) ---------------------------------------


def test_emit_posts_once_per_alert(monkeypatch):
    surface = GrafanaSurface(base_url="http://grafana.test", token="tok")

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    surface.emit(Report(items=[_case(), _case(severity=Severity.CRITICAL)]))
    assert len(posted) == 2
    for ann in posted:
        assert "steadystate" in ann["tags"]


def test_emit_ignores_signals(monkeypatch):
    surface = GrafanaSurface(base_url="http://grafana.test", token="tok")

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    signal = _case(layer=Layer.SIGNAL, severity=Severity.LOW)
    surface.emit(Report(items=[_case(), signal]))
    assert len(posted) == 1  # only the ALERT-layer item pages


def test_emit_post_uses_bearer_token_and_annotations_url(monkeypatch):
    surface = GrafanaSurface(base_url="http://grafana.test/", token="secret-tok")

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
        seen["method"] = request.get_method()
        seen["data"] = request.data
        seen["content_type"] = request.headers.get("Content-type")
        seen["auth"] = request.headers.get("Authorization")
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    surface.emit(Report(items=[_case()]))
    assert seen["url"] == "http://grafana.test/api/annotations"
    assert seen["method"] == "POST"
    assert seen["content_type"] == "application/json"
    assert seen["auth"] == "Bearer secret-tok"
    assert isinstance(seen["data"], bytes) and seen["data"]


def test_no_url_degrades_honestly(monkeypatch, caplog):
    monkeypatch.delenv("GRAFANA_URL", raising=False)
    monkeypatch.setenv("GRAFANA_TOKEN", "tok")
    surface = GrafanaSurface()
    assert surface.base_url is None

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    with caplog.at_level(logging.WARNING, logger="steadystate.notify.grafana"):
        surface.emit(Report(items=[_case(), _case()]))

    assert posted == []  # nothing sent, no network touched
    assert len(caplog.records) == 1
    assert "grafana" in caplog.text.lower()


def test_no_token_degrades_honestly(monkeypatch, caplog):
    monkeypatch.setenv("GRAFANA_URL", "http://grafana.test")
    monkeypatch.delenv("GRAFANA_TOKEN", raising=False)
    surface = GrafanaSurface()
    assert surface.token is None

    posted: list[dict] = []
    monkeypatch.setattr(surface, "_post", lambda payload: posted.append(payload))

    with caplog.at_level(logging.WARNING, logger="steadystate.notify.grafana"):
        surface.emit(Report(items=[_case()]))

    assert posted == []  # missing token alone is enough to degrade
    assert len(caplog.records) == 1


def test_constructor_args_override_missing_env(monkeypatch):
    monkeypatch.delenv("GRAFANA_URL", raising=False)
    monkeypatch.delenv("GRAFANA_TOKEN", raising=False)
    surface = GrafanaSurface(base_url="http://grafana.test", token="tok")
    assert surface.base_url == "http://grafana.test"
    assert surface.token == "tok"
