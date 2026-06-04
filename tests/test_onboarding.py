"""The setup wizard (`init`) + preflight (`doctor`) and the config catalog behind them.

The pure pieces -- assess / audit / .env read+write -- are tested directly; the two commands are
driven through Typer's CliRunner with scripted stdin so the interactive flow is exercised without
a real terminal. The load-bearing guarantees: a secret value never appears in `doctor` output, and
`init` merges into an existing .env without wiping untouched keys.
"""

from __future__ import annotations

import pytest

from steadystate import onboarding as ob
from steadystate.onboarding import Status, audit, read_env_file, write_env_file

typer_testing = pytest.importorskip("typer.testing")


# -- the catalog is internally consistent --------------------------------------


def test_every_setting_env_is_unique():
    envs = [s.env for cap in ob.capabilities() for s in cap.settings]
    assert len(envs) == len(set(envs)), "an env var is claimed by two settings"


def test_capability_keys_are_unique():
    keys = [cap.key for cap in ob.capabilities()]
    assert len(keys) == len(set(keys))


# -- assess / audit ------------------------------------------------------------


def test_assess_off_partial_ready_for_a_two_var_capability():
    grafana = next(c for c in ob.capabilities() if c.key == "grafana")
    assert grafana.assess({})[0] is Status.OFF
    partial, hint = grafana.assess({"GRAFANA_URL": "https://g"})
    assert partial is Status.PARTIAL and "GRAFANA_TOKEN" in hint
    ready, _ = grafana.assess({"GRAFANA_URL": "https://g", "GRAFANA_TOKEN": "t"})
    assert ready is Status.READY


def test_llm_accepts_either_anthropic_or_a_custom_endpoint(monkeypatch):
    monkeypatch.setattr(ob, "_anthropic_sdk_available", lambda: True)  # SDK present for this case
    llm = next(c for c in ob.capabilities() if c.key == "llm")
    assert llm.assess({"ANTHROPIC_API_KEY": "sk-ant"})[0] is Status.READY
    # The custom OpenAI-compatible endpoint is stdlib urllib -- never needs the SDK.
    monkeypatch.setattr(ob, "_anthropic_sdk_available", lambda: False)
    assert (
        llm.assess({"STEADYSTATE_LLM_BASE_URL": "u", "STEADYSTATE_LLM_MODEL": "m"})[0]
        is Status.READY
    )
    half, hint = llm.assess({"STEADYSTATE_LLM_BASE_URL": "u"})
    assert half is Status.PARTIAL and "STEADYSTATE_LLM_MODEL" in hint


def test_llm_anthropic_key_without_the_sdk_is_partial_not_a_false_ready(monkeypatch):
    # A key with no `anthropic` SDK installed degrades silently at runtime -- doctor must say so,
    # not report a green "ready" that lies (the bug that hid a non-working LLM in live testing).
    monkeypatch.setattr(ob, "_anthropic_sdk_available", lambda: False)
    llm = next(c for c in ob.capabilities() if c.key == "llm")
    status, hint = llm.assess({"ANTHROPIC_API_KEY": "sk-ant"})
    assert status is Status.PARTIAL and "anthropic" in hint


def test_llm_kill_switch_reads_off_even_with_a_key():
    llm = next(c for c in ob.capabilities() if c.key == "llm")
    status, detail = llm.assess({"ANTHROPIC_API_KEY": "sk-ant", "STEADYSTATE_LLM_ENABLED": "false"})
    assert status is Status.OFF and "STEADYSTATE_LLM_ENABLED" in detail


def test_audit_covers_every_capability_once():
    rows = audit({})
    assert {r.capability for r in rows} == set(ob.capabilities())


# -- .env read / write ---------------------------------------------------------


def test_read_env_file_parses_and_strips_quotes(tmp_path):
    f = tmp_path / ".env"
    f.write_text(
        '# a comment\nSLACK_WEBHOOK_URL=https://hooks\nGRAFANA_TOKEN="quoted"\n\nbad line\n'
    )
    assert read_env_file(f) == {"SLACK_WEBHOOK_URL": "https://hooks", "GRAFANA_TOKEN": "quoted"}


def test_read_env_file_missing_is_empty(tmp_path):
    assert read_env_file(tmp_path / "nope.env") == {}


def test_write_env_file_merges_without_wiping_untouched_keys(tmp_path):
    f = tmp_path / ".env"
    write_env_file(f, {"SLACK_WEBHOOK_URL": "https://a", "KEEP_ME": "x"})
    merged = write_env_file(f, {"TEAMS_WEBHOOK_URL": "https://b"})
    assert merged["SLACK_WEBHOOK_URL"] == "https://a"  # the earlier key survived
    assert merged["KEEP_ME"] == "x"  # even one outside the catalog
    assert merged["TEAMS_WEBHOOK_URL"] == "https://b"
    assert read_env_file(f) == merged  # round-trips on disk


def test_write_env_file_drops_empty_values(tmp_path):
    f = tmp_path / ".env"
    write_env_file(f, {"SLACK_WEBHOOK_URL": "https://a", "TEAMS_WEBHOOK_URL": ""})
    assert "TEAMS_WEBHOOK_URL" not in read_env_file(f)


# -- doctor command ------------------------------------------------------------


def _run(args, **kw):
    from steadystate.cli import app

    return typer_testing.CliRunner().invoke(app, args, **kw)


def test_doctor_reports_capability_status_from_an_env_file(tmp_path):
    f = tmp_path / ".env"
    f.write_text("SLACK_WEBHOOK_URL=https://hooks\n")
    result = _run(["doctor", "--env-file", str(f)])
    assert result.exit_code == 0
    assert "Slack alerts" in result.stdout
    assert "ready" in result.stdout  # the configured one shows ready


def test_doctor_never_prints_a_secret_value(tmp_path):
    f = tmp_path / ".env"
    f.write_text("SLACK_WEBHOOK_URL=https://hooks/SUPER-SECRET-TOKEN\n")
    result = _run(["doctor", "--env-file", str(f)])
    assert "SUPER-SECRET-TOKEN" not in result.stdout  # only the *status*, never the value


# -- init wizard ---------------------------------------------------------------


def test_init_writes_only_the_configured_capabilities(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    # One confirm per capability (LLM is first, Slack second). Decline LLM; configure Slack (y +
    # url); decline the rest -- derived from the catalog so adding a capability doesn't break this.
    answers = "n\n" + "y\nhttps://hooks.slack.com/x\n" + "n\n" * (len(ob.capabilities()) - 2)
    result = _run(["init", "--env-file", str(env_file)], input=answers)
    assert result.exit_code == 0
    written = read_env_file(env_file)
    assert written.get("SLACK_WEBHOOK_URL") == "https://hooks.slack.com/x"
    assert "ANTHROPIC_API_KEY" not in written  # declined -> not written
    assert "TEAMS_WEBHOOK_URL" not in written


def test_init_writes_nothing_when_everything_is_declined(tmp_path):
    env_file = tmp_path / ".env"
    result = _run(["init", "--env-file", str(env_file)], input="n\n" * len(ob.capabilities()))
    assert result.exit_code == 0
    assert not env_file.exists()  # no file created when nothing was configured
    assert "no file written" in result.stdout
