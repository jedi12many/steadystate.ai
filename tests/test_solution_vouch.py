"""Drafted -> vouched (issue #253 phase 2): a solution authored LIVE (an agent over MCP at --author)
lands as a DRAFT (proposed) -- surfaced but NEVER offered as a runnable pending until a human
`vouch`es it. A file/committed solution (no `proposed` key) defaults vouched. The writer stamps the
flag, so an agent can't self-vouch by submitting `proposed=false` in the JSON. And `vouch` is a
write-tier MCP tool: an --author agent can draft, but only the write grant can vouch."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from steadystate.act.solution_remedy import record_solution_remediations
from steadystate.model import Provenance
from steadystate.probe.base import Symptom
from steadystate.probe.solutions import (
    add_solution,
    describe_solution,
    load_solutions,
    vouch_solution,
)
from steadystate.reason.alert import Severity
from steadystate.state import StateStore

_NOW = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
_RAW = {
    "name": "evicted-fix",
    "for": "Evicted",
    "solution": {
        "kind": "command",
        "run": "kubectl delete pods --field-selector=status.phase=Failed",
    },
    "impact": "low",
    "reversibility": "high",
    "author": "ops",
}


def _sym(category: str, title: str) -> Symptom:
    return Symptom(
        identity=f"default/{title}",
        kind="Pod",
        category=category,
        severity=Severity.MEDIUM,
        title=title,
        detail="d",
        provenance=Provenance(source="k8s"),
        evidence={},
    )


class _Alert:
    def __init__(self, *symptoms: Symptom) -> None:
        self.symptoms = list(symptoms)


class _Report:
    def __init__(self, *alerts: _Alert) -> None:
        self.alerts = list(alerts)


def _offered(path: str) -> list[str]:
    """The runnable pendings a scan would OFFER from the runbook at ``path`` (drafts excluded)."""
    report = _Report(_Alert(_sym("Evicted", "web Evicted")))
    with StateStore(":memory:") as store:
        record_solution_remediations(store, report, _NOW, solutions=load_solutions(path))
        return [p.drift_identity for p in store.all_pending()]


def test_a_file_solution_with_no_proposed_key_is_offered(tmp_path):
    # backward compat: a hand-edited / committed entry (no `proposed`) defaults vouched -> offered.
    p = str(tmp_path / "solutions.json")
    Path(p).write_text(json.dumps([_RAW]))  # written directly, no `proposed` key
    assert load_solutions(p)[0].proposed is False
    assert _offered(p) == ["evicted-fix (author: ops)"]


def test_an_agent_drafted_solution_is_not_offered_until_vouched(tmp_path):
    p = str(tmp_path / "solutions.json")
    sol, msg = add_solution(dict(_RAW), author="the-agent", path=p)  # verb path -> a DRAFT
    assert sol.proposed is True and "DRAFT" in msg
    assert _offered(p) == []  # surfaced, but NOT offered as runnable
    assert "DRAFT" in describe_solution(load_solutions(p)[0])
    ok, vmsg = vouch_solution("evicted-fix", actor="jeff", path=p)  # a human vouches
    assert ok and "vouched" in vmsg
    assert load_solutions(p)[0].proposed is False
    assert _offered(p) == ["evicted-fix (author: ops)"]  # now runnable


def test_the_writer_overrides_a_submitted_proposed_so_an_agent_cant_self_vouch(tmp_path):
    p = str(tmp_path / "solutions.json")
    sneaky = {**_RAW, "proposed": False}  # the agent claims its draft is already vouched
    sol, _msg = add_solution(
        sneaky, author="the-agent", path=p
    )  # the verb path stamps proposed=True
    assert sol.proposed is True  # the writer's channel wins, not the submitted value
    assert _offered(p) == []


def test_cli_authoring_vouches_immediately(tmp_path):
    # the CLI path passes proposed=False -- a human at the terminal vouches as they author.
    p = str(tmp_path / "solutions.json")
    sol, _msg = add_solution(dict(_RAW), author="jeff", path=p, proposed=False)
    assert sol.proposed is False
    assert _offered(p) == ["evicted-fix (author: ops)"]


def test_vouch_is_a_write_tier_mcp_tool_not_author():
    from steadystate.inbound.mcp import mcp_tools

    author_tools = {t["name"] for t in mcp_tools(write=False, author=True)}
    write_tools = {t["name"] for t in mcp_tools(write=True)}
    assert "add-solution" in author_tools  # an --author agent CAN draft a fix
    assert "vouch" not in author_tools  # ...but it can't vouch its own draft
    assert "vouch" in write_tools  # vouch needs the write grant (a human gate)
