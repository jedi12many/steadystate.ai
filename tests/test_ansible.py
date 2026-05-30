"""Ansible source: turn `ansible-playbook --check` json-callback output into Drift."""

from __future__ import annotations

import pytest

from steadystate.model import ChangeType
from steadystate.sources.ansible import AnsibleSource, drifts_from_ansible_check

# A check run: web01's haproxy.cfg would change; everything else is already in desired state.
_RESULT = {
    "plays": [
        {
            "play": {"name": "Configure HAProxy"},
            "tasks": [
                {
                    "task": {"name": "Deploy haproxy.cfg"},
                    "hosts": {
                        "web01": {
                            "action": "template",
                            "changed": True,
                            "diff": [{"before": "old cfg\n", "after": "new cfg\n"}],
                            "invocation": {"module_name": "template"},
                        },
                        "web02": {"action": "template", "changed": False},
                    },
                },
                {
                    "task": {"name": "Ensure haproxy running"},
                    "hosts": {
                        "web01": {"action": "service", "changed": False},
                        "web02": {"action": "service", "changed": False},
                    },
                },
            ],
        }
    ],
    "stats": {"web01": {"changed": 1, "ok": 2}, "web02": {"changed": 0, "ok": 2}},
}


def test_changed_task_becomes_one_drift():
    drifts = drifts_from_ansible_check(_RESULT)
    assert len(drifts) == 1  # only web01's template task would change
    drift = drifts[0]
    assert drift.identity == "web01:Deploy haproxy.cfg"
    assert drift.kind == "template"
    assert drift.change_type is ChangeType.MODIFIED
    assert drift.provenance.source == "ansible"


def test_diff_maps_before_to_observed_after_to_declared():
    drift = drifts_from_ansible_check(_RESULT)[0]
    assert drift.observed == {"content": "old cfg\n"}  # before = host as it is
    assert drift.declared == {"content": "new cfg\n"}  # after = what the playbook wants


def test_unchanged_tasks_and_hosts_are_not_drift():
    # web02 (unchanged) and both service tasks contribute nothing.
    assert all(d.identity.startswith("web01:") for d in drifts_from_ansible_check(_RESULT))


def test_each_changed_host_is_its_own_drift():
    result = {
        "plays": [
            {
                "tasks": [
                    {
                        "task": {"name": "patch"},
                        "hosts": {
                            "a": {"action": "apt", "changed": True},
                            "b": {"action": "apt", "changed": True},
                        },
                    }
                ]
            }
        ]
    }
    ids = {d.identity for d in drifts_from_ansible_check(result)}
    assert ids == {"a:patch", "b:patch"}


def test_module_name_from_invocation_then_falls_back():
    from_invocation = {
        "plays": [
            {
                "tasks": [
                    {
                        "task": {"name": "t"},
                        "hosts": {"h": {"changed": True, "invocation": {"module_name": "copy"}}},
                    }
                ]
            }
        ]
    }
    assert drifts_from_ansible_check(from_invocation)[0].kind == "copy"

    bare = {"plays": [{"tasks": [{"task": {"name": "t"}, "hosts": {"h": {"changed": True}}}]}]}
    assert drifts_from_ansible_check(bare)[0].kind == "ansible_task"


def test_empty_or_missing_plays_yield_no_drift():
    assert drifts_from_ansible_check({}) == []
    assert drifts_from_ansible_check({"plays": []}) == []


def test_source_reads_a_captured_result():
    assert len(AnsibleSource(result=_RESULT).collect_drift()) == 1


def test_source_needs_result_or_playbook():
    with pytest.raises(ValueError):
        AnsibleSource().collect_drift()
