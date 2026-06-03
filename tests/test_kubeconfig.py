"""Discovering kubeconfigs that sit in the working dir (not on kubectl's default path), and
threading the chosen kubeconfig through to every kubectl call so a discovered target can actually
be probed. These pin the content-sniff detection, the targets it builds (carrying their kubeconfig
+ disambiguated names), the round-trip through the targets file, and that `--kubeconfig` reaches
both the live source's read and the probe's calls."""

from __future__ import annotations

from pathlib import Path

import steadystate.discover as disc
from steadystate.discover import cwd_kubeconfigs, kubeconfig_targets
from steadystate.probe.kubectl import KubectlProbe
from steadystate.sources.k8s import KubernetesLiveSource
from steadystate.targets import Target, load_targets, save_targets

_KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- cluster: {server: https://x}
  name: c1
contexts:
- context: {cluster: c1, user: u1}
  name: prod@c1
current-context: prod@c1
users:
- name: u1
"""


# -- detection (content-sniffed, not name-matched) ------------------------------


def test_cwd_kubeconfigs_finds_a_kubeconfig_by_content_not_name(tmp_path: Path):
    (tmp_path / "admin.conf").write_text(_KUBECONFIG)  # no .yaml extension -- still found
    (tmp_path / "notes.yaml").write_text("kind: Notes\nfoo: bar\n")  # yaml, but not a kubeconfig
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe\x00kind: Config")  # invalid utf-8 -> skipped
    found = [p.name for p in cwd_kubeconfigs(tmp_path)]
    assert found == ["admin.conf"]


def test_cwd_kubeconfigs_skips_an_oversized_file(tmp_path: Path):
    big = tmp_path / "huge.yaml"
    big.write_text("kind: Config\n" + "x" * (disc._KUBECONFIG_MAX_BYTES + 1))
    assert cwd_kubeconfigs(tmp_path) == []


# -- the targets it builds ------------------------------------------------------


def test_kubeconfig_targets_carry_their_kubeconfig(tmp_path: Path, monkeypatch):
    kc = tmp_path / "prod.kubeconfig"
    kc.write_text(_KUBECONFIG)
    monkeypatch.setattr(disc, "_contexts_in", lambda path: ["prod@c1"])
    [target] = kubeconfig_targets(tmp_path)
    assert target.source == "k8s-live" and target.context == "prod@c1"
    assert target.kubeconfig == str(kc) and target.name == "prod-c1"


def test_kubeconfig_targets_disambiguate_a_shared_context_name(tmp_path: Path, monkeypatch):
    (tmp_path / "a.kubeconfig").write_text(_KUBECONFIG)
    (tmp_path / "b.kubeconfig").write_text(_KUBECONFIG)
    monkeypatch.setattr(disc, "_contexts_in", lambda path: ["admin"])  # both files: same ctx name
    names = [t.name for t in kubeconfig_targets(tmp_path)]
    # the second isn't dropped -- it's a real second cluster; the file stem disambiguates.
    assert names[0] == "admin" and names[1] != "admin" and len(set(names)) == 2


def test_kubeconfig_survives_the_targets_file_round_trip(tmp_path: Path):
    target = Target(name="prod", source="k8s-live", context="prod@c1", kubeconfig="/tmp/kc")
    path = tmp_path / "targets.json"
    save_targets(path, {"prod": target})
    assert load_targets(path)["prod"].kubeconfig == "/tmp/kc"


# -- threading: --kubeconfig reaches every kubectl call -------------------------


def test_the_probe_adds_kubeconfig_to_its_kubectl_calls():
    probe = KubectlProbe()
    probe.use_context("prod@c1")
    probe.use_kubeconfig("/tmp/kc")
    argv = probe._kubectl("get", "pods")
    assert argv[:3] == ["kubectl", "get", "pods"]
    assert "--kubeconfig" in argv and argv[argv.index("--kubeconfig") + 1] == "/tmp/kc"
    assert "--context" in argv  # both flags ride together


def test_the_live_source_adds_kubeconfig_to_its_read(monkeypatch):
    captured: list[list[str]] = []

    def fake_run_tool(argv, **kwargs):
        captured.append(argv)
        return "[]"

    monkeypatch.setattr("steadystate.sources.k8s.run_tool", fake_run_tool)
    src = KubernetesLiveSource()
    src.use_context("prod@c1")
    src.use_kubeconfig("/tmp/kc")
    src._run_kubectl()
    [argv] = captured
    assert "--kubeconfig" in argv and argv[argv.index("--kubeconfig") + 1] == "/tmp/kc"


def test_no_kubeconfig_means_no_flag():
    probe = KubectlProbe()
    probe.use_context("prod@c1")
    assert "--kubeconfig" not in probe._kubectl("get", "pods")
