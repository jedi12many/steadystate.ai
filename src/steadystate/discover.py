"""Environment discovery -- "what can `scan`/`probe` actually do *here*?"

Three different questions get three commands. `doctor` answers "what credentials/config are
set?"; `catalog`/`commands` show what this build *statically* offers. This is the third: given
the **current directory** and **this machine** -- which CLIs are installed, which backends are
reachable, which inputs are lying around -- can I run each `--source`/`--probe` right now, what's
missing, and what's the exact command?

Registry-driven: the sources/probes and the CLI each one needs are read live from the registries
(the required binary is the first real token of a declared ``observe`` command), so this never
drifts from what's installed. The pure assessment (``assess_source`` / ``assess_probe``) is split
from the I/O that gathers the facts (``probe_environment``) so the verdict logic is testable
without a real shell or filesystem.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from .probe import PROBE_CAPABILITIES, auto_prober_for
from .sources import CAPABILITIES
from .targets import Target

# A cheap, read-only "is the backend reachable?" probe per CLI: binary -> argv. Only CLIs whose
# check genuinely contacts the backend belong here -- `terraform version` / `helm version` are
# client-only and prove nothing about state/cluster reachability, so they're omitted (those just
# report "installed"). kubectl/docker reads do hit the cluster/daemon.
_REACHABILITY: dict[str, list[str]] = {
    "kubectl": ["kubectl", "cluster-info", "--request-timeout=3s"],
    "docker": ["docker", "info", "--format", "{{.ServerVersion}}"],
}

# observe commands that name no local CLI: HTTP API reads (`GET /api/...`) hit a remote API, not a
# binary on PATH, so they carry no tool requirement -- those sources read a captured snapshot.
_HTTP_VERBS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})

# Per-source input hints: a comma-separated glob that signals a live working dir, plus the example
# commands. Hand-maintained -- the registry knows *tools*, not what a valid *input* looks like.
_HINTS: dict[str, dict[str, str]] = {
    "terraform": {
        "globs": "*.tf",
        "live": "steadystate scan . --source terraform",
        "capture": "terraform show -json tfplan > plan.json"
        " && steadystate scan plan.json --source terraform",
    },
    "docker-compose": {
        "globs": "docker-compose.yml,docker-compose.yaml,compose.yml,compose.yaml",
        "live": "steadystate scan . --source docker-compose --probe docker",
        "capture": "steadystate scan compose-snapshot.json --source docker-compose",
    },
    "k8s": {
        # No live CLI path is wired into `--source k8s`; it consumes a {declared,observed} snapshot.
        "capture": "build {declared,observed} (helm get manifest | kubectl get -o json),"
        " then steadystate scan snapshot.json --source k8s --probe kubectl",
    },
    "helm": {
        "globs": "Chart.yaml",
        "capture": "helm list -o json > releases.json"
        " && steadystate scan releases.json --source helm",
    },
    "argocd": {
        "capture": "steadystate scan app.json --source argocd --probe argocd"
        "  (app.json = an Application JSON)",
    },
    "ansible": {
        "capture": "ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check --diff ... > play.json"
        " && steadystate scan play.json --source ansible",
    },
    "rancher": {
        "capture": "steadystate scan gitrepo.json --source rancher"
        "  (a captured Fleet GitRepo JSON)",
    },
}

_REACHABILITY_TIMEOUT = 5.0

# The one headline that means "scan would work here right now" -- a single constant so the exit
# signal (`scannable_now`) and the report can't drift on the literal.
_READY = "READY"


def required_bins(observe: tuple[str, ...]) -> list[str]:
    """The CLIs a capability needs = the first real token of each declared observe command, deduped
    in first-seen order. Leading ``VAR=value`` env assignments are skipped
    (``ANSIBLE_...=json ansible-playbook ...`` -> ``["ansible-playbook"]``); HTTP-verb reads
    (``GET /api/...``) name no local CLI and yield nothing. ``("kubectl get -o json",)`` ->
    ``["kubectl"]``; ``("docker compose ...",)`` -> ``["docker"]``. Pure."""
    seen: dict[str, None] = {}
    for cmd in observe:
        binary = ""
        for token in cmd.split():
            if "=" in token and not token.startswith("-"):
                continue  # leading env assignment, e.g. ANSIBLE_STDOUT_CALLBACK=json
            binary = token
            break
        if not binary or binary in _HTTP_VERBS:
            continue
        seen.setdefault(binary, None)
    return list(seen)


def snapshot_source(doc: object) -> str | None:
    """The source name whose captured-snapshot shape ``doc`` matches, or None. Cheap structural
    heuristics only -- a hint, never authoritative. Pure."""
    if isinstance(doc, dict):
        if {"declared", "observed"} & doc.keys():
            return "k8s"
        if doc.get("kind") == "Application":
            return "argocd"
        if {"resource_changes", "resource_drift"} & doc.keys():
            return "terraform"
    if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "chart" in doc[0]:
        return "helm"
    return None


@dataclass(frozen=True)
class ToolStatus:
    """One CLI a capability needs: is it on PATH, and (where we can cheaply check) is its backend
    reachable? ``reachable`` is None when un-checked -- either no reachability probe is defined for
    it, or it isn't installed."""

    name: str
    installed: bool
    reachable: bool | None


@dataclass(frozen=True)
class Finding:
    """A single source or probe's readiness in this environment."""

    name: str
    kind: str  # "source" | "probe"
    headline: str
    tools: tuple[ToolStatus, ...]
    inputs: tuple[str, ...] = ()  # matched input files in the cwd
    snapshots: tuple[str, ...] = ()  # detected captured snapshots for this source
    auto_probe: str | None = None  # source: the `--probe auto` pick
    auto_for: tuple[str, ...] = ()  # probe: the sources it's auto for


def _tool_statuses(
    bins: list[str], present: set[str], reachable: dict[str, bool]
) -> tuple[ToolStatus, ...]:
    return tuple(
        ToolStatus(name=b, installed=b in present, reachable=reachable.get(b)) for b in bins
    )


def _headline(tools: tuple[ToolStatus, ...], has_signal: bool, *, needs_input: bool) -> str:
    if not tools:
        return "n/a -- reads a captured snapshot only"
    missing = [t.name for t in tools if not t.installed]
    if missing:
        return f"blocked -- install: {', '.join(missing)}"
    unreachable = [t.name for t in tools if t.reachable is False]
    if unreachable:
        return f"installed, but backend unreachable: {', '.join(unreachable)}"
    if needs_input and not has_signal:
        return "tools ready -- no input found in cwd"
    return _READY


def assess_source(
    name: str,
    observe: tuple[str, ...],
    present: set[str],
    reachable: dict[str, bool],
    inputs: tuple[str, ...],
    snapshots: tuple[str, ...],
) -> Finding:
    """Build the Finding for one ``--source``. Pure -- all environment facts are passed in."""
    tools = _tool_statuses(required_bins(observe), present, reachable)
    headline = _headline(tools, bool(inputs or snapshots), needs_input=True)
    return Finding(
        name=name,
        kind="source",
        headline=headline,
        tools=tools,
        inputs=inputs,
        snapshots=snapshots,
        auto_probe=auto_prober_for(name),
    )


def assess_probe(
    name: str,
    observe: tuple[str, ...],
    present: set[str],
    reachable: dict[str, bool],
    auto_for: tuple[str, ...],
) -> Finding:
    """Build the Finding for one ``--probe``. Pure. A probe needs no cwd input -- it reads live
    health or the same snapshot its source does -- so readiness is purely tool availability."""
    tools = _tool_statuses(required_bins(observe), present, reachable)
    headline = _headline(tools, has_signal=True, needs_input=False)
    return Finding(name=name, kind="probe", headline=headline, tools=tools, auto_for=auto_for)


# -- I/O: gather the facts the pure assessors consume ----------------------------------------


def _installed(bins: set[str]) -> set[str]:
    return {b for b in bins if shutil.which(b) is not None}


def _check_reachable(binary: str) -> bool:
    argv = _REACHABILITY[binary]
    try:
        return (
            subprocess.run(argv, capture_output=True, timeout=_REACHABILITY_TIMEOUT).returncode == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


def _present_inputs(globs: str, cwd: Path) -> tuple[str, ...]:
    found: list[str] = []
    for pattern in (g.strip() for g in globs.split(",") if g.strip()):
        found.extend(sorted(p.name for p in cwd.glob(pattern)))
    return tuple(found)


def _classify_snapshots(cwd: Path) -> dict[str, list[str]]:
    """Bucket small ``*.json`` files in ``cwd`` by the source whose snapshot shape they match."""
    buckets: dict[str, list[str]] = {}
    for path in sorted(cwd.glob("*.json")):
        try:
            if path.stat().st_size > 2_000_000:
                continue
            doc = json.loads(path.read_text())
        except (OSError, ValueError, RecursionError):  # RecursionError: deeply-nested JSON
            continue
        if (source := snapshot_source(doc)) is not None:
            buckets.setdefault(source, []).append(path.name)
    return buckets


def probe_environment(cwd: Path | None = None) -> list[Finding]:
    """Inspect ``cwd`` (default: the process cwd) and this machine, returning a Finding per source
    then per probe. This is the I/O seam -- it gathers PATH/reachability/inputs and hands them to
    the pure assessors."""
    cwd = cwd or Path.cwd()

    # All CLIs any source or probe could need, looked up once.
    all_bins: set[str] = set()
    for caps in (*CAPABILITIES.values(), *PROBE_CAPABILITIES.values()):
        all_bins.update(required_bins(caps.observe))
    present = _installed(all_bins)
    reachable = {b: _check_reachable(b) for b in present if b in _REACHABILITY}

    snapshots = _classify_snapshots(cwd)
    findings: list[Finding] = []
    for name in sorted(CAPABILITIES):
        inputs = _present_inputs(_HINTS.get(name, {}).get("globs", ""), cwd)
        findings.append(
            assess_source(
                name,
                CAPABILITIES[name].observe,
                present,
                reachable,
                inputs,
                tuple(snapshots.get(name, ())),
            )
        )
    for name in sorted(PROBE_CAPABILITIES):
        auto_for = tuple(s for s in sorted(CAPABILITIES) if auto_prober_for(s) == name)
        findings.append(
            assess_probe(name, PROBE_CAPABILITIES[name].observe, present, reachable, auto_for)
        )
    return findings


def scannable_now(findings: list[Finding]) -> bool:
    """True iff at least one ``--source`` can be scanned in this cwd right now -- a tool-backed
    source that's READY, or a snapshot-only source (k8s/argocd/rancher) with a matching snapshot
    file present (it needs no local CLI). This is the signal ``discover --check`` exits non-zero
    on, so a CI/preflight step can branch on "is there anything to scan here?". Pure."""
    return any(f.kind == "source" and (f.headline == _READY or bool(f.snapshots)) for f in findings)


def as_dict(
    findings: list[Finding],
    inspections: list[Inspection] | None = None,
    cwd: Path | None = None,
) -> dict:
    """The discovery report as a JSON-serializable dict (`discover --json`): every Finding (and,
    when ``--deep`` ran, every Inspection) as a plain dict, plus the top-level ``scannable`` signal.
    Lets other tooling consume discovery without scraping the human report. Pure."""
    cwd = cwd or Path.cwd()
    payload: dict = {
        "cwd": str(cwd),
        "scannable": scannable_now(findings),
        "sources": [asdict(f) for f in findings if f.kind == "source"],
        "probes": [asdict(f) for f in findings if f.kind == "probe"],
    }
    if inspections is not None:
        payload["deep"] = [asdict(i) for i in inspections]
    return payload


# -- rendering --------------------------------------------------------------------------------


def _tool_line(tool: ToolStatus) -> str:
    if not tool.installed:
        return f"      [x] {tool.name}: not installed"
    if tool.reachable is False:
        return f"      [~] {tool.name}: installed, backend NOT reachable"
    return f"      [+] {tool.name}: installed"


def render(findings: list[Finding], cwd: Path | None = None) -> list[str]:
    """The discovery report as lines. Pure given ``findings`` -- the CLI just echoes them."""
    cwd = cwd or Path.cwd()
    lines = [f"steadystate discovery -- {cwd}", ""]
    sources = [f for f in findings if f.kind == "source"]
    probes = [f for f in findings if f.kind == "probe"]

    lines.append("SOURCES (--source):")
    for f in sources:
        lines.append(f"  * {f.name:<16} {f.headline}")
        lines.extend(_tool_line(t) for t in f.tools)
        if f.inputs:
            lines.append(f"      found in cwd: {', '.join(f.inputs[:4])}")
        if f.snapshots:
            lines.append(f"      snapshot(s): {', '.join(f.snapshots[:4])}")
        hint = _HINTS.get(f.name, {})
        if hint.get("live"):
            lines.append(f"      live:    {hint['live']}")
        if hint.get("capture"):
            lines.append(f"      capture: {hint['capture']}")
        lines.append("")

    lines.append("PROBES (--probe):")
    for f in probes:
        auto = f"  (auto for --source {', '.join(f.auto_for)})" if f.auto_for else ""
        lines.append(f"  ~ {f.name:<16} {f.headline}{auto}")
        lines.extend(_tool_line(t) for t in f.tools)
        if not f.tools:
            lines.append("      [+] reads a captured snapshot")
        lines.append("")

    lines.append("legend: [+] ready  [~] installed but backend unreachable  [x] not installed")
    return lines


# -- deep inspection: actually interrogate the live env (opt-in, read-only) -------------------
#
# The base report says whether a tool *could* run; deep inspection runs read-only `get`/`list`
# reads against reachable backends and reports concrete facts -- and, crucially, turns the generic
# hints into commands carrying the env's *real* release/namespace names. Called "inspect" (not
# "probe") to keep the health-probe seam's vocabulary distinct. Every read degrades to "skipped"
# on failure; it never invents a fact and never blocks the base report.

_DEEP_TIMEOUT = 10.0


@dataclass(frozen=True)
class Inspection:
    """One tool's live read: concrete facts and (when we can name them) tailored commands. ``ok``
    is False with a ``note`` when the read was skipped (tool absent / backend unreachable)."""

    tool: str
    ok: bool
    facts: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    note: str = ""
    targets: tuple[Target, ...] = ()  # live resources here that map to a valid scan target


def deep_targets(inspections: list[Inspection]) -> list[Target]:
    """The live-discovered resources that map to a scannable target (an existing path), flattened
    across inspections -- what `--deep --create` adds beyond the cwd-local ``proposed_targets``.
    Only sources whose target path is a live directory (docker-compose) qualify; argocd/helm would
    need a captured snapshot file, so they stay advice-only. Pure."""
    return [target for inspection in inspections for target in inspection.targets]


# -- pure summarizers (parse a read into facts/commands) --------------------------------------


def _node_ready(node: dict) -> bool:
    conditions = (node.get("status") or {}).get("conditions") or []
    return any(
        isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True"
        for c in conditions
    )


def summarize_nodes(doc: object) -> str:
    """`kubectl get nodes -o json` -> "N node(s), M Ready; kubelet v1.x". Pure."""
    items = doc.get("items") if isinstance(doc, dict) else None
    nodes = [n for n in (items or []) if isinstance(n, dict)]
    ready = sum(1 for n in nodes if _node_ready(n))
    versions = sorted(
        {((n.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion", "") for n in nodes}
        - {""}
    )
    kubelet = ", ".join(versions) if versions else "unknown"
    return f"{len(nodes)} node(s), {ready} Ready; kubelet {kubelet}"


def namespace_names(doc: object) -> list[str]:
    """`kubectl get namespaces -o json` -> the namespace names. Pure."""
    if not isinstance(doc, dict):
        return []
    return [
        name
        for n in (doc.get("items") or [])
        if isinstance(n, dict) and (name := (n.get("metadata") or {}).get("name"))
    ]


def summarize_releases(releases: object) -> list[str]:
    """`helm list -A -o json` -> one "name (ns=…, chart=…, status)" line per release. Pure."""
    if not isinstance(releases, list):
        return []
    return [
        f"{r.get('name', '?')} (ns={r.get('namespace', '?')}, "
        f"chart={r.get('chart', '?')}, {r.get('status', '?')})"
        for r in releases
        if isinstance(r, dict)
    ]


def helm_snapshot_commands(releases: object) -> list[str]:
    """The payoff: a concrete `helm get manifest <name> -n <ns>` declared-side render per real
    release, so `--source k8s` advice names the env's actual releases instead of placeholders.
    Pure -- consumes parsed `helm list -A -o json`."""
    out: list[str] = []
    for r in releases if isinstance(releases, list) else []:
        if not isinstance(r, dict):
            continue
        name, namespace = r.get("name"), r.get("namespace")
        if name and namespace:
            out.append(
                f"helm get manifest {name} -n {namespace} "
                f"| kubectl create --dry-run=client -o json -f - > {name}.declared.json"
            )
    return out


def backend_from_state(doc: object) -> str | None:
    """The backend type recorded in `.terraform/terraform.tfstate` (e.g. "s3"), or None. Pure."""
    if isinstance(doc, dict) and isinstance(backend := doc.get("backend"), dict):
        type_ = backend.get("type")
        return type_ if isinstance(type_, str) else None
    return None


def summarize_containers(containers: object) -> list[str]:
    """`docker ps --format {{json .}}` (one object per line, parsed to a list) -> a count line and,
    when present, the running names/images. Pure."""
    items = [c for c in (containers if isinstance(containers, list) else []) if isinstance(c, dict)]
    facts = [f"{len(items)} running container(s)"]
    names = [name for c in items if (name := c.get("Names") or c.get("Image"))][:8]
    if names:
        facts.append("running: " + ", ".join(names))
    return facts


def _compose_dir(config: object) -> str | None:
    """The directory of a compose project's first config file, or None when it can't be resolved.
    The path comes from the docker host, so its separator may differ from ours -- slice on either
    rather than pathlib (which would mangle a POSIX path on Windows). Pure."""
    first = config.split(",")[0].strip() if isinstance(config, str) else ""
    cut = max(first.rfind("/"), first.rfind("\\"))
    return first[:cut] if cut > 0 else None


def compose_scan_commands(projects: object) -> list[str]:
    """`docker compose ls --format json` -> a `scan <dir> --source docker-compose` per project,
    pointed at the directory of the project's compose file. Pure."""
    out: list[str] = []
    for p in projects if isinstance(projects, list) else []:
        if not isinstance(p, dict):
            continue
        directory = _compose_dir(p.get("ConfigFiles")) or "."
        out.append(
            f"steadystate scan {directory} --source docker-compose --probe docker"
            f"  # project {p.get('Name', '?')}"
        )
    return out


def compose_targets(projects: object) -> list[Target]:
    """`docker compose ls --format json` -> a `docker-compose` Target per project, pointed at the
    project's own directory. Unlike argocd/helm -- whose targets would need a captured snapshot file
    that doesn't exist yet -- a compose project's directory is real on disk, so the target is
    scannable now. This is what `--deep --create` registers beyond the cwd-local pass: running
    projects rooted *elsewhere*. Names come from the project. Pure."""
    out: list[Target] = []
    for p in projects if isinstance(projects, list) else []:
        if not isinstance(p, dict):
            continue
        directory = _compose_dir(p.get("ConfigFiles"))
        name = _slug(str(p.get("Name") or ""))
        if directory and name:
            out.append(
                Target(
                    name=name, source="docker-compose", path=directory, label=name, probe="docker"
                )
            )
    return out


def summarize_argocd_apps(apps: object) -> list[str]:
    """`argocd app list -o json` (or a `kubectl get applications` List) -> one
    "name (sync=…, health=…)" line per app. Pure."""
    items = apps if isinstance(apps, list) else apps.get("items") if isinstance(apps, dict) else []
    out: list[str] = []
    for a in items or []:
        if not isinstance(a, dict):
            continue
        name = (a.get("metadata") or {}).get("name", "?")
        status = a.get("status") or {}
        sync = (status.get("sync") or {}).get("status", "?")
        health = (status.get("health") or {}).get("status", "?")
        out.append(f"{name} (sync={sync}, health={health})")
    return out


def argocd_capture_commands(apps: object) -> list[str]:
    """A `argocd app get <name> -o json > <name>.json` capture per real app, so `--source argocd`
    advice names the env's actual applications. Pure."""
    items = apps if isinstance(apps, list) else apps.get("items") if isinstance(apps, dict) else []
    out: list[str] = []
    for a in items or []:
        if isinstance(a, dict) and (name := (a.get("metadata") or {}).get("name")):
            out.append(
                f"argocd app get {name} -o json > {name}.json"
                f" && steadystate scan {name}.json --source argocd --probe argocd"
            )
    return out


# Common Ansible inventory / playbook filenames -- used to find a real input to name in the
# tailored capture command (we can't parse YAML stdlib-only, so detection is filename-based).
_ANSIBLE_PLAYBOOKS = ("site.yml", "site.yaml", "playbook.yml", "playbook.yaml", "main.yml")


def inventory_hosts(doc: object) -> list[str]:
    """The distinct host names in an `ansible-inventory --list` doc, in first-seen order.
    `_meta.hostvars` is the authoritative host set; we also fold in any host listed under a group,
    so a sparse inventory (no gathered vars) still counts. Pure."""
    if not isinstance(doc, dict):
        return []
    hosts: dict[str, None] = {}
    hostvars = (doc.get("_meta") or {}).get("hostvars")
    if isinstance(hostvars, dict):
        for host in hostvars:
            hosts.setdefault(host, None)
    for key, group in doc.items():
        if key == "_meta" or not isinstance(group, dict):
            continue
        for host in group.get("hosts") or []:
            if isinstance(host, str):
                hosts.setdefault(host, None)
    return list(hosts)


def summarize_inventory(doc: object) -> str:
    """`ansible-inventory --list` (JSON) -> "N host(s) in M group(s)". Groups are the top-level
    keys minus Ansible's synthetic `_meta` / `all` / `ungrouped`. Pure."""
    hosts = inventory_hosts(doc)
    groups = (
        [k for k in doc if k not in ("_meta", "all", "ungrouped")] if isinstance(doc, dict) else []
    )
    return f"{len(hosts)} host(s) in {len(groups)} group(s)"


def _ansible_playbook(cwd: Path) -> str | None:
    """A real playbook filename in ``cwd`` to name in the capture command, or None. Filename-based
    (the project is stdlib-only, so a playbook's YAML can't be parsed to confirm it). Pure given
    the dir."""
    return next((name for name in _ANSIBLE_PLAYBOOKS if (cwd / name).is_file()), None)


def ansible_capture_command(cwd: Path) -> str:
    """The `--check` capture for `--source ansible`, naming a real playbook from ``cwd`` when one is
    present (else a `<playbook>` placeholder). The check run IS the reconcile, so -- unlike the
    other inspectors' live reads -- it's too heavy to run in a preflight; we tailor the command and
    let the operator run it. Pure given the dir."""
    playbook = _ansible_playbook(cwd) or "<playbook>"
    return (
        f"ANSIBLE_STDOUT_CALLBACK=json ansible-playbook --check --diff {playbook} > play.json"
        " && steadystate scan play.json --source ansible"
    )


# `ansible-playbook --list-tasks` prints role-prefixed task lines: ``  rolename : task name``. The
# role is the single identifier before the first `` : ``. We require a no-space identifier so a
# colon inside a plain (role-less) task name can't be mistaken for a role -- a heuristic that's fine
# because the result is only an *advisory suggestion* a human confirms, never a fact the system acts
# on. (Ansible parses the playbook; we read its output -- we never parse the YAML ourselves.)
_ROLE_TASK = re.compile(r"^\s+([\w.-]+) : ")


def playbook_roles(list_tasks_output: str) -> list[str]:
    """The distinct role names in `ansible-playbook --list-tasks` output, first-seen order. Pure.
    A role is the strongest hint of *what a playbook manages* (an `haproxy` role -> haproxy) -- used
    to SUGGEST services to watch, never to assert them."""
    roles: dict[str, None] = {}
    for line in list_tasks_output.splitlines():
        match = _ROLE_TASK.match(line)
        if match:
            roles.setdefault(match.group(1), None)
    return list(roles)


def _playbook_roles(cwd: Path) -> list[str]:
    """Run the read-only `ansible-playbook --list-tasks` on a playbook in ``cwd`` and return the
    role names it applies, or [] (no playbook, ansible absent, parse/role-resolution failure).
    `--list-tasks` only lists -- it executes nothing -- so it's safe in a preflight, unlike the
    `--check` reconcile. Inventory is passed through when set, as a host pattern may need it."""
    playbook = _ansible_playbook(cwd)
    if playbook is None or shutil.which("ansible-playbook") is None:
        return []
    argv = ["ansible-playbook", "--list-tasks", str(cwd / playbook)]
    inventory = os.environ.get("STEADYSTATE_ANSIBLE_INVENTORY")
    if inventory:
        argv += ["-i", inventory]
    ok, out = _run(argv)
    return playbook_roles(out) if ok else []


# -- I/O: run the read-only commands ----------------------------------------------------------


def _run(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=_DEEP_TIMEOUT)
        return result.returncode == 0, result.stdout
    except (OSError, subprocess.SubprocessError):
        return False, ""


def _run_json(argv: list[str]) -> object | None:
    ok, out = _run(argv)
    if not ok:
        return None
    try:
        return json.loads(out)
    except (ValueError, RecursionError):  # RecursionError: deeply-nested JSON
        return None


def _run_ndjson(argv: list[str]) -> list[dict] | None:
    """For tools that emit one JSON object per line (e.g. `docker ps --format {{json .}}`). None on
    a failed run; bad lines are skipped, not fatal."""
    ok, out = _run(argv)
    if not ok:
        return None
    docs: list[dict] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except (ValueError, RecursionError):  # RecursionError: deeply-nested JSON
            continue
        if isinstance(parsed, dict):
            docs.append(parsed)
    return docs


def inspect_kubectl() -> Inspection:
    if shutil.which("kubectl") is None:
        return Inspection("kubectl", ok=False, note="kubectl not installed")
    nodes = _run_json(["kubectl", "get", "nodes", "-o", "json", "--request-timeout=8s"])
    if nodes is None:
        return Inspection(
            "kubectl", ok=False, note="installed, but no reachable cluster (kubeconfig/context?)"
        )
    _, context = _run(["kubectl", "config", "current-context"])
    namespaces = namespace_names(_run_json(["kubectl", "get", "namespaces", "-o", "json"]))
    facts = [f"context: {context.strip() or 'unknown'}", f"nodes: {summarize_nodes(nodes)}"]
    if namespaces:
        facts.append(f"namespaces ({len(namespaces)}): {', '.join(namespaces[:12])}")
    return Inspection("kubectl", ok=True, facts=tuple(facts))


def inspect_helm() -> Inspection:
    if shutil.which("helm") is None:
        return Inspection("helm", ok=False, note="helm not installed")
    releases = _run_json(["helm", "list", "-A", "-o", "json"])
    if releases is None:
        return Inspection(
            "helm", ok=False, note="installed, but couldn't list releases (cluster unreachable?)"
        )
    summaries = summarize_releases(releases)
    if not summaries:
        return Inspection("helm", ok=True, facts=("no Helm releases in any namespace",))
    commands = helm_snapshot_commands(releases)
    recs = ("render each release's declared side for --source k8s:", *commands) if commands else ()
    return Inspection(
        "helm", ok=True, facts=tuple(f"release: {s}" for s in summaries), recommendations=recs
    )


def inspect_terraform(cwd: Path) -> Inspection:
    tf_files = sorted(cwd.glob("*.tf"))
    if not tf_files:
        return Inspection("terraform", ok=False, note="no *.tf files in cwd")
    initialized = (cwd / ".terraform").is_dir()
    facts = [
        f"{len(tf_files)} *.tf file(s) in cwd",
        "initialized: yes" if initialized else "initialized: no (run `terraform init`)",
    ]
    recommendations: tuple[str, ...] = ()
    state = cwd / ".terraform" / "terraform.tfstate"
    if state.exists():
        try:
            backend = backend_from_state(json.loads(state.read_text()))
        except (OSError, ValueError, RecursionError):  # RecursionError: deeply-nested JSON
            backend = None
        if backend:
            facts.append(f"backend: {backend}")
            recommendations = (
                f"state lives in the {backend} backend; if you can't read it, generate plan.json "
                "where you can (CI) and scan that file -- don't use -backend=false (no state = "
                "every resource reads as ADDED)",
            )
    return Inspection("terraform", ok=True, facts=tuple(facts), recommendations=recommendations)


def inspect_docker() -> Inspection:
    if shutil.which("docker") is None:
        return Inspection("docker", ok=False, note="docker not installed")
    containers = _run_ndjson(["docker", "ps", "--format", "{{json .}}"])
    if containers is None:
        return Inspection("docker", ok=False, note="installed, but daemon unreachable")
    facts = summarize_containers(containers)
    projects = _run_json(["docker", "compose", "ls", "--format", "json"])
    recommendations: tuple[str, ...] = ()
    targets: tuple[Target, ...] = ()
    if isinstance(projects, list) and projects:
        facts.extend(
            f"compose project: {p.get('Name', '?')} ({p.get('Status', '?')})"
            for p in projects
            if isinstance(p, dict)
        )
        if commands := compose_scan_commands(projects):
            recommendations = ("scan each running compose project:", *commands)
        targets = tuple(compose_targets(projects))
    return Inspection(
        "docker", ok=True, facts=tuple(facts), recommendations=recommendations, targets=targets
    )


def inspect_argocd() -> Inspection:
    if shutil.which("argocd") is None:
        return Inspection("argocd", ok=False, note="argocd CLI not installed")
    apps = _run_json(["argocd", "app", "list", "-o", "json"])
    if apps is None:
        return Inspection(
            "argocd", ok=False, note="installed, but not logged in / server unreachable"
        )
    summaries = summarize_argocd_apps(apps)
    if not summaries:
        return Inspection("argocd", ok=True, facts=("no Argo CD applications",))
    commands = argocd_capture_commands(apps)
    recs = ("capture each app for --source argocd:", *commands) if commands else ()
    return Inspection(
        "argocd", ok=True, facts=tuple(f"app: {s}" for s in summaries), recommendations=recs
    )


def inspect_ansible(cwd: Path) -> Inspection:
    """The live read for `--source ansible`: `ansible-inventory --list` (read-only JSON) reports the
    fleet the playbooks target -- host + group counts -- and the advice names a real playbook from
    the cwd. The `--check` run that yields drift is the reconcile itself, too heavy for a preflight,
    so we never run it here; we surface the fleet and tailor the capture command. Skips honestly
    when ansible isn't installed or no inventory resolves."""
    if shutil.which("ansible-inventory") is None:
        return Inspection("ansible", ok=False, note="ansible not installed")
    inventory = _run_json(["ansible-inventory", "--list"])
    if inventory is None:
        return Inspection(
            "ansible", ok=False, note="installed, but no inventory resolved (ansible.cfg / -i?)"
        )
    hosts = inventory_hosts(inventory)
    facts = [f"inventory: {summarize_inventory(inventory)}"]
    if hosts:
        facts.append(f"hosts: {', '.join(hosts[:12])}")
    recs = ["capture --check drift for --source ansible:", ansible_capture_command(cwd)]
    # Advisory only: read the playbook's roles (via Ansible's own --list-tasks, never YAML-parsing)
    # to SUGGEST what services the fleet runs, so `--probe ansible` has somewhere to look. A hint a
    # human confirms -- it drives no detection or action, so a wrong guess just gets ignored.
    roles = _playbook_roles(cwd)
    if roles:
        facts.append(f"playbook roles: {', '.join(roles[:12])}")
        recs.append(
            f"these roles suggest services to watch (advisory) -- `--probe ansible` reports any "
            f"that are failing/down: {', '.join(roles[:12])}"
        )
    return Inspection("ansible", ok=True, facts=tuple(facts), recommendations=tuple(recs))


def deep_inspect(cwd: Path | None = None) -> list[Inspection]:
    """Run the read-only live reads for the supported tools and return one Inspection each."""
    cwd = cwd or Path.cwd()
    return [
        inspect_kubectl(),
        inspect_helm(),
        inspect_terraform(cwd),
        inspect_docker(),
        inspect_argocd(),
        inspect_ansible(cwd),
    ]


def render_inspections(results: list[Inspection]) -> list[str]:
    """The deep-inspection section as lines, appended after the base report. Pure."""
    lines = ["", "DEEP INSPECTION (live, read-only):"]
    for r in results:
        if not r.ok:
            lines.append(f"  {r.tool}: skipped -- {r.note}")
            continue
        lines.append(f"  {r.tool}:")
        lines.extend(f"      - {fact}" for fact in r.facts)
        lines.extend(f"      -> {rec}" for rec in r.recommendations)
    return lines


# -- target creation: turn what's here into named scan targets ---------------------------------
#
# `--create` writes the discovered sources into the targets registry (the name -> {source, path}
# map the chat listener resolves). The base name comes from the cwd; when more than one source is
# scannable here, each gets a `-<source>` suffix so the names stay unique and self-describing.


def _slug(name: str) -> str:
    """A filesystem/CLI-friendly target name: lowercased, non-alphanumerics collapsed to single
    dashes, edges trimmed. "Shop.API v2" -> "shop-api-v2". Pure."""
    out = []
    for ch in name.lower():
        out.append(ch if ch.isalnum() else "-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def _target_path(finding: Finding, cwd: Path) -> str | None:
    """The concrete path a target for this source would scan: the working dir when the source has a
    live dir signal present (terraform's *.tf, a compose file), else a detected snapshot file, else
    None (nothing scannable here). Pure."""
    if _HINTS.get(finding.name, {}).get("live") and finding.inputs:
        return str(cwd)
    if finding.snapshots:
        return str(cwd / finding.snapshots[0])
    return None


def proposed_targets(findings: list[Finding], cwd: Path) -> list[Target]:
    """The targets `--create` would write: one per source with a usable input in ``cwd``. The base
    name is the cwd's; with a single hit it's used bare, with several each is suffixed `-<source>`
    so the names are unique and say what they scan. Pure -- the caller persists them."""
    base = _slug(cwd.name) or "target"
    hits = [
        (f, path)
        for f in findings
        if f.kind == "source" and (path := _target_path(f, cwd)) is not None
    ]
    multiple = len(hits) > 1
    targets: list[Target] = []
    for finding, path in hits:
        name = f"{base}-{finding.name}" if multiple else base
        targets.append(Target(name=name, source=finding.name, path=path, label=name, probe="auto"))
    return targets


# -- kube contexts -> live targets: register each reachable cluster ----------------------------
#
# `--create` also registers one `k8s-live` target per kube context, so a fleet of clusters you can
# reach (a dir of kubeconfigs, or one config with many contexts) becomes named targets you can
# `probe` -- the whole point of the live cluster-health path. kubectl reads/merges the kubeconfig(s)
# and parses the YAML, so this stays stdlib-only; it degrades to no targets when kubectl is absent
# or no context resolves, never blocking a create.

_GET_CONTEXTS = ["kubectl", "config", "get-contexts", "-o", "name"]


def context_targets(contexts: list[str]) -> list[Target]:
    """One live (`k8s-live`) target per kube context. The target name is a slug of the context
    (friendly to type in chat); the raw context drives kubectl and labels the alerts, and there's
    no path (a live source reads live state). Pure -- the caller persists them."""
    targets: list[Target] = []
    for ctx in contexts:
        name = _slug(ctx) or "cluster"
        targets.append(
            Target(name=name, source="k8s-live", path="", label=ctx, probe="auto", context=ctx)
        )
    return targets


def kube_contexts() -> list[str]:
    """The kube contexts visible to kubectl (`kubectl config get-contexts -o name`), in file order,
    deduped. [] when kubectl is absent or no context resolves -- a local kubeconfig read, no cluster
    contact. This is the I/O seam `--create` consumes via ``context_targets``."""
    ok, out = _run(_GET_CONTEXTS)
    if not ok:
        return []
    seen: dict[str, None] = {}
    for line in out.splitlines():
        name = line.strip()
        if name:
            seen.setdefault(name, None)
    return list(seen)


# A kubeconfig the operator dropped in the working dir isn't on kubectl's default path, so
# ``kubectl config get-contexts`` never sees it -- `discover` would miss a cluster you clearly want
# probed. So we look for kubeconfig files in the cwd, enumerate each one's contexts (handing the
# file to kubectl via ``--kubeconfig`` so kubectl still does the YAML parse -- stdlib-only), and
# make each a target that REMEMBERS its kubeconfig, so a later `probe` adds ``--kubeconfig`` and can
# actually reach the cluster. Content-sniffed, not name-matched: a kubeconfig is reliably
# ``kind: Config``, so an arbitrarily-named file (``admin.conf``, ``prod-cluster``) is still found.

# How many bytes of a candidate file to sniff for the kubeconfig signature, and the cap above which
# a file is too big to be a hand-dropped kubeconfig (don't read a multi-GB blob to sniff it).
_KUBECONFIG_SNIFF_BYTES = 4096
_KUBECONFIG_MAX_BYTES = 1_000_000


def _looks_like_kubeconfig(path: Path) -> bool:
    """True if ``path``'s head carries the kubeconfig signature (``kind: Config``). A cheap content
    sniff so we only hand real candidates to kubectl -- never matches on filename, so an
    arbitrarily-named kubeconfig is still found, and a same-named non-kubeconfig is not."""
    try:
        if path.stat().st_size > _KUBECONFIG_MAX_BYTES:
            return False
        with path.open("r", encoding="utf-8") as fh:
            head = fh.read(_KUBECONFIG_SNIFF_BYTES)
    except (OSError, UnicodeDecodeError):
        return False  # unreadable / binary -> not a kubeconfig
    return "kind: Config" in head


def cwd_kubeconfigs(cwd: Path) -> list[Path]:
    """The kubeconfig files in ``cwd`` (top level only, content-sniffed), sorted for stable order.
    Pure-ish (a directory read); the I/O the create path consumes via ``kubeconfig_targets``."""
    try:
        entries = sorted(cwd.iterdir())
    except OSError:
        return []
    return [p for p in entries if p.is_file() and _looks_like_kubeconfig(p)]


def _contexts_in(kubeconfig: Path) -> list[str]:
    """The contexts defined in one kubeconfig file -- ``kubectl config get-contexts --kubeconfig``,
    so kubectl does the YAML parse and a non-kubeconfig (or kubectl-absent) yields []."""
    ok, out = _run([*_GET_CONTEXTS, "--kubeconfig", str(kubeconfig)])
    if not ok:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def kubeconfig_targets(cwd: Path) -> list[Target]:
    """One live (`k8s-live`) target per context found in a cwd kubeconfig, each carrying the
    ``kubeconfig`` it came from so a later `probe` can actually reach the cluster (adds
    ``--kubeconfig``). Names are slugged from the context and de-duplicated *within this set* (two
    cwd kubeconfigs can share a context name -- the file stem disambiguates) so a real second
    cluster isn't silently dropped. Pure given the kubectl reads; the caller persists them."""
    targets: list[Target] = []
    used: set[str] = set()
    for kc in cwd_kubeconfigs(cwd):
        for ctx in _contexts_in(kc):
            name = _slug(ctx) or "cluster"
            if name in used:  # same context name in another cwd kubeconfig -> disambiguate
                name = f"{name}-{_slug(kc.stem)}" or name
            used.add(name)
            targets.append(
                Target(
                    name=name,
                    source="k8s-live",
                    path="",
                    label=ctx,
                    probe="auto",
                    context=ctx,
                    kubeconfig=str(kc),
                )
            )
    return targets


# -- CI emission: a GitHub Actions workflow tailored to what's here -----------------------------
#
# `--emit-ci` writes a workflow that scans the sources discovered in the cwd -- the durable home
# for a scan, and the *right* home for the snapshot-file sources (terraform plan / helm list /
# k8s render) whose backend creds live in CI, not on a laptop. It's the capstone of the discover
# arc: discover -> (create) -> run on a schedule + every PR. The capture command per source is
# known; the *auth* to a backend is not (OIDC / Vault / kubeconfig vary), so that's left as a
# clearly-marked TODO -- the same honest boundary the hand-authored deploy/ example draws.


@dataclass(frozen=True)
class CIRecipe:
    """How to scan one source in CI: the `uses:` setup actions, a one-line auth TODO (the creds
    discover can't know), the shell that captures the scannable input, and the scan command."""

    setup: tuple[str, ...]
    auth: str
    capture: tuple[str, ...]
    scan: str


# Per-source CI recipe. Only sources that can be a discovery "hit" (a local input or a detected
# snapshot in the cwd) appear here -- ansible/rancher have no cwd signal to key off.
_CI_STEPS: dict[str, CIRecipe] = {
    "terraform": CIRecipe(
        setup=("hashicorp/setup-terraform@v3",),
        auth="TODO: authenticate to your Terraform backend + provider (OIDC / Vault / secrets).",
        capture=(
            "terraform init -input=false",
            "terraform plan -refresh=true -out tfplan",
            "terraform show -json tfplan > plan.json",
        ),
        scan="steadystate scan plan.json --source terraform --to console",
    ),
    "helm": CIRecipe(
        setup=("azure/setup-helm@v4",),
        auth="TODO: provide cluster access (kubeconfig / OIDC / az aks get-credentials).",
        capture=("helm list -A -o json > releases.json",),
        scan="steadystate scan releases.json --source helm --to console",
    ),
    "docker-compose": CIRecipe(
        setup=(),
        auth="TODO: make the compose project + a running stack available (often not in CI).",
        capture=(),  # scans the live working dir directly
        scan="steadystate scan . --source docker-compose --probe docker --to console",
    ),
    "k8s": CIRecipe(
        setup=(),
        auth="TODO: provide cluster access (kubeconfig / OIDC).",
        capture=(
            "# TODO: render the snapshot, e.g. snapshot.json ="
            ' {"declared": <helm get manifest | kubectl ...>, "observed": <kubectl get -o json>}',
        ),
        scan="steadystate scan snapshot.json --source k8s --probe kubectl --to console",
    ),
    "argocd": CIRecipe(
        setup=(),
        auth="TODO: provide ARGOCD_SERVER + ARGOCD_TOKEN (or `argocd login`).",
        capture=("argocd app get <app> -o json > app.json",),
        scan="steadystate scan app.json --source argocd --probe argocd --to console",
    ),
}


def emittable_sources(findings: list[Finding]) -> list[str]:
    """The source names `--emit-ci` will write a job step for: a discovery hit (a local input or a
    detected snapshot in the cwd) that has a known CI recipe. Pure."""
    return [
        f.name
        for f in findings
        if f.kind == "source" and (f.inputs or f.snapshots) and f.name in _CI_STEPS
    ]


def emit_github_actions(findings: list[Finding], cwd: Path) -> list[str]:
    """A GitHub Actions workflow that scans the sources discovered in ``cwd`` -- tailored to what's
    here, not a generic template. One capture+scan step per discovered source; credentials are left
    as TODO comments (discover can't know your auth). Pure string templating, stdlib-only -- the CLI
    echoes the lines to stdout so `discover --emit-ci > .github/workflows/drift.yml` just works."""
    lines = [
        f"# Generated by `steadystate discover --emit-ci` for {cwd}.",
        "# Review the TODO auth steps, then commit as .github/workflows/steadystate-drift.yml.",
        "name: steadystate-drift",
        "on:",
        "  schedule:",
        '    - cron: "0 * * * *"  # hourly drift sweep',
        "  pull_request:  # and a pre-merge review of what would change",
        "  workflow_dispatch:",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  scan:",
        "    runs-on: ubuntu-latest",
        "    steps:",
        "      - uses: actions/checkout@v4",
        "      - name: Install steadystate",
        "        run: pip install steadystate",
    ]
    for name in emittable_sources(findings):
        recipe = _CI_STEPS[name]
        lines.append(f"      # --- {name} ---")
        lines.append(f"      # {recipe.auth}")
        lines.extend(f"      - uses: {action}" for action in recipe.setup)
        lines.append(f"      - name: Scan {name} for drift")
        lines.append("        run: |")
        lines.extend(f"          {cmd}" for cmd in recipe.capture)
        lines.append(f"          {recipe.scan}")
    return lines
