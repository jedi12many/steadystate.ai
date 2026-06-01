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
import shutil
import subprocess
from dataclasses import dataclass
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
    return "READY"


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
        except (OSError, ValueError):
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


def compose_scan_commands(projects: object) -> list[str]:
    """`docker compose ls --format json` -> a `scan <dir> --source docker-compose` per project,
    pointed at the directory of the project's compose file. Pure."""
    out: list[str] = []
    for p in projects if isinstance(projects, list) else []:
        if not isinstance(p, dict):
            continue
        config = p.get("ConfigFiles")
        first = config.split(",")[0].strip() if isinstance(config, str) else ""
        # The compose path comes from the docker host, so its separator may differ from ours --
        # slice on either rather than pathlib (which would mangle a POSIX path on Windows).
        cut = max(first.rfind("/"), first.rfind("\\"))
        directory = first[:cut] if cut > 0 else "."
        out.append(
            f"steadystate scan {directory} --source docker-compose --probe docker"
            f"  # project {p.get('Name', '?')}"
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
    except ValueError:
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
        except ValueError:
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
        except (OSError, ValueError):
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
    if isinstance(projects, list) and projects:
        facts.extend(
            f"compose project: {p.get('Name', '?')} ({p.get('Status', '?')})"
            for p in projects
            if isinstance(p, dict)
        )
        if commands := compose_scan_commands(projects):
            recommendations = ("scan each running compose project:", *commands)
    return Inspection("docker", ok=True, facts=tuple(facts), recommendations=recommendations)


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


def deep_inspect(cwd: Path | None = None) -> list[Inspection]:
    """Run the read-only live reads for the supported tools and return one Inspection each."""
    cwd = cwd or Path.cwd()
    return [
        inspect_kubectl(),
        inspect_helm(),
        inspect_terraform(cwd),
        inspect_docker(),
        inspect_argocd(),
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
