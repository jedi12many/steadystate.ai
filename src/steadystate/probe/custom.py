"""User-defined, per-wall health checks -- a DECLARATIVE rule (a vetted read + a condition) the
operator (in plain English via ``define-check``) or an agent (filling the schema, via ``add-check``)
stores in the wall's ``.steadystate/checks.json``, which steadystate evaluates DETERMINISTICALLY
into a Symptom. It never executes operator-supplied code; ``parse_check`` is the gate on the schema.

The safety model mirrors the action catalog: WHAT to check is data (a schema of vetted, read-only
reads); the reading and comparing are steadystate's. A check can only ever OBSERVE -- emit a finding
-- never act; acting on what it finds still passes the bound + catalog. So a wrong check is *noise*
(a mutable finding), never damage. Per-wall by construction: the checks live in the wall's
``.steadystate/``, so different cluster-sets carry different rules for free, no cross-wall reach.

Read kinds: ``kubectl-cpu`` / ``kubectl-mem`` -- the live CPU/memory of the pods matching a label
selector (metrics API), aggregated and compared to a threshold; ``kubectl-log`` -- a regex that
should be *present* (a success signal, e.g. ``status=sent``) or *absent* (an error) in the
pods' recent logs, i.e. "running, but doing its job?"; and ``docker-log`` -- the same, over the logs
of the containers matching a ``docker ps`` filter (functional health for compose);
``ansible-service`` -- is a unit ``active``/``inactive`` across a host pattern; and ``http`` -- a
**smoke test**: GET/HEAD an endpoint and assert the response (the strongest "is it working?" signal
-- proof, not inference).

The passive kinds are conservative: a read we couldn't take -> no finding (a *down* app is the
generic prober's call). The ``http`` smoke test is the deliberate exception -- an endpoint that
won't answer IS the service being down, so an unreachable probe FIRES. Each check is dispatched to
the reader for its backend. The Symptoms ride the normal pipeline, so a custom finding is tracked
new/recurring/resolved, muteable, feeds ``resolve``/``learn`` -- and counts as IMPAIRED in
`summary`."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # noqa: S404 -- argv only, no shell; reads only
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from .._http import safe_urlopen  # the single http(s)-gated urlopen
from ..evidence import EvidenceKeys
from ..model import Provenance
from ..reason.alert import Severity
from .ansible_health import (
    _RUNNING_STATES,
    _services_by_host,
)  # reuse the vetted service_facts read
from .base import Symptom

DEFAULT_CHECKS_FILE = ".steadystate/checks.json"  # legacy/gitignored -- still read if present
COMMITTED_CHECKS_FILE = "steadystate/checks.json"  # version-controlled INTENT (the preferred home)
CHECKS_ENV = "STEADYSTATE_CHECKS"


def resolve_checks_path(explicit: str = "") -> str:
    """Where the checks live. Checks are *intent* (IaC-grade), unlike the ephemeral ``state.db``, so
    the **committed** ``steadystate/`` is the home -- authored/agent-written checks are reviewed in
    PRs and travel with the IaC, not lost in the gitignored ``.steadystate/``. Order: ``explicit``
    path, else ``STEADYSTATE_CHECKS``, else committed ``steadystate/checks.json`` if it exists,
    else -- inside a ``steadystate/`` tree (a silo), where the prefix would stutter -- the bare
    ``./checks.json``, else the legacy ``.steadystate/checks.json`` if THAT exists. A fresh write
    (none yet) lands committed -- bare inside the tree -- so a newly authored check is always
    somewhere version-controllable."""
    from ..config import in_steadystate_tree

    if explicit:
        return explicit
    env = os.environ.get(CHECKS_ENV, "").strip()
    if env:
        return env
    if Path(COMMITTED_CHECKS_FILE).exists():
        return COMMITTED_CHECKS_FILE
    in_tree = in_steadystate_tree()
    if in_tree and Path("checks.json").exists():
        return "checks.json"
    if Path(DEFAULT_CHECKS_FILE).exists():
        return DEFAULT_CHECKS_FILE
    return "checks.json" if in_tree else COMMITTED_CHECKS_FILE


_NUMERIC_KINDS = frozenset({"kubectl-cpu", "kubectl-mem"})  # a threshold over an aggregated value
# functional health: a pattern that should/shouldn't be in the workload's recent logs. kubectl-log
# reads pods (a label selector + namespace); docker-log reads containers (a `docker ps` filter).
_LOG_KINDS = frozenset({"kubectl-log", "docker-log"})
_KUBECTL_KINDS = _NUMERIC_KINDS | {"kubectl-log"}
_ANSIBLE_KINDS = frozenset({"ansible-service"})  # is a host/VM service in the expected state?
# the SMOKE TEST: actively exercise an endpoint and assert the response -- the strongest "is it
# doing its job?" signal (proof, not inference), and an agent's close-the-loop verdict after a fix.
_HTTP_KINDS = frozenset({"http"})
_ALL_KINDS = _NUMERIC_KINDS | _LOG_KINDS | _ANSIBLE_KINDS | _HTTP_KINDS
_SAFE_METHODS = frozenset({"GET", "HEAD"})  # idempotent only -- a smoke test reads, never mutates
_OPS = frozenset({"<", ">", "<=", ">=", "==", "!="})
_AGGS = frozenset({"sum", "max", "avg"})
_EXPECT = frozenset({"present", "absent"})  # for the log kinds
_EXPECT_SERVICE = frozenset({"active", "inactive"})  # for ansible-service
_SEVERITIES = {s.value: s for s in Severity}


@dataclass(frozen=True)
class CustomCheck:
    """One declarative check: a vetted read, a condition, and the finding to emit when it holds.
    Parsed + validated from a JSON object; an invalid one is dropped (so a single typo never sinks
    the rest). Pure data -- no code, no command, nothing to execute. ``parse_check`` fills only the
    fields the ``kind`` uses (numeric: op/value/agg; log: pattern/expect/tail; service: service/
    expect)."""

    name: str
    kind: str  # kubectl-cpu | kubectl-mem | kubectl-log | docker-log | ansible-service
    selector: str  # k8s label selector | docker ps filter | ansible host pattern
    namespace: str
    severity: Severity
    title: str
    # numeric (kubectl-cpu / kubectl-mem): a threshold over the aggregated value
    op: str = ""  # < > <= >= == !=
    value: float = 0.0  # CPU in millicores; memory in MiB
    agg: str = "sum"  # combine the matching pods' values: sum | max | avg
    # log (kubectl-log / docker-log): a pattern present (a success signal) or absent (an error)
    pattern: str = ""  # a regex searched across the recent logs
    expect: str = ""  # present/absent (log) | active/inactive (service)
    tail: int = 200  # lines of recent log per pod/container to read
    # service (ansible-service): the unit name, in its expected state across the host pattern
    service: str = ""  # e.g. "mailer" (".service" suffix optional)
    # http (smoke test): exercise an endpoint and assert the response
    url: str = ""  # the http(s) endpoint to probe (the target; http checks carry no selector)
    method: str = "GET"  # GET | HEAD only -- safe, idempotent; a smoke test reads, never mutates
    status: int = 200  # the expected HTTP status; a different status (or no response) fires
    body: str = ""  # optional regex that must be PRESENT in the response body (a success signal)

    @property
    def unit(self) -> str:
        return "millicores" if self.kind == "kubectl-cpu" else "MiB"


@dataclass(frozen=True)
class CheckResult:
    """One smoke test's outcome -- PASS or FAIL, with the target and a reason. Unlike a Symptom
    (emitted only on failure), a result is reported either way, so `smoke` can affirmatively show
    that a service is *working*, not merely that nothing failed."""

    name: str
    kind: str
    passed: bool
    detail: str  # the failure reason when not passed; "" on a pass
    target: str  # what was exercised (the URL)


def parse_check(raw: dict) -> CustomCheck | None:
    """Build a :class:`CustomCheck` from one JSON object, or None if it's malformed / uses a read
    kind or operator outside the vetted set. The validation IS the safety boundary on the schema."""
    if not isinstance(raw, dict):
        return None
    read, when, emit = raw.get("read") or {}, raw.get("when") or {}, raw.get("emit") or {}
    name = raw.get("name")
    kind = read.get("kind")
    namespace = read.get("namespace", "")  # k8s only; a docker filter carries its own scope
    severity, title = emit.get("severity"), emit.get("title")
    if not (isinstance(name, str) and name):
        return None
    if kind not in _ALL_KINDS or not isinstance(namespace, str):
        return None
    if severity not in _SEVERITIES or not isinstance(title, str) or not title:
        return None
    sev = _SEVERITIES[severity]
    # http (smoke test): the URL is the target -- no selector / namespace, a different shape.
    if kind in _HTTP_KINDS:
        return _parse_http_check(name, sev, title, read, when)
    # every other kind targets a selector (a label / docker filter / host pattern).
    selector = read.get("selector")
    if not isinstance(selector, str) or not selector:
        return None
    if kind in _KUBECTL_KINDS and not namespace:
        return None  # a kubectl read is scoped to one namespace
    common = {
        "name": name,
        "kind": kind,
        "selector": selector,
        "namespace": namespace,
        "severity": sev,
        "title": title,
    }
    if kind in _NUMERIC_KINDS:
        agg, op, value = read.get("agg", "sum"), when.get("op"), when.get("value")
        if agg not in _AGGS or op not in _OPS:
            return None
        if not isinstance(value, int | float) or isinstance(value, bool):
            return None
        return CustomCheck(**common, op=op, value=float(value), agg=agg)
    if kind in _ANSIBLE_KINDS:
        service, expect = read.get("service"), when.get("expect")
        if not isinstance(service, str) or not service or expect not in _EXPECT_SERVICE:
            return None
        return CustomCheck(**common, service=service, expect=expect)
    log = _parse_log_fields(when, read)  # the log kinds (kubectl-log / docker-log)
    return None if log is None else CustomCheck(**common, **log)


def _parse_log_fields(when: dict, read: dict) -> dict | None:
    """The condition shared by every log kind: a regex that should be ``present`` (a success signal)
    or ``absent`` (an error) in the recent logs, + how many lines to read. None if malformed -- the
    pattern must compile (a broken regex is dropped, not stored), so the check can never throw."""
    pattern, expect, tail = when.get("pattern"), when.get("expect"), read.get("tail", 200)
    if not isinstance(pattern, str) or not pattern or expect not in _EXPECT:
        return None
    if not isinstance(tail, int) or isinstance(tail, bool) or tail <= 0:
        return None
    try:
        re.compile(pattern)
    except re.error:
        return None
    return {"pattern": pattern, "expect": expect, "tail": tail}


def _parse_http_check(
    name: str, severity: Severity, title: str, read: dict, when: dict
) -> CustomCheck | None:
    """Validate a ``http`` smoke test: a vetted, **idempotent** request (GET/HEAD only -- it reads
    by exercising, never mutates) to an http(s) URL, asserting an expected status and, optionally, a
    body regex. The method allowlist + the http(s)-only URL are the safety boundary on the active
    kind. None if malformed (a bad URL, an unsafe method, an uncompilable body regex)."""
    url = read.get("url")
    method = str(read.get("method", "GET")).upper()
    expected_status = when.get("status", 200)
    body = when.get("body", "")
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    if method not in _SAFE_METHODS:
        return None
    if not isinstance(expected_status, int) or isinstance(expected_status, bool):
        return None
    if not isinstance(body, str):
        return None
    if body:
        try:
            re.compile(body)
        except re.error:
            return None
    return CustomCheck(
        name=name,
        kind="http",
        selector="",
        namespace="",
        severity=severity,
        title=title,
        url=url,
        method=method,
        status=expected_status,
        body=body,
    )


def load_checks(path: str = "") -> list[CustomCheck]:
    """The valid checks (a JSON list of check objects, from ``resolve_checks_path``). Missing /
    malformed file -> [] (the un-checked path is unchanged). Invalid entries are skipped, valid ones
    kept -- one bad rule never disables the others."""
    path = resolve_checks_path(path)
    if not path or not Path(path).exists():
        return []
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [check for item in raw if (check := parse_check(item)) is not None]


def diagnose_checks(path: str = "") -> list[str]:
    """A human diagnosis of the checks file for `doctor` -- because `load_checks` SILENTLY drops
    what it can't parse (a bad JSON file -> [], a bad entry -> skipped, a wrong path -> missing), so
    authored check that just 'doesn't show up' gives no clue why. This turns each silent miss into a
    line: where it looked, whether the file is there + parses, how many checks loaded, and WHICH
    entries were skipped. Returns lines (the first names the resolved path)."""
    resolved = resolve_checks_path(path)
    lines = [f"checks file: {resolved}"]
    target = Path(resolved)
    if not target.exists():
        looked = " or ".join(dict.fromkeys([COMMITTED_CHECKS_FILE, DEFAULT_CHECKS_FILE]))
        lines.append(f"  not found (looked: {looked}). Set STEADYSTATE_CHECKS / --checks.")
        return lines
    try:
        raw = json.loads(target.read_text())
    except (OSError, ValueError) as exc:
        lines.append(f"  INVALID JSON ({exc}) -- the WHOLE file is ignored. Fix the syntax.")
        return lines
    if not isinstance(raw, list):
        lines.append("  not a JSON list -- it must be a [ ... ] of check objects.")
        return lines
    valid = 0
    for i, item in enumerate(raw):
        if parse_check(item) is not None:
            valid += 1
        else:
            name = item.get("name", "?") if isinstance(item, dict) else "?"
            lines.append(f"  check #{i} ('{name}'): SKIPPED -- doesn't match the vetted schema.")
    lines.append(f"  {valid}/{len(raw)} check(s) valid + loaded.")
    if valid < len(raw):
        lines.append(f"  schema: {CHECK_SCHEMA_HINT}")
    return lines


# -- authoring: validate + store a check, and translate natural language into one -----------------

# A compact description of the vetted schema -- prompts the LLM (`define_check`) and tells a caller
# what a *valid* check looks like when one is rejected. The schema IS the safety boundary.
CHECK_SCHEMA_HINT = (
    "A check is JSON: {name, read:{kind,...}, when:{...}, emit:{severity, title}}. "
    "severity is low|medium|high|critical. Kinds:\n"
    "- kubectl-cpu / kubectl-mem: read{selector(label, e.g. app=web), namespace, "
    "agg?(sum|max|avg)}, when{op(<,>,<=,>=,==,!=), value} -- CPU millicores, memory MiB.\n"
    "- kubectl-log: read{selector, namespace, tail?}, when{pattern(regex), "
    "expect(present|absent)} -- present fires when MISSING (a success signal gone), absent "
    "fires when it APPEARS.\n"
    "- docker-log: read{selector(a `docker ps` filter, e.g. name=web), tail?}, "
    "when{pattern, expect}.\n"
    "- ansible-service: read{selector(host pattern), service}, when{expect(active|inactive)}.\n"
    "- http (a SMOKE TEST -- the strongest 'is it working?' signal): read{url(http/https), "
    "method?(GET|HEAD)}, when{status?(expected, default 200), body?(regex that must be present)} "
    "-- fires on a wrong status, a missing body signal, or no response."
)


def add_check(raw: dict, checks_path: str = "") -> tuple[CustomCheck | None, str]:
    """Validate ``raw`` against the vetted schema and, if valid, store it in the wall's checks.json
    (replacing any check of the same name -- so re-defining one updates it). Returns (check, msg) on
    success or (None, why) when it doesn't validate. **The validation is the gate**: only a
    schema-valid check is ever written -- whoever authored it (a human, an agent) can't store code
    or an unvetted read."""
    check = parse_check(raw)
    if check is None:
        return None, f"that didn't validate -- a check must match the schema.\n{CHECK_SCHEMA_HINT}"
    path = Path(resolve_checks_path(checks_path))
    items: list = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text())
            items = loaded if isinstance(loaded, list) else []
        except (OSError, ValueError):
            items = []
    items = [it for it in items if not (isinstance(it, dict) and it.get("name") == check.name)]
    items.append(raw)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(items, indent=2))
    return (
        check,
        f"check '{check.name}' added [{check.kind}] -- runs on the next probe of this wall.",
    )


def describe_check(check: CustomCheck) -> str:
    """A one-line 'what it watches' for `checks` -- so an operator/agent reads back what's set."""
    if check.kind in _NUMERIC_KINDS:
        what = (
            f"{check.selector} {check.kind.removeprefix('kubectl-')} {check.op} {check.value:.0f}"
        )
    elif check.kind == "ansible-service":
        what = f"{check.service} {check.expect} on {check.selector}"
    else:  # log kinds
        what = f"/{check.pattern}/ {check.expect} in {check.selector}"
    return f"{check.name}  [{check.kind}]  {what} -> {check.severity.value}"


_DEFINE_SYSTEM = (
    "You translate an operator's request into ONE steadystate custom health-check, as JSON. Use a "
    "vetted read kind and only its fields; invent nothing outside the schema. Pick a short "
    "kebab-case name and a clear title. Reply with ONLY the JSON object.\n\n" + CHECK_SCHEMA_HINT
)


def define_check(text: str, complete: Callable[[str, str, str], str | None]) -> dict | None:
    """Translate a natural-language request into a check dict via the LLM seam (``complete``), or
    None when no model is configured / the reply has no JSON. It only *proposes* the JSON -- the
    caller runs it through :func:`add_check`, so the vetted-schema gate decides what's stored."""
    from ..reason.llm import _extract_json  # reuse the analyst's lenient JSON extraction

    reply = complete(_DEFINE_SYSTEM, text, "define-check")
    if not reply:
        return None
    data = _extract_json(reply)
    return data if isinstance(data, dict) else None


# -- the read: live CPU / memory of the matching pods (metrics API) -----------------------------


def _cpu_millicores(quantity: str) -> float | None:
    """Parse a k8s CPU quantity to millicores: ``123456n`` (nanocores), ``5m`` (millicores), ``2``
    (cores), ``500u`` (microcores). None on anything unparseable."""
    quantity = quantity.strip()
    try:
        if quantity.endswith("n"):
            return float(quantity[:-1]) / 1_000_000
        if quantity.endswith("u"):
            return float(quantity[:-1]) / 1_000
        if quantity.endswith("m"):
            return float(quantity[:-1])
        return float(quantity) * 1000
    except ValueError:
        return None


_MEM_UNITS = {"Ki": 1 / 1024, "Mi": 1.0, "Gi": 1024.0, "Ti": 1024.0 * 1024}


def _mem_mib(quantity: str) -> float | None:
    """Parse a k8s memory quantity to MiB: ``Ki``/``Mi``/``Gi``/``Ti`` suffixes, or bare bytes."""
    quantity = quantity.strip()
    for suffix, factor in _MEM_UNITS.items():
        if quantity.endswith(suffix):
            try:
                return float(quantity[:-2]) * factor
            except ValueError:
                return None
    try:
        return float(quantity) / (1024 * 1024)  # bare bytes
    except ValueError:
        return None


def _pod_values(payload: dict, kind: str) -> list[float]:
    """Per-pod CPU (millicores) or memory (MiB) from a PodMetrics list, summing each pod's
    containers. Skips a pod whose quantity won't parse rather than guessing."""
    parse = _cpu_millicores if kind == "kubectl-cpu" else _mem_mib
    field_name = "cpu" if kind == "kubectl-cpu" else "memory"
    values: list[float] = []
    for pod in payload.get("items", []):
        total = 0.0
        ok = False
        for container in pod.get("containers", []):
            raw = (container.get("usage") or {}).get(field_name)
            parsed = parse(raw) if isinstance(raw, str) else None
            if parsed is not None:
                total += parsed
                ok = True
        if ok:
            values.append(total)
    return values


def _aggregate(values: list[float], agg: str) -> float:
    if agg == "max":
        return max(values)
    if agg == "avg":
        return sum(values) / len(values)
    return sum(values)


class CustomCheckEvaluator:
    """Runs the wall's checks against one cluster -- a thin, read-only kubectl caller. Carries the
    ``use_context`` / ``use_kubeconfig`` seam the engine configures (so it aims at the target's
    cluster, exactly like the live source and the kubectl prober)."""

    def __init__(self, *, checks_path: str = DEFAULT_CHECKS_FILE, timeout: float = 10.0) -> None:
        self._checks_path = checks_path
        self._timeout = timeout
        self._context: str | None = None
        self._kubeconfig: str | None = None

    def use_context(self, context: str) -> None:
        self._context = context or None

    def use_kubeconfig(self, kubeconfig: str) -> None:
        self._kubeconfig = kubeconfig or None

    def _kubectl(self, *args: str) -> list[str]:
        argv = ["kubectl", *args]
        if self._context:
            argv += ["--context", self._context]
        if self._kubeconfig:
            argv += ["--kubeconfig", self._kubeconfig]
        return argv

    def _pod_metrics(self, namespace: str, selector: str) -> dict | None:
        """The metrics API's PodMetrics for the matching pods, or None when it can't be read (no
        metrics-server, unreachable cluster). None -> the check yields no finding (never a false
        alarm from a read we couldn't take)."""
        path = (
            f"/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods"
            f"?labelSelector={quote(selector, safe='')}"
        )
        try:
            done = subprocess.run(  # noqa: S603 -- argv list, no shell; read-only --raw GET
                self._kubectl("get", "--raw", path),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if done.returncode != 0:
            return None
        try:
            payload = json.loads(done.stdout)
        except ValueError:
            return None
        return payload if isinstance(payload, dict) else None

    def _pod_logs(self, namespace: str, selector: str, tail: int) -> str | None:
        """The recent logs (``--tail`` lines/pod, all containers) of the pods matching ``selector``,
        or None when they can't be read (unreachable, too many pods for one request). None -> the
        check yields no finding -- a *down* app is the generic prober's job; a log check answers
        'running but is it doing its work?'."""
        try:
            done = subprocess.run(  # noqa: S603 -- argv list, no shell; read-only `logs`
                self._kubectl(
                    "logs",
                    "-n",
                    namespace,
                    "-l",
                    selector,
                    f"--tail={tail}",
                    "--all-containers=true",
                    "--prefix=true",
                ),
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None

    def evaluate(self) -> list[Symptom]:
        """Read + check the kubectl-kind checks; emit a Symptom for each that fires. Read-only.
        (A docker/other-backend check in the same file is another reader's job -- skipped here.)"""
        symptoms: list[Symptom] = []
        for check in load_checks(self._checks_path):
            if check.kind not in _KUBECTL_KINDS:
                continue
            fired = (
                self._eval_log(check) if check.kind == "kubectl-log" else self._eval_numeric(check)
            )
            if fired is not None:
                symptoms.append(fired)
        return symptoms

    def _eval_numeric(self, check: CustomCheck) -> Symptom | None:
        payload = self._pod_metrics(check.namespace, check.selector)
        if payload is None:
            return None  # metrics unavailable -> no finding (never a false alarm)
        values = _pod_values(payload, check.kind)
        if not values:
            return None  # no matching pods / no parseable usage -> nothing to compare
        actual = _aggregate(values, check.agg)
        if not _fires(check.op, actual, check.value):
            return None
        detail = (
            f"{check.kind.removeprefix('kubectl-')} {actual:.0f}{check.unit[:1]} {check.op} "
            f"{check.value:.0f} ({check.agg} over {len(values)} pod(s) matching {check.selector})"
        )
        evidence = {
            "value": f"{actual:.1f} {check.unit}",
            "threshold": f"{check.op} {check.value:.0f}",
            EvidenceKeys.NAMESPACE: check.namespace,
            "selector": check.selector,
            "matched_pods": str(len(values)),
        }
        return _to_symptom(check, detail, evidence, self._context or "")

    def _eval_log(self, check: CustomCheck) -> Symptom | None:
        logs = self._pod_logs(check.namespace, check.selector, check.tail)
        return _log_symptom(check, logs, self._context or "")


# -- docker: the same log condition over a container's logs (functional health for compose) -----


class DockerCheckEvaluator:
    """Runs the wall's ``docker-log`` checks against the local docker engine -- a thin, read-only
    ``docker`` caller. No context/kubeconfig (docker is the host's engine); the check's ``selector``
    is a ``docker ps --filter`` expression (e.g. ``name=mailer`` or
    ``label=com.docker.compose.service=mailer``). Same condition + Symptom shape as kubectl-log."""

    def __init__(self, *, checks_path: str = DEFAULT_CHECKS_FILE, timeout: float = 10.0) -> None:
        self._checks_path = checks_path
        self._timeout = timeout

    def evaluate(self) -> list[Symptom]:
        symptoms: list[Symptom] = []
        for check in load_checks(self._checks_path):
            if check.kind != "docker-log":
                continue
            logs = self._container_logs(check.selector, check.tail)
            fired = _log_symptom(check, logs, "")
            if fired is not None:
                symptoms.append(fired)
        return symptoms

    def _container_logs(self, selector: str, tail: int) -> str | None:
        """The recent logs of the containers matching the ``docker ps --filter`` ``selector``, or
        None when docker can't be reached. No matching containers -> '' (a present-check then fires
        'not working', the right read of a service that isn't there)."""
        ids = self._containers(selector)
        if ids is None:
            return None
        chunks: list[str] = []
        for cid in ids:
            out = self._run("logs", "--tail", str(tail), cid)
            if out is None:
                return None
            chunks.append(out)
        return "\n".join(chunks)

    def _containers(self, selector: str) -> list[str] | None:
        out = self._run("ps", "--filter", selector, "--format", "json")
        if out is None:
            return None
        ids: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            cid = entry.get("ID") or entry.get("Names") if isinstance(entry, dict) else None
            if cid:
                ids.append(str(cid))
        return ids

    def _run(self, *args: str) -> str | None:
        try:
            done = subprocess.run(  # noqa: S603 -- argv list, no shell; read-only docker ps/logs
                ["docker", *args],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout if done.returncode == 0 else None


# -- ansible: is a host/VM service in the expected state across a host pattern? ------------------


class AnsibleCheckEvaluator:
    """Runs the wall's ``ansible-service`` checks: is a unit ``active`` (or ``inactive``) across the
    hosts matching a pattern? It runs ONLY the vetted, read-only ``service_facts`` gather (no
    operator-supplied command -- that would be code execution, which the schema forbids). The
    check's ``selector`` is an ansible host pattern, ``service`` the unit name. Same Symptom shape
    as every other kind, so it rides the pipeline."""

    def __init__(
        self, *, checks_path: str = DEFAULT_CHECKS_FILE, inventory: str = "", timeout: float = 30.0
    ) -> None:
        self._checks_path = checks_path
        self._inventory = inventory
        self._timeout = timeout

    def evaluate(self) -> list[Symptom]:
        symptoms: list[Symptom] = []
        for check in load_checks(self._checks_path):
            if check.kind != "ansible-service":
                continue
            by_host = self._service_states(check.selector)
            if not by_host:  # ansible unavailable / no hosts matched -> no finding
                continue
            want_running = check.expect == "active"
            bad = [
                host
                for host in sorted(by_host)
                if (_service_running(by_host[host], check.service)) != want_running
            ]
            if bad:
                detail = (
                    f"{check.service} not {check.expect} on {len(bad)}/{len(by_host)} host(s): "
                    f"{', '.join(bad[:8])}"
                )
                evidence = {
                    "service": check.service,
                    "expect": check.expect,
                    "host_pattern": check.selector,
                    "affected": str(len(bad)),
                }
                symptoms.append(_to_symptom(check, detail, evidence, ""))
        return symptoms

    def _service_states(self, pattern: str) -> dict[str, dict] | None:
        """``{host: {service: {state, status}}}`` from a read-only ``service_facts`` gather over the
        host pattern, or None when ansible can't run / parse (-> no finding)."""
        if shutil.which("ansible") is None:
            return None
        argv = ["ansible", pattern, "-m", "service_facts"]
        if self._inventory:
            argv += ["-i", self._inventory]
        env = {
            **os.environ,
            "ANSIBLE_STDOUT_CALLBACK": "json",
            "ANSIBLE_LOAD_CALLBACK_PLUGINS": "true",
        }
        try:
            done = subprocess.run(  # noqa: S603 -- argv list, no shell; read-only service_facts
                argv, capture_output=True, text=True, timeout=self._timeout, env=env, check=False
            )
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            return _services_by_host(json.loads(done.stdout))
        except ValueError:
            return None


def _service_running(services: dict, name: str) -> bool:
    """Whether unit ``name`` is in a running state on a host. Tries the bare name and the common
    ``<name>.service`` form; a unit not present at all is 'not running'."""
    info = services.get(name) or services.get(f"{name}.service")
    if not isinstance(info, dict):
        return False
    return str(info.get("state") or "").lower() in _RUNNING_STATES


# -- http: the SMOKE TEST -- exercise an endpoint and assert the response ------------------------


class HttpCheckEvaluator:
    """Runs the wall's ``http`` smoke tests: GET/HEAD an endpoint and assert the response (an
    expected status, optionally a body regex). The strongest "is it doing its job?" signal -- it
    *exercises* the service rather than inferring from logs/status. A wrong status, a missing body
    signal, OR an unreachable endpoint all FIRE -- a smoke test that can't reach the service IS the
    service being down (the opposite of the passive kinds, where an unreadable signal is a no-op).
    Read-only: GET/HEAD only. A failed smoke test rides the pipeline as a Symptom (-> IMPAIRED)."""

    def __init__(self, *, checks_path: str = DEFAULT_CHECKS_FILE, timeout: float = 10.0) -> None:
        self._checks_path = checks_path
        self._timeout = timeout

    def evaluate(self) -> list[Symptom]:
        """The pipeline view: a Symptom for each FAILED smoke test (a passing one is silent)."""
        return [
            _to_symptom(check, detail, ev, "") for check, ok, detail, ev in self._run() if not ok
        ]

    def results(self) -> list[CheckResult]:
        """The affirmative view: PASS *and* FAIL for every smoke test -- so `smoke` can show that
        the gateway is *working*, not just the absence of a failure. The close-the-loop verdict."""
        return [
            CheckResult(
                name=check.name, kind=check.kind, passed=ok, detail=detail, target=check.url
            )
            for check, ok, detail, _ev in self._run()
        ]

    def _run(self) -> list[tuple[CustomCheck, bool, str, dict[str, str]]]:
        out: list[tuple[CustomCheck, bool, str, dict[str, str]]] = []
        for check in load_checks(self._checks_path):
            if check.kind != "http":
                continue
            ok, detail, evidence = self._request(check)
            out.append((check, ok, detail, evidence))
        return out

    def _request(self, check: CustomCheck) -> tuple[bool, str, dict[str, str]]:
        """GET/HEAD the URL and judge the response: (ok, detail, evidence). A connection failure or
        timeout is a FAILED smoke test (the service didn't answer), never a no-op."""
        ev = {"url": check.url, "method": check.method, "expected_status": str(check.status)}
        req = urllib.request.Request(check.url, method=check.method)
        try:
            with safe_urlopen(req, timeout=self._timeout) as resp:  # http(s)-gated open
                status = resp.status
                payload = resp.read(65536).decode("utf-8", "replace") if check.body else ""
        except urllib.error.HTTPError as exc:  # a 4xx/5xx still carries a status to compare
            status = exc.code
            payload = exc.read(65536).decode("utf-8", "replace") if check.body else ""
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return False, f"{check.url} did not respond ({exc})", {**ev, "error": str(exc)[:200]}
        ev["status"] = str(status)
        if status != check.status:
            return False, f"{check.url} returned {status} (expected {check.status})", ev
        if check.body and re.search(check.body, payload) is None:
            return False, f"{check.url} answered {status} but body missing /{check.body}/", ev
        return True, "", ev


def _log_symptom(check: CustomCheck, logs: str | None, context: str) -> Symptom | None:
    """The condition shared by every log kind: ``expect=present`` fires when the pattern is MISSING
    (a success signal that's gone), ``expect=absent`` fires when it's FOUND (an error appeared). A
    read we couldn't take (``logs is None``) -> no finding. Backend-neutral -- the caller fetched
    the logs (kubectl or docker); this just decides + builds the Symptom."""
    if logs is None:
        return None
    found = re.search(check.pattern, logs) is not None
    if found != (check.expect == "absent"):
        return None
    state = "present" if found else "absent"
    detail = f"logs of {check.selector}: /{check.pattern}/ {state} (expected {check.expect})"
    evidence = {
        "pattern": check.pattern,
        "expect": check.expect,
        "found": str(found),
        "selector": check.selector,
    }
    if check.namespace:
        evidence[EvidenceKeys.NAMESPACE] = check.namespace
    return _to_symptom(check, detail, evidence, context)


def _fires(op: str, actual: float, threshold: float) -> bool:
    return {
        "<": actual < threshold,
        ">": actual > threshold,
        "<=": actual <= threshold,
        ">=": actual >= threshold,
        "==": actual == threshold,
        "!=": actual != threshold,
    }[op]


def _to_symptom(check: CustomCheck, detail: str, evidence: dict[str, str], context: str) -> Symptom:
    """Turn a fired check into a Symptom -- same shape every prober emits, so it rides the pipeline
    (tracked new/recurring/resolved, muteable, feeds resolve/learn). ``category`` is the check name,
    so its fingerprint is stable across scans. No ``recommended_action``: a check observes, it
    doesn't fix (acting on it still goes through the catalog + bound)."""
    scope = "/".join(part for part in (context, "custom", check.namespace, check.name) if part)
    return Symptom(
        identity=scope,
        kind="CustomCheck",
        category=check.name,
        severity=check.severity,
        title=check.title,
        detail=detail,
        provenance=Provenance(source="custom-check", address=check.name),
        evidence=evidence,
    )


def evaluate_custom_checks(
    context: str = "",
    kubeconfig: str = "",
    inventory: str = "",
    *,
    checks_path: str = "",
) -> list[Symptom]:
    """The engine entry point: evaluate the checks (from ``resolve_checks_path`` --
    ``STEADYSTATE_CHECKS`` or the default), returning the Symptoms that fired. Each check is
    dispatched to the reader for its backend (``kubectl-*`` -> the cluster; ``docker-*`` -> the
    local docker engine; ``ansible-*`` -> the inventory), so one file can mix them and each runs
    where it makes sense. [] when there's no checks file (the common case). Read-only throughout."""
    checks_path = resolve_checks_path(checks_path)
    checks = load_checks(checks_path)
    if not checks:
        return []
    symptoms: list[Symptom] = []
    if any(c.kind in _KUBECTL_KINDS for c in checks):
        kube = CustomCheckEvaluator(checks_path=checks_path)
        kube.use_context(context)
        kube.use_kubeconfig(kubeconfig)
        symptoms += kube.evaluate()
    if any(c.kind == "docker-log" for c in checks):
        symptoms += DockerCheckEvaluator(checks_path=checks_path).evaluate()
    if any(c.kind in _ANSIBLE_KINDS for c in checks):
        symptoms += AnsibleCheckEvaluator(checks_path=checks_path, inventory=inventory).evaluate()
    if any(c.kind in _HTTP_KINDS for c in checks):
        symptoms += HttpCheckEvaluator(checks_path=checks_path).evaluate()
    return symptoms


def run_smoke_checks(checks_path: str = "", match: str = "") -> list[CheckResult]:
    """Run the wall's ``http`` smoke tests live and return each one's PASS/FAIL -- the affirmative
    'is it working?' view (a passing test is *shown*, not just silent). [] when none are defined.
    ``match`` (when set) runs only the smoke tests naming it (in the check name or URL) -- so
    scoping to a workload doesn't fire unrelated probes. Read-only (GET/HEAD). Backs smoke."""
    results = HttpCheckEvaluator(checks_path=resolve_checks_path(checks_path)).results()
    if not match:
        return results
    m = match.lower()
    return [r for r in results if m in r.name.lower() or m in r.target.lower()]
