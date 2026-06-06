"""User-defined, per-wall health checks -- a DECLARATIVE rule (a vetted read + a condition) the
operator (or an agent, via a future ``define-check``) stores in the wall's
``.steadystate/checks.json``, which steadystate evaluates DETERMINISTICALLY into a Symptom. It never
executes operator-supplied code.

The safety model mirrors the action catalog: WHAT to check is data (a schema of vetted, read-only
reads); the reading and comparing are steadystate's. A check can only ever OBSERVE -- emit a finding
-- never act; acting on what it finds still passes the bound + catalog. So a wrong check is *noise*
(a mutable finding), never damage. Per-wall by construction: the checks live in the wall's
``.steadystate/``, so different cluster-sets carry different rules for free, no cross-wall reach.

Read kinds: ``kubectl-cpu`` / ``kubectl-mem`` -- the live CPU/memory of the pods matching a label
selector (metrics API), aggregated and compared to a threshold; and ``kubectl-log`` -- a regex that
should be *present* (a success signal, e.g. postfix's ``status=sent``) or *absent* (an error) in the
pods' recent logs, i.e. "running, but doing its job?". A read we couldn't take -> no finding (never
a false alarm; a *down* app is the generic prober's call). The Symptoms ride the normal pipeline, so
a custom finding is tracked new/recurring/resolved, muteable, and feeds ``resolve``/``learn``."""

from __future__ import annotations

import json
import re
import subprocess  # noqa: S404 -- argv only, no shell; reads only
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from ..model import Provenance
from ..reason.alert import Severity
from .base import Symptom

DEFAULT_CHECKS_FILE = ".steadystate/checks.json"

_NUMERIC_KINDS = frozenset({"kubectl-cpu", "kubectl-mem"})  # a threshold over an aggregated value
_LOG_KIND = (
    "kubectl-log"  # a pattern that should/shouldn't be in the pods' logs (functional health)
)
_ALL_KINDS = _NUMERIC_KINDS | {_LOG_KIND}
_OPS = frozenset({"<", ">", "<=", ">=", "==", "!="})
_AGGS = frozenset({"sum", "max", "avg"})
_EXPECT = frozenset({"present", "absent"})
_SEVERITIES = {s.value: s for s in Severity}


@dataclass(frozen=True)
class CustomCheck:
    """One declarative check: a vetted read, a condition, and the finding to emit when it holds.
    Parsed + validated from a JSON object; an invalid one is dropped (so a single typo never sinks
    the rest). Pure data -- no code, no command, nothing to execute. The numeric fields (op/value/
    agg) apply to ``kubectl-cpu``/``kubectl-mem``; the log fields (pattern/expect/tail) apply to
    ``kubectl-log`` -- ``parse_check`` fills whichever the kind uses."""

    name: str
    kind: str  # read kind: kubectl-cpu | kubectl-mem | kubectl-log
    selector: str  # a label selector, e.g. "app=postfix"
    namespace: str
    severity: Severity
    title: str
    # numeric (kubectl-cpu / kubectl-mem): a threshold over the aggregated value
    op: str = ""  # < > <= >= == !=
    value: float = 0.0  # CPU in millicores; memory in MiB
    agg: str = "sum"  # combine the matching pods' values: sum | max | avg
    # log (kubectl-log): a pattern that should be present (a success signal) or absent (an error)
    pattern: str = ""  # a regex searched across the pods' recent logs
    expect: str = ""  # present -> fire when MISSING; absent -> fire when FOUND
    tail: int = 200  # lines of recent log per pod to read

    @property
    def unit(self) -> str:
        return "millicores" if self.kind == "kubectl-cpu" else "MiB"


def parse_check(raw: dict) -> CustomCheck | None:
    """Build a :class:`CustomCheck` from one JSON object, or None if it's malformed / uses a read
    kind or operator outside the vetted set. The validation IS the safety boundary on the schema."""
    if not isinstance(raw, dict):
        return None
    read, when, emit = raw.get("read") or {}, raw.get("when") or {}, raw.get("emit") or {}
    name = raw.get("name")
    kind, selector, namespace = read.get("kind"), read.get("selector"), read.get("namespace")
    severity, title = emit.get("severity"), emit.get("title")
    if not (isinstance(name, str) and name):
        return None
    if kind not in _ALL_KINDS or not isinstance(selector, str) or not selector:
        return None
    if not isinstance(namespace, str) or not namespace:
        return None
    if severity not in _SEVERITIES or not isinstance(title, str) or not title:
        return None
    common = {
        "name": name,
        "kind": kind,
        "selector": selector,
        "namespace": namespace,
        "severity": _SEVERITIES[severity],
        "title": title,
    }
    if kind in _NUMERIC_KINDS:
        agg, op, value = read.get("agg", "sum"), when.get("op"), when.get("value")
        if agg not in _AGGS or op not in _OPS:
            return None
        if not isinstance(value, int | float) or isinstance(value, bool):
            return None
        return CustomCheck(**common, op=op, value=float(value), agg=agg)
    # kubectl-log: a pattern (regex) that should be present or absent in the pods' recent logs.
    pattern, expect, tail = when.get("pattern"), when.get("expect"), read.get("tail", 200)
    if not isinstance(pattern, str) or not pattern or expect not in _EXPECT:
        return None
    if not isinstance(tail, int) or isinstance(tail, bool) or tail <= 0:
        return None
    try:
        re.compile(pattern)  # a check with a broken regex is dropped, not stored
    except re.error:
        return None
    return CustomCheck(**common, pattern=pattern, expect=expect, tail=tail)


def load_checks(path: str = DEFAULT_CHECKS_FILE) -> list[CustomCheck]:
    """The wall's valid checks (``.steadystate/checks.json``: a JSON list of check objects). '' /
    missing / malformed file -> [] (the un-checked path is unchanged). Invalid entries are skipped,
    valid ones kept -- one bad rule never disables the others."""
    if not path or not Path(path).exists():
        return []
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [check for item in raw if (check := parse_check(item)) is not None]


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
        """Read + check every loaded check; emit a Symptom for each that fires. Read-only."""
        symptoms: list[Symptom] = []
        for check in load_checks(self._checks_path):
            fired = self._eval_log(check) if check.kind == _LOG_KIND else self._eval_numeric(check)
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
            "namespace": check.namespace,
            "selector": check.selector,
            "matched_pods": str(len(values)),
        }
        return _to_symptom(check, detail, evidence, self._context or "")

    def _eval_log(self, check: CustomCheck) -> Symptom | None:
        logs = self._pod_logs(check.namespace, check.selector, check.tail)
        if logs is None:
            return None  # couldn't read logs -> no finding
        found = re.search(check.pattern, logs) is not None
        # expect=present -> fire when the success signal is MISSING; expect=absent -> when found
        if found != (check.expect == "absent"):
            return None
        state = "present" if found else "absent"
        detail = (
            f"logs of {check.selector} in {check.namespace}: /{check.pattern}/ {state} "
            f"(expected {check.expect})"
        )
        evidence = {
            "pattern": check.pattern,
            "expect": check.expect,
            "found": str(found),
            "namespace": check.namespace,
            "selector": check.selector,
        }
        return _to_symptom(check, detail, evidence, self._context or "")


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
    ctx = f"{context}/" if context else ""
    return Symptom(
        identity=f"{ctx}custom/{check.namespace}/{check.name}",
        kind="CustomCheck",
        category=check.name,
        severity=check.severity,
        title=check.title,
        detail=detail,
        provenance=Provenance(source="custom-check", address=check.name),
        evidence=evidence,
    )


def evaluate_custom_checks(
    context: str = "", kubeconfig: str = "", *, checks_path: str = DEFAULT_CHECKS_FILE
) -> list[Symptom]:
    """The engine entry point: evaluate the wall's checks against the target cluster, returning the
    Symptoms that fired. [] when there's no checks file (the common case) -- so it's a cheap no-op
    on a wall that hasn't defined any. Read-only throughout."""
    if not load_checks(checks_path):
        return []
    evaluator = CustomCheckEvaluator(checks_path=checks_path)
    evaluator.use_context(context)
    evaluator.use_kubeconfig(kubeconfig)
    return evaluator.evaluate()
