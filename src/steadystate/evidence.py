"""The cross-module contract for the keys inside ``Finding.details`` / ``Symptom.evidence``.

A finding is persisted as ``details: dict[str, str]`` (a JSON blob in SQLite), and a growing
amount of behaviour is keyed off particular entries: the drift-vs-symptom discriminator
(``change``), the fields that compose a remediation command
(``cluster``/``kind``/``workload``/``node``/``namespace``), the ``category`` a reflex or solution
matches on. Those keys are *written* by the probes and the reconciler and *read* in
server/act/health/classify/analyze -- a cross-module schema that was, until now, bare string
literals in a dozen files, where one typo on either side fails silently.

``EvidenceKeys`` pins that schema in one place. The string VALUES are unchanged -- they are
persisted, so they must be -- this is pure indirection: producers and consumers reference the same
name, so a rename is one line and a typo is an ``AttributeError``, not a silent miss. Probe-LOCAL
evidence (display-only fields a single probe writes and nothing reads cross-module --
``unhealthy_pods``, ``disk_percent``, ...) stays a bare literal: it isn't a contract, and
centralising it would add noise. This deliberately does NOT cover the ``checks.json`` check-spec
schema (``selector``/``op``/...), which is a separate, user-facing contract."""

from __future__ import annotations

from typing import Final


class EvidenceKeys:
    """Keys in ``Finding.details`` / ``Symptom.evidence`` that cross a module boundary."""

    CATEGORY: Final = "category"  # the malfunction class a reflex/solution matches on
    WORKLOAD: Final = "workload"  # workload name -- command composition, identity, platform layer
    NAMESPACE: Final = "namespace"  # k8s namespace -- command composition, platform layer
    CLUSTER: Final = "cluster"  # the context -- resolves the target's kubeconfig
    KIND: Final = "kind"  # resource kind -- command composition
    NODE: Final = "node"  # node name -- node-scoped command composition
    CHANGE: Final = "change"  # a drift's change type; its PRESENCE marks drift vs live symptom
    LAST_LOG: Final = "last_log"  # the failing pod's last log line -- RCA evidence
    TRACE: Final = "trace"  # captured stack trace, rendered last by `analyze`
    SAMPLE: Final = "sample"  # sample error lines -- RCA evidence
    CORRELATED: Final = "correlated"  # group-scope marker on a correlation fingerprint
