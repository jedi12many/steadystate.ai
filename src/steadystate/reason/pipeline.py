"""The reasoning pipeline: drift -> Signal/Event -> (LLM correlation) -> Alerts.

Every drift is scored deterministically and filtered by a Brain-Tuning bar into a
Signal (counted firehose) or an Event. The Events are handed to the LLM correlator
in one batch; it groups them by root cause, and each group becomes an Alert -- which
is why several signals from different sources (a node out of storage) can fold into
one Alert. The correlator is a registered plugin seam (auto | llm | deterministic, plus
any out-of-tree correlator); without a model it degrades honestly to deterministic
grouping by shared attribute (reason/correlate.py) -- shared-file / shared-namespace
Events still fold into one Alert, not singleton noise.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from ..act.plan import RemediationPlan, assess
from ..domains import default_domains
from ..domains.base import Domain, PolicyFinding, Reference, evaluate_with, references_for
from ..model import ChangeType, Drift, Resource
from ..plugins import merged
from .alert import Alert, Layer, Severity
from .correlate import Cluster, Correlator, DeterministicCorrelator, LLMCorrelator
from .llm import LLMAnalyst
from .report import Report, Tuning, classify

if TYPE_CHECKING:  # observe.base imports Severity from .alert; guard to avoid the import cycle
    from ..observe.base import Symptom

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def _workload_name(identity: str) -> str:
    """The bare workload/resource name -- the last `/`- or `.`-segment
    (``prod-cluster/apps/Deployment/team-a/squid`` -> ``squid``). Pure."""
    return identity.rsplit("/", 1)[-1].rsplit(".", 1)[-1]


def _place(identity: str) -> str:
    """The namespace a workload lives in -- the second-to-last `/`-segment -- for naming where a
    grouped symptom occurs (``.../team-a/squid`` -> ``team-a``), else the identity. Pure."""
    parts = identity.split("/")
    return parts[-2] if len(parts) >= 2 else identity


# An Event awaiting correlation: the drift, its deterministic score, the domain that
# raised it (if any), and that domain's framework references for the drift (if any).
_Event = tuple[Drift, Severity, "str | None", "list[Reference]"]

# The correlator plugin registry: name -> factory(analyst) -> Correlator. Mirrors
# DRIFT_SOURCES (sources/__init__.py) and SURFACES (notify/__init__.py): a new in-tree
# correlator is one line in _BUILTIN_CORRELATORS, and an out-of-tree one is a
# `steadystate.correlators` entry point overlaid by merged() (built-ins win a clash).
# "auto" is resolved in build_correlator, not registered as a name.
_BUILTIN_CORRELATORS: dict[str, Callable[[LLMAnalyst], Correlator]] = {
    "deterministic": lambda _analyst: DeterministicCorrelator(),
    "llm": lambda analyst: LLMCorrelator(analyst),
}

CORRELATORS: dict[str, Callable[[LLMAnalyst], Correlator]] = merged(
    "correlators", _BUILTIN_CORRELATORS
)


def build_correlator(mode: str, analyst: LLMAnalyst) -> Correlator:
    """Construct the Correlator for ``mode`` (a registry name or ``auto``), or raise.

    - ``auto`` (default): the LLM correlator when a provider is configured, else the
      deterministic correlator with no model call attempted.
    - any registered name (``deterministic`` | ``llm`` | an out-of-tree correlator):
      that correlator.
    - anything else: ValueError, the way build_drift_source/build_surfaces reject
      unknown names (the CLI turns it into a clean typer.BadParameter).
    """
    if mode == "auto":
        if analyst._provider() != "none":
            return LLMCorrelator(analyst)
        return DeterministicCorrelator()
    try:
        factory = CORRELATORS[mode]
    except KeyError:
        known = ", ".join(sorted(CORRELATORS))
        raise ValueError(f"unknown correlator '{mode}' (known: auto, {known})") from None
    return factory(analyst)


def select_correlator(mode: str, analyst: LLMAnalyst) -> Correlator:
    """Back-compat thin wrapper over build_correlator (kept for existing callers)."""
    return build_correlator(mode, analyst)


def baseline_severity(drift: Drift) -> Severity:
    """Deterministic floor, before any domain pack weighs in."""
    if not drift.actionable:
        # Reality moved but config doesn't assert it (no plan to reconcile): informational,
        # so it stays a counted Signal by default rather than paging. A domain pack can still
        # raise it (e.g. a bucket gone public is CRITICAL no matter how it was detected).
        return Severity.LOW
    if drift.change_type is ChangeType.REMOVED:
        return Severity.HIGH  # something we declared is gone from reality
    if drift.change_type is ChangeType.MODIFIED:
        return Severity.MEDIUM
    return Severity.LOW


def _action_from_plan(plan: RemediationPlan) -> str:
    if plan.eligible:
        return f"Reconcile to declared state: {' '.join(plan.command)} ({plan.blast_radius})"
    return f"Manual review required: {plan.reason}"


class Pipeline:
    def __init__(
        self,
        analyst: LLMAnalyst | None = None,
        domains: list[Domain] | None = None,
        tuning: Tuning = Tuning.DEFAULT,
        correlator: Correlator | str | None = None,
    ) -> None:
        self.analyst = analyst or LLMAnalyst()
        self.domains = domains if domains is not None else default_domains()
        self.tuning = tuning
        # correlator: a mode string ("auto"|"llm"|"deterministic"|an out-of-tree name),
        # an explicit Correlator instance, or None -> the LLM correlator over our analyst
        # (back-compat default: same behaviour as the old analyst.correlate -- it degrades
        # honestly to deterministic grouping when no provider is configured).
        if correlator is None:
            self.correlator: Correlator = LLMCorrelator(self.analyst)
        elif isinstance(correlator, str):
            self.correlator = build_correlator(correlator, self.analyst)
        else:
            self.correlator = correlator

    def _score(self, drift: Drift) -> tuple[Severity, str | None, list[Reference]]:
        """Deterministic severity, which domain pack (if any) raised it, and that pack's
        framework references for the drift -- picked from the SAME domain, at the same
        point, so severity and references can never come from different packs or disagree.
        """
        severity = baseline_severity(drift)
        flagged_by: str | None = None
        references: list[Reference] = []
        for domain in self.domains:
            scored = domain.score(drift)
            if scored is not None and _SEVERITY_RANK[scored] > _SEVERITY_RANK[severity]:
                severity = scored
                flagged_by = domain.name
                references = references_for(domain, drift)
        return severity, flagged_by, references

    def _signal(
        self,
        drift: Drift,
        severity: Severity,
        flagged_by: str | None,
        references: list[Reference],
    ) -> Alert:
        # Below the Event bar: the counted firehose, never analyzed.
        return Alert(
            title=drift.summary(),
            severity=severity,
            drifts=[drift],
            why_it_matters=f"{drift.summary()}: declared and observed state diverge.",
            layer=Layer.SIGNAL,
            recommended_action=None,
            llm_backed=False,
            flagged_by=flagged_by,
            references=references,
        )

    def _alert_from_cluster(self, cluster: Cluster, events: list[_Event]) -> Alert:
        members = [events[i] for i in cluster.drift_indexes]
        drifts = [m[0] for m in members]
        severity = max((m[1] for m in members), key=lambda s: _SEVERITY_RANK[s])
        flagged_by = next((m[2] for m in members if m[2] is not None), None)
        # References ride with the flagging member, mirroring flagged_by: take the first
        # member that contributed any (none when no pack mapped the cluster's drift).
        references = next((m[3] for m in members if m[3]), [])
        action = cluster.recommended_action
        # A single *actionable* Terraform Event with no model-suggested action -> the
        # executor's plan. A non-actionable drift has no reconciliation, so we don't offer
        # a "terraform apply" that would be a no-op.
        if action is None and len(drifts) == 1:
            only = drifts[0]
            if only.provenance.source == "terraform" and only.actionable:
                action = _action_from_plan(assess(only))
        return Alert(
            title=cluster.title,
            severity=severity,
            drifts=drifts,
            why_it_matters=cluster.why_it_matters,
            layer=Layer.ALERT,
            recommended_action=action,
            llm_backed=cluster.llm_backed,
            flagged_by=flagged_by,
            references=references,
        )

    def _alert_from_finding(self, finding: PolicyFinding, flagged_by: str, layer: Layer) -> Alert:
        """Turn a standing-policy violation into an Alert (or, below the bar, a Signal).

        No drift, so ``drifts`` is empty and the finding rides in ``findings`` -- that's what
        carries the fingerprint reconciliation keys memory on and the detail the surfaces
        render. Not correlated in v1: posture violations are independent, not root-cause-linked.
        """
        return Alert(
            title=finding.title,
            severity=finding.severity,
            drifts=[],
            why_it_matters=finding.detail,
            layer=layer,
            recommended_action=None,
            llm_backed=False,
            flagged_by=flagged_by,
            references=list(finding.references),
            findings=[finding],
        )

    def _alert_from_symptom(self, symptom: Symptom, layer: Layer) -> Alert:
        """Turn an operational malfunction into an Alert (or, below the bar, a Signal). No drift,
        so ``drifts`` is empty and the symptom rides in ``symptoms`` -- which carries the
        fingerprint memory keys on and the evidence the surfaces render. A standalone symptom
        unless `_diagnose` later folds it into a co-located drift's Alert."""
        return Alert(
            title=symptom.title,
            severity=symptom.severity,
            drifts=[],
            why_it_matters=symptom.detail,
            layer=layer,
            recommended_action=None,
            llm_backed=False,
            flagged_by=symptom.provenance.source,
            symptoms=[symptom],
        )

    def _diagnose(self, drift_alerts: list[Alert], symptom_alerts: list[Alert]) -> list[Alert]:
        """Cross-type correlation -- the headline. A Symptom on a resource that ALSO has a Drift
        is the same incident: the drift is the likely root cause of the malfunction. Fold such a
        symptom INTO the drift's Alert (which already carries the fix -- reconcile the drift),
        raising its severity and reframing it as a diagnosis. Returns the symptom Alerts that
        stood alone (no co-located drift) to surface on their own."""
        by_identity: dict[str, Alert] = {}
        for alert in drift_alerts:
            for drift in alert.drifts:
                by_identity.setdefault(drift.identity, alert)

        standalone: list[Alert] = []
        for symptom_alert in symptom_alerts:
            symptom = symptom_alert.symptoms[0]
            host = by_identity.get(symptom.identity)
            if host is None:
                standalone.append(symptom_alert)
                continue
            host.symptoms.append(symptom)
            if _SEVERITY_RANK[symptom.severity] > _SEVERITY_RANK[host.severity]:
                host.severity = symptom.severity
            name = symptom.identity.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
            host.title = f"{name} is failing -- likely root cause: drift"
            host.why_it_matters = (
                f"{host.why_it_matters}  Operational impact: {symptom.detail} "
                f"-- likely root cause: {host.drifts[0].summary()}."
            )
        return standalone

    def _group_symptoms(self, symptom_alerts: list[Alert]) -> list[Alert]:
        """Fold standalone symptom Alerts that share ``(kind, workload name, category)`` into ONE
        Alert -- the same app failing the same way across namespaces (or the landscape) is one issue
        to handle, not N. Each instance's Symptom rides along (so memory/mute still track per
        instance and you can see which recovered); the merged Alert names how many and where.
        Mechanical, like the deterministic correlator -- it groups by a shared attribute, it doesn't
        claim a reasoned root cause. Order-stable (first-seen group order)."""
        groups: dict[tuple[str, str, str], list[Alert]] = {}
        order: list[tuple[str, str, str]] = []
        for alert in symptom_alerts:
            symptom = alert.symptoms[0]
            key = (symptom.kind, _workload_name(symptom.identity), symptom.category)
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(alert)
        out: list[Alert] = []
        for key in order:
            members = groups[key]
            out.append(members[0] if len(members) == 1 else self._merge_symptoms(key, members))
        return out

    def _merge_symptoms(self, key: tuple[str, str, str], members: list[Alert]) -> Alert:
        """One Alert for a group of same-(kind, name, category) symptom Alerts across places."""
        kind, name, category = key
        symptoms = [m.symptoms[0] for m in members]
        severity = max((s.severity for s in symptoms), key=lambda sv: _SEVERITY_RANK[sv])
        places = sorted({_place(s.identity) for s in symptoms})
        shown = ", ".join(places[:8]) + (f" (+{len(places) - 8} more)" if len(places) > 8 else "")
        return Alert(
            title=f"{name} is {category} in {len(places)} place(s)",
            severity=severity,
            drifts=[],
            why_it_matters=(
                f"{len(symptoms)} instances of {kind} {name} are {category} across: {shown}. "
                "Likely one root cause (e.g. a shared image/config) -- grouped mechanically by "
                "name + symptom, so handle it once."
            ),
            layer=Layer.ALERT,
            recommended_action=None,
            llm_backed=False,
            flagged_by=symptoms[0].provenance.source,
            symptoms=symptoms,
        )

    def run(
        self,
        drifts: list[Drift],
        resources: list[Resource] | None = None,
        symptoms: list[Symptom] | None = None,
    ) -> Report:
        """Reason about ``drifts``; the declared ``resources`` posture (standing-policy pass); and
        any operational ``symptoms`` a prober found. Both extra inputs default to None so the
        stateless drift path is byte-for-byte unchanged. A Symptom co-located with a Drift folds
        into one diagnosis Alert (`_diagnose`); the rest stand alone -- the same Signal/Event/Alert
        machinery for all three departure types."""
        signals: list[Alert] = []
        events: list[_Event] = []
        for drift in drifts:
            severity, flagged_by, references = self._score(drift)
            if classify(severity, self.tuning) is Layer.SIGNAL:
                signals.append(self._signal(drift, severity, flagged_by, references))
            else:
                events.append((drift, severity, flagged_by, references))
        clusters = self.correlator.correlate([event[0] for event in events])
        drift_alerts = [self._alert_from_cluster(cluster, events) for cluster in clusters]

        # Standing-policy pass over the declared baseline (CIS/STIG): each domain that
        # implements evaluate() generates findings the same Brain-Tuning bar sorts into
        # Signals (counted) or surfaced Alerts. Independent of the drift path above.
        policy_alerts: list[Alert] = []
        for domain in self.domains:
            for finding in evaluate_with(domain, resources or []):
                below_bar = classify(finding.severity, self.tuning) is Layer.SIGNAL
                layer = Layer.SIGNAL if below_bar else Layer.ALERT
                alert = self._alert_from_finding(finding, domain.name, layer)
                (signals if below_bar else policy_alerts).append(alert)

        # Operational pass: a prober's Symptoms sort by the same bar. A surfaced symptom on a
        # drifted resource diagnoses into that drift's Alert; the rest stand alone.
        symptom_alerts: list[Alert] = []
        for symptom in symptoms or []:
            below_bar = classify(symptom.severity, self.tuning) is Layer.SIGNAL
            layer = Layer.SIGNAL if below_bar else Layer.ALERT
            alert = self._alert_from_symptom(symptom, layer)
            (signals if below_bar else symptom_alerts).append(alert)
        standalone_symptoms = self._diagnose(drift_alerts, symptom_alerts)
        # The same workload failing the same way across namespaces folds into one Alert -- so a bad
        # image crashlooping every team's `squid` is one issue to handle, not one per namespace.
        standalone_symptoms = self._group_symptoms(standalone_symptoms)

        return Report(
            items=signals + drift_alerts + policy_alerts + standalone_symptoms,
            tuning=self.tuning,
        )
