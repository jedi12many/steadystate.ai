"""The ArgoCD health probe: ArgoCD's own per-resource health.status -> Symptom."""

from __future__ import annotations

from steadystate.probe.argocd import ArgoCDProbe, symptoms_from_argocd_app
from steadystate.reason.alert import Severity


def _app(*resources: dict) -> dict:
    return {"status": {"resources": list(resources)}}


def _res(name: str, health: str | None, *, kind="Deployment", group="apps", ns="prod", msg=""):
    res = {"group": group, "kind": kind, "namespace": ns, "name": name}
    if health is not None:
        res["health"] = {"status": health, "message": msg}
    return res


# -- symptoms_from_argocd_app (pure) -------------------------------------------


def test_degraded_is_a_high_symptom_with_the_message():
    app = _app(_res("web", "Degraded", msg="progress deadline exceeded"))
    [symptom] = symptoms_from_argocd_app(app)
    assert symptom.identity == "apps/Deployment/prod/web"
    assert symptom.category == "Degraded" and symptom.severity is Severity.HIGH
    assert "progress deadline exceeded" in symptom.detail


def test_missing_and_unknown_are_medium():
    syms = symptoms_from_argocd_app(_app(_res("a", "Missing"), _res("b", "Unknown")))
    assert {s.severity for s in syms} == {Severity.MEDIUM}


def test_healthy_progressing_suspended_and_absent_health_are_not_symptoms():
    app = _app(
        _res("ok", "Healthy"),
        _res("rolling", "Progressing"),
        _res("paused", "Suspended"),
        _res("nohealth", None),
    )
    assert symptoms_from_argocd_app(app) == []


def test_identity_matches_the_source_so_drift_and_symptom_co_locate():
    # The probe identity must equal the argocd SOURCE identity for the same resource, so a
    # Degraded + OutOfSync resource diagnoses into one alert.
    from steadystate.sources.argocd import _identity as source_identity

    res = _res("web", "Degraded")
    [symptom] = symptoms_from_argocd_app(_app(res))
    assert symptom.identity == source_identity(res)


# -- the probe ------------------------------------------------------------------


def test_probe_reads_the_app_snapshot_ignoring_resources():
    app = _app(_res("web", "Degraded"))
    # argocd is a drift-only source, so `resources` is [] -- the probe uses its snapshot.
    assert ArgoCDProbe(app).probe([])[0].category == "Degraded"


def test_probe_with_no_app_is_silent():
    assert ArgoCDProbe().probe([]) == []
    assert ArgoCDProbe({}).probe([]) == []
