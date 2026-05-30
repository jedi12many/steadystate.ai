# steadystate.ai — demo walkthrough

Three self-contained demos that show the product finding real problems. Two run anywhere
(captured snapshots — exactly how the ArgoCD / Kubernetes integrations run in CI); the third
runs against your own cloud.

**For a sharper, plain-English narrative**, set an LLM key and drop `--no-llm`:

```sh
export ANTHROPIC_API_KEY=sk-ant-...     # or STEADYSTATE_LLM_BASE_URL/_API_KEY/_MODEL for any OpenAI-compatible endpoint
```

`--no-llm` (used below) runs the deterministic engine — the security mapping, the diagnosis
correlation, and the guardrails are all deterministic; the LLM only adds the prose.

---

## 1. The headline — drift **and** malfunction, diagnosed (`argocd-incident.json`)

One ArgoCD Application snapshot with a real incident. steadystate reads its **sync** status as
drift *and* its **health** status as malfunction, from the same document, and correlates them.

```sh
steadystate scan demo/argocd-incident.json --source argocd --probe auto --label prod-argo --no-llm
```

You get **three** kinds of alert at once:

- **`payments` — diagnosed.** OutOfSync (drift) **and** Degraded (malfunction) on the same
  resource → **one** root-caused alert: *"payments is failing — likely root cause: drift,"*
  carrying the failing-pod evidence and recommending the drift's fix. *No log tool makes this link.*
- **`web` — malfunction with no drift.** Synced, but Degraded ("0/3 pods available"). The problem
  that never touched your config — the thing a drift-only tool is blind to.
- **`cache` — drift only.** OutOfSync but Healthy.

That single scan is the whole thesis: *steady state = running as declared **and** healthy.*

---

## 2. Kubernetes Pod Security (`k8s-insecure.json`)

A declared manifest with a workload that has been insecure since day one — no drift required.

```sh
steadystate scan demo/k8s-insecure.json --source k8s --label prod-k8s --no-llm
```

Four findings on `billing`, mapped to CIS Kubernetes + MITRE ATT&CK:

- **privileged container** → CIS 5.2.1 · **T1611 (Escape to Host)** — HIGH
- **adds `SYS_ADMIN`** → CIS 5.2.8 · **T1611** — HIGH (host-escape-grade capability)
- **hostNetwork** → CIS 5.2.4 — MEDIUM
- **hostPath `/`** → CIS 5.2.12 · **T1611** — MEDIUM

Honest framing: config-exposure → technique, **not** behavioral detection.

---

## 3. Live cloud — security exposure + the guardrailed fix (your own GCP/Terraform)

Run from a Terraform working directory. This **changes real infrastructure**, so use a sandbox.
It induces two exposures out of band, lets steadystate catch them, fixes one through the
guardrailed loop, and reconciles the rest.

```sh
# --- inject two real exposures (out of band, as a human would) ---
gcloud compute firewall-rules update <ssh-rule> --source-ranges=0.0.0.0/0          # open SSH to the world
gcloud storage buckets update gs://<bucket> --no-public-access-prevention          # drop the bucket guardrail

# --- steadystate finds them, mapped to ATT&CK ---
steadystate scan . --source terraform --label gcp-prod --no-llm
#   HIGH  google_compute_firewall.ssh    [MITRE T1190]   (open ingress)
#   HIGH  google_storage_bucket.sandbox  [MITRE T1530] [MITRE T1562]   (public storage / impair defenses)

# --- fix the bucket through the guardrailed loop: suggest -> approve -> verify ---
steadystate scan . --source terraform --autonomy suggest --label gcp-prod --state .steadystate/demo.db
steadystate approve <bucket-fingerprint> --actor you --state .steadystate/demo.db
#   Result: applied + verified -- Applied and verified clear.
steadystate history --state .steadystate/demo.db          # the append-only audit trail

# --- reconcile the rest ---
terraform apply -target=<ssh-rule> -auto-approve
```

Validated on the `ssai-sandbox` GCP project: both exposures detected, the bucket reconciled and
**verified** against live infrastructure, the firewall closed.

---

## What each demo proves, in one line

| Demo | Proves |
|---|---|
| ArgoCD incident | drift **+** malfunction **+** the correlation no monitor makes |
| k8s Pod Security | standing security/compliance posture (CIS + ATT&CK), not just drift |
| Live GCP | it works on real cloud — detect → approve → **verified** remediation → audit |

Run `steadystate catalog` to see every plugin and command this build offers.
