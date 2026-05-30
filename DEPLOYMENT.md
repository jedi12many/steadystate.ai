# Deploying steadystate

steadystate is a stdlib-only Python CLI. You run it as a **scheduled job, close to where the
declared state and the observed reality both live**, and it surfaces drift to the alerting you
already use. This guide gives the deployment model and three worked examples; the last one
also doubles as the spec for the code still to build.

## The model

The scan loop is always the same: **collect declared → reconcile against observed → reason
(domain packs + correlation + optional Prometheus enrichment) → surface → optionally act,
behind the approval gate.** What changes per environment is *where it runs* and *how it
reaches the two states*.

Four principles hold everywhere:

- **steadystate is secrets-agnostic.** It never stores a credential. The *runner* integrates
  your secret manager (Vault, a kubeconfig, Akeyless, …) and injects creds as env vars or
  files; steadystate consumes the already-authenticated tooling (terraform, kubectl, ansible)
  or reads a token from the env. One less thing to trust.
- **Observe-first.** Default autonomy is **observe** (alert only). Raise a plugin/environment
  to **suggest** (a human approves) or **auto** (self-heals within the guardrails) per the
  per-plugin command manifest (`steadystate commands`) — observe commands run freely, the
  potentially-destructive ones always pass the approval gate.
- **Run it where the state is.** In CI when the plan is a CI artifact; in-cluster when the
  truth is the K8s API; on a central scheduler when you're reaching out to a fleet.
- **Surface to what you have.** `--to console,slack,teams` for alerts; `prometheus`/`grafana`
  for metrics + annotations; `--enrich prometheus` to escalate a drift whose resource is
  unhealthy *right now*.

State (memory: new/recurring/resolved, mute/snooze, LLM spend) lives in a small SQLite file —
mount a volume so it persists across runs.

---

## Example 1 — GitHub → Terraform → Azure (secrets in HashiCorp Vault)

**Shape: in CI (pull).** The Terraform plan is already produced in your pipeline, so steadystate
just reads it. Vault → Azure auth is the *workflow's* job; steadystate sees only the plan JSON.

```yaml
# .github/workflows/drift.yml
name: drift
on:
  schedule: [{ cron: "0 * * * *" }]   # hourly drift sweep
  pull_request:                        # and pre-merge review
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: read }   # OIDC -> Vault
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/vault-action@v3                 # Vault issues short-lived Azure creds
        with:
          method: jwt
          secrets: |
            azure/creds/terraform  client_id  | ARM_CLIENT_ID ;
            azure/creds/terraform  client_secret | ARM_CLIENT_SECRET
      - uses: hashicorp/setup-terraform@v3
      - run: |
          terraform init
          terraform plan -out tfplan
          terraform show -json tfplan > plan.json
      - run: pipx run steadystate scan plan.json --source terraform --to console,teams
        env:
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
```

| | |
|---|---|
| **Source** | `terraform` (reads the plan JSON) |
| **Domain** | `security-azure` (NSG to Internet → T1190, storage public → T1530, broad role → T1098) |
| **Secrets** | Vault → Azure creds **in the workflow**; steadystate sees none |
| **Surface** | console (the CI log / PR check) + Teams |
| **Act** | `terraform apply` is the plugin's declared destructive command — gate it through `fix` once you raise autonomy |
| **Autonomy** | observe (alert) → suggest (approve in Teams) |
| **Status** | ✅ **works today** — needs only packaging + this example workflow |

---

## Example 2 — Rancher / Kubernetes on on-prem OpenStack (auth: kubeconfig)

**Shape: in-cluster CronJob.** Run steadystate *inside* the cluster with a **read-only
ServiceAccount** — then there's no kubeconfig file to mount at all; the pod's SA is the auth.
(For an external runner, mount the kubeconfig and set `KUBECONFIG` instead.)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: steadystate, namespace: steadystate }
spec:
  schedule: "*/30 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: steadystate          # read-only RBAC, below
          restartPolicy: OnFailure
          containers:
            - name: steadystate
              image: ghcr.io/jedi12many/steadystate:latest
              command: ["/bin/sh", "-c"]
              args:
                - |
                  kubectl get deploy,statefulset,svc -A -o json > observed.json
                  # declared = your rendered manifests (kustomize build ... -o json) or GitOps
                  steadystate scan snapshot.json --source k8s --to slack
              env: [{ name: SLACK_WEBHOOK_URL, valueFrom: { secretKeyRef: { name: steadystate, key: slack } } }]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: steadystate-readonly }
rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["get", "list"] }]   # observe-only
```

For the Rancher/Fleet angle, point the `rancher` source at a Fleet `GitRepo` to ride its sync
status instead of diffing manifests yourself.

| | |
|---|---|
| **Source** | `k8s` (declared manifests vs `kubectl get`) and/or `rancher` (Fleet GitRepo status) |
| **Domain** | baseline severity today; a K8s security pack (privileged pods, hostNetwork, …) is a follow-up |
| **Secrets** | the pod's read-only ServiceAccount (no kubeconfig file in-cluster) |
| **Surface** | Slack + console |
| **Act** | `kubectl apply -f` / `kubectl rollout restart` are the plugin's destructive commands |
| **Autonomy** | observe (most clusters self-heal via the operator/Fleet already — let them, and just watch) |
| **Status** | ✅ **works today** — needs the deploy manifests + read-only RBAC above |

---

## Example 3 — 10 pet Linux servers + HAProxy (Ansible; metrics → Prometheus/Grafana; secrets in Akeyless)

**Shape: central scheduler (agentless reach-out).** A cron job on a bastion (or a small
container) runs an Ansible **check** to find drift, scans it, and — crucially — **enriches with
Prometheus** so a config drift on a host whose HAProxy backend is *down right now* pages louder.
This is the self-healing showcase: detect → reason (is the heal the right move?) → run the
playbook, at the autonomy level you chose.

```bash
# on the scheduler (cron), secrets resolved by Ansible's Akeyless lookup, not by steadystate
ansible-playbook site.yml --check --diff --output=json > drift.json     # what WOULD change = the drift
steadystate scan drift.json --source ansible \
  --enrich prometheus \                # escalate a drift whose HAProxy backend is unhealthy now
  --to grafana,teams                   # annotate dashboards + page

# act (only above observe): run the playbook for real, behind the approval gate
#   suggest -> approve from Teams/console -> steadystate runs:  ansible-playbook site.yml --limit <host>
#   auto    -> steadystate runs it itself when storage fills on a weekend and you're away
```

| | |
|---|---|
| **Source** | **`ansible` (to build)** — parse `ansible-playbook --check --diff` (or the callback JSON) into Drift, the same way the terraform source rides `terraform plan` |
| **Observed health** | `--enrich prometheus` with a template like `up{job="haproxy",instance="{name}"} == 0` |
| **Secrets** | Akeyless via Ansible's lookup/vault — steadystate runs ansible, sees no secret |
| **Surface** | Grafana annotations + Teams |
| **Act** | **`ansible` executor (to build)** — `ansible-playbook site.yml --limit <host>` is the declared destructive command |
| **Autonomy** | suggest → auto (the "heal the worker over the weekend" case) |
| **Status** | 🔨 **needs an Ansible source + executor** — the one real code gap of the three |

---

## Readiness & roadmap

| Capability | Example | Status |
|---|---|---|
| terraform source + Azure security pack | 1 | ✅ shipped |
| k8s + rancher sources | 2 | ✅ shipped |
| Prometheus enrichment + Grafana/Prometheus surfaces | 3 | ✅ shipped |
| Packaging: a published wheel + a container image (`ghcr.io/.../steadystate`) | all | 🔨 to do |
| Example CI workflow (Ex 1) + in-cluster CronJob/RBAC (Ex 2) as real files under `deploy/` | 1, 2 | 🔨 to do |
| **Ansible source + executor** (`--check --diff` → Drift; `ansible-playbook` → act) | 3 | 🔨 to do — the headline build |
| Per-plugin executor + autonomy gate + inbound approval (observe/suggest/auto) | act on all three | 🔨 designed, not built |
| K8s security domain pack (privileged/hostNetwork/…) | 2 | 🔨 follow-up |

The common thread: **detection is ready across all three today; turning the crank from
observe → suggest → auto is the same machinery for every backend**, and the one missing
*backend* is Ansible.
