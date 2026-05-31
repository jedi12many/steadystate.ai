# Deploying steadystate

steadystate is a stdlib-only Python CLI. You run it as a **scheduled job, close to where the
declared state and the observed reality both live**, and it surfaces drift to the alerting you
already use. This guide gives the deployment model and three worked examples: a CI drift check,
an in-cluster CronJob, and a persistent listener that lets chat talk back.

## The model

The scan loop is always the same: **collect declared → reconcile against observed → reason
(domain packs + correlation + optional Prometheus enrichment) → surface → optionally act,
behind the approval gate.** What changes per environment is *where it runs* and *how it
reaches the two states*.

Four principles hold everywhere:

- **steadystate is secrets-agnostic.** It never stores a credential. The *runner* integrates
  your secret manager (Vault, a kubeconfig, your cloud's secret manager, …) and injects creds
  as env vars or files; steadystate consumes the already-authenticated tooling (terraform,
  kubectl, ansible, helm) or reads a token from the env. One less thing to trust.
- **Observe-first.** Default autonomy is **observe** (alert only). Raise a plugin/environment
  to **suggest** (a human approves) or **auto** (self-heals within the guardrails) per the
  per-plugin command manifest (`steadystate commands`) — observe commands run freely, the
  potentially-destructive ones always pass the approval gate.
- **Run it where the state is.** In CI when the plan is a CI artifact; in-cluster when the
  truth is the K8s API; on a central scheduler when you're reaching out to a fleet.
- **Surface to what you have.** `--to console,slack,teams` for alerts; `prometheus`/`grafana`
  for metrics + annotations; `--enrich prometheus` to escalate a drift whose resource is
  unhealthy *right now*.

State — memory (new/recurring/resolved, mute/snooze) and LLM spend — lives in a small SQLite
file (`--state`). Mount a volume so it persists across runs, and **share that one file** between
the scheduled scan and the persistent listener (Example 3) so a chat approval acts on the same
pending remediation a scan recorded.

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
| **Status** | ✅ **shipped** — a runnable workflow lives at [`deploy/github-actions/drift.yml`](deploy/github-actions/drift.yml) |

---

## Example 2 — Rancher / Kubernetes on on-prem OpenStack (auth: kubeconfig)

**Shape: in-cluster CronJob.** Run steadystate *inside* the cluster with a **read-only
ServiceAccount** — then there's no kubeconfig file to mount at all; the pod's SA is the auth.
(For an external runner, mount the kubeconfig and set `KUBECONFIG` instead.) The default in
[`deploy/kubernetes/cronjob.yaml`](deploy/kubernetes/cronjob.yaml) rides Rancher/Fleet — it reads
a Fleet `GitRepo`'s sync status, so there are no declared manifests to render in-cluster:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: steadystate, namespace: steadystate }
spec:
  schedule: "*/30 * * * *"
  concurrencyPolicy: Forbid
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
                  kubectl get gitrepo -n "$FLEET_NS" "$GITREPO" -o json > /data/gitrepo.json
                  steadystate scan /data/gitrepo.json --source rancher \
                    --to console,slack --state /data/state.db
              volumeMounts:
                - { name: state, mountPath: /data }   # the shared SQLite PVC
          volumes:
            - name: state
              persistentVolumeClaim: { claimName: steadystate-state }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: steadystate-readonly }
rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["get", "list"] }]   # observe-only
```

For a non-Fleet cluster use the `k8s` source instead: observe with `kubectl get ... -o json` and
supply the declared manifests from a git-sync sidecar (e.g. `kustomize build` → JSON on a shared
volume), then `--source k8s`. Full manifests (namespace, ServiceAccount, ClusterRole/Binding, and
the state PVC) are in [`deploy/kubernetes/rbac.yaml`](deploy/kubernetes/rbac.yaml).

| | |
|---|---|
| **Source** | `rancher` (Fleet GitRepo status) by default; or `k8s` (declared manifests vs `kubectl get`) |
| **Domain** | baseline severity today; a K8s security pack (privileged pods, hostNetwork, …) is a follow-up |
| **Secrets** | the pod's read-only ServiceAccount (no kubeconfig file in-cluster) |
| **Surface** | Slack + console |
| **Act** | `kubectl apply -f` / `kubectl rollout restart` are the plugin's destructive commands |
| **Autonomy** | observe (most clusters self-heal via the operator/Fleet already — let them, and just watch) |
| **Status** | ✅ **shipped** — manifests + read-only RBAC at [`deploy/kubernetes/`](deploy/kubernetes/) |

---

## Example 3 — A persistent listener: chat talks back, state in SQLite

**Shape: a long-lived Deployment.** The CronJob in Example 2 *pushes* alerts out on a timer. The
listener is the counterpart that keeps a process running so chat can talk *back*: approve/decline
a remediation, ask `pending` / `help` / `findings`, or **`probe <target>`** to run the same
reasoning engine `scan` runs against a named target on demand (Summon). Both pods write the **same
SQLite file**, so a chat approval clears the very gate a scheduled scan opened, and a mute in chat
silences that finding on the next scan.

```yaml
# deploy/kubernetes/listener.yaml (trimmed) -- apply rbac.yaml first (namespace, SA, state PVC).
apiVersion: apps/v1
kind: Deployment
metadata: { name: steadystate-listener, namespace: steadystate }
spec:
  replicas: 1                                   # one writer to the SQLite store; scale the store, not pods
  selector: { matchLabels: { app: steadystate-listener } }
  template:
    metadata: { labels: { app: steadystate-listener } }
    spec:
      serviceAccountName: steadystate           # the read-only SA from rbac.yaml (for k8s probes)
      containers:
        - name: listener
          image: ghcr.io/jedi12many/steadystate:latest
          args: [listen, --from=slack, --port=8723, --state=/data/state.db]
          env:
            - name: STEADYSTATE_TARGETS         # the `probe <target>` registry (ConfigMap below)
              value: /config/targets.json
            - name: STEADYSTATE_SLACK_SIGNING_SECRET   # THE security boundary for inbound requests
              valueFrom: { secretKeyRef: { name: steadystate, key: slack-signing-secret } }
          volumeMounts:
            - { name: state, mountPath: /data }                 # shared SQLite PVC
            - { name: targets, mountPath: /config, readOnly: true }
      volumes:
        - name: state
          persistentVolumeClaim: { claimName: steadystate-state }   # SAME claim the CronJob mounts
        - name: targets
          configMap: { name: steadystate-targets }
---
# Adding a probe target is a ConfigMap edit -- no redeploy. Each entry is the inputs a `scan` takes.
apiVersion: v1
kind: ConfigMap
metadata: { name: steadystate-targets, namespace: steadystate }
data:
  targets.json: |
    {
      "prod-k8s":  { "source": "k8s",    "path": "/data/manifests.json", "label": "prod-k8s" },
      "prod-argo": { "source": "argocd", "path": "/data/argo-app.json",  "label": "prod-argo" }
    }
```

A Service + Ingress (public HTTPS, in the same file) front the listener — chat providers POST to a
public URL, so TLS terminates at the Ingress. **The Ingress is not the security boundary:** the
listener verifies every request's signature (Slack/Teams HMAC, Discord Ed25519) before acting,
keyed by the provider secret above. Set `--from` and the matching secret env var to your provider
(`STEADYSTATE_SLACK_SIGNING_SECRET` / `_TEAMS_SECURITY_TOKEN` / `_DISCORD_PUBLIC_KEY` — see the
per-provider [`deploy/`](deploy/) READMEs).

**On the shared SQLite store:** it's a single file on a `ReadWriteOnce` PVC, and the listener is
the only writer for approve/decline (hence `replicas: 1`). A RWO volume requires the CronJob pod
and the listener pod to land on the same node — pin them with a node selector, or use a
`ReadWriteMany` storage class if they may spread. Drop the PVC + volume to run stateless (you lose
memory and pending approvals across restarts).

| | |
|---|---|
| **Shape** | long-lived Deployment + Service + Ingress (public HTTPS), single replica |
| **Source** | any named target in the registry — `probe <target>` runs the same engine as `scan` |
| **Secrets** | the provider's signing secret (HMAC / Ed25519) — the boundary for inbound requests |
| **Surface** | inbound chat (Slack / Teams / Discord); the listener replies in-thread |
| **State** | SQLite on a PVC shared with the CronJob — chat approvals + scheduled scans are one memory |
| **Act** | approve/decline from chat clears the same approval gate the CronJob's findings created |
| **Autonomy** | observe + suggest (chat is a trigger and an approval surface, never a bypass) |
| **Status** | ✅ **shipped** — [`deploy/kubernetes/listener.yaml`](deploy/kubernetes/listener.yaml) (+ `rbac.yaml`, provider READMEs) |

No chat provider handy? `steadystate chat` is a local REPL over the **same** command grammar and
`steadystate probe <target>` is the one-shot Summon — both exercise the whole mechanism without a
provider, signing, or a public endpoint.
