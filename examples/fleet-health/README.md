# fleet-health — "is anything on fire?" across your clusters

**The situation:** your IaC is locked down — repos built from templates, state in a cloud backend
you can't read from a laptop — so the drift-vs-declared path is hard to use. But you *can* reach
the clusters. So skip drift entirely and ask the question that matters: **is anything on fire?**
This scenario points steadystate at a directory of kubeconfigs, discovers every context as a
target, and probes the live clusters for crash-looping / image-pull-failing / restart-storming
workloads — driven from the CLI or chat, with memory of what changed.

It builds on the live **`k8s-live`** source (it reads the cluster's own workloads and health-checks
them — no declared manifests needed) and the **fleet sweep**. Start local; add the listener when
you want it from Teams/Slack while away from your desk.

> Don't want to deploy into the cluster while you evaluate? Run this exact flow on a jump box
> instead — see [bastion-host](../bastion-host/). Steps 1–2 below are identical; only the
> "make it persistent" part differs (a systemd service vs an in-cluster Deployment).

## 1. Discover your clusters → named targets

Point `KUBECONFIG` at the kubeconfigs you can reach (a directory of files, or one config with many
contexts), then let `discover --create` register each context as a target:

```sh
export KUBECONFIG="$(ls -1 ~/.kube/clusters/*.yaml | paste -sd:)"   # a dir of kubeconfigs, merged
steadystate discover --create        # writes one k8s-live target per context -> targets.json
steadystate targets --check          # see your clusters

#   prod-cluster        k8s-live   context=prod-cluster        [ok]
#   stg-cluster         k8s-live   context=stg-cluster         [ok]
#   gke-eu-prod         k8s-live   context=gke_proj_eu_prod    [ok]
```

A live target carries no path — it reads live state — so `targets --check` validates it by
reachability, not a file. The raw context drives kubectl; the slug is just the friendly name you
type.

## 2. Probe the fleet (local first)

```sh
steadystate sweep                    # probe every cluster, roll up what's on fire
#   Fleet sweep: 3 cluster(s) -- 1 on fire, 2 clear, 0 unreachable.
#     prod-cluster   2 alert(s) (1 new)
#     stg-cluster    clear
#     gke-eu-prod    clear

steadystate scan --target prod-cluster --probe auto   # one cluster, in detail
steadystate chat                     # a local REPL: `probe all`, `probe prod-cluster`, `targets`
```

Point `--state` at a SQLite file (the default `.steadystate/state.db`) and the sweep becomes
**memoryful**: a workload that catches fire reads as *new*, one that recovers reads as *resolved* —
so you see *what changed since the last sweep*, not the same wall every time. Run it on a loop
(`watch`, a cron entry, or the CronJob) and you have continuous fleet health with no IaC at all.

## 3. Make it persistent + reachable from chat

To ask `probe all` from Teams/Slack while away, run the [chat-listener](../chat-listener/) with two
additions: **mount the kubeconfigs** so the listener can reach the clusters, and ship the
**discovered `targets.json`** as the registry.

```yaml
# Additions to deploy/kubernetes/listener.yaml for fleet health
spec:
  template:
    spec:
      containers:
        - name: listener
          env:
            - name: STEADYSTATE_TARGETS
              value: /config/targets.json          # the discovered targets (ConfigMap)
            - name: KUBECONFIG                      # colon-joined: kubectl merges them
              value: /kube/prod-cluster.yaml:/kube/stg-cluster.yaml:/kube/gke-eu-prod.yaml
          volumeMounts:
            - { name: state,   mountPath: /data }
            - { name: targets, mountPath: /config, readOnly: true }
            - { name: kubeconfigs, mountPath: /kube, readOnly: true }
      volumes:
        - name: kubeconfigs
          secret: { secretName: steadystate-kubeconfigs }   # one key per cluster kubeconfig
---
# Generate the targets ConfigMap straight from discovery:
#   steadystate discover --create && kubectl create configmap steadystate-targets \
#     --from-file=targets.json -n steadystate
apiVersion: v1
kind: ConfigMap
metadata: { name: steadystate-targets, namespace: steadystate }
data:
  targets.json: |
    {
      "prod-cluster": { "source": "k8s-live", "context": "prod-cluster" },
      "stg-cluster":  { "source": "k8s-live", "context": "stg-cluster" },
      "gke-eu-prod":  { "source": "k8s-live", "context": "gke_proj_eu_prod" }
    }
```

Then, from chat: `@steadystate probe all` sweeps the fleet (stateful — each sweep compares to the
last), `@steadystate probe prod-cluster` looks at one, `@steadystate targets` lists them.

> The fleet sweep can take a while across many clusters. On Slack/Discord it rides the existing
> async deferral; on Teams (no inbound callback) start with the local CLI / a scheduled sweep that
> posts via the outbound Teams webhook.

## RBAC: least-privilege fleet read

Each kubeconfig's identity needs cluster-wide **read** — `get`/`list` on
deployments/statefulsets/daemonsets/pods, plus `pods/log` for the failing pod's last log line. The
built-in **`view`** ClusterRole grants exactly that and nothing mutating, so bind the listener's
identity (or each remote kubeconfig user) to it:

```sh
kubectl create clusterrolebinding steadystate-view \
  --clusterrole=view --serviceaccount=steadystate:steadystate
```

| | |
|---|---|
| **Source** | `k8s-live` (the cluster's own workloads, health-checked — no declared manifests) |
| **Discovery** | `discover --create` → one target per kube context |
| **Secrets** | the kubeconfigs (a Secret); the chat provider's signing secret for inbound |
| **Surface** | `sweep` / `scan --target` (CLI) · `probe all` / `probe <cluster>` (chat) |
| **State** | SQLite — the sweep is stateful, so new/recurring/resolved works across sweeps |
| **Act** | none — `k8s-live` is observe-only (it never changes a workload) |
| **Autonomy** | observe (this is a health *signal*; remediation is your operator's job) |

✅ **shipped** — `k8s-live` source, `Target.context`, `discover --create` context enumeration, and
the `sweep` / `probe all` fleet batch. Drive it locally with `steadystate chat` (no provider
needed), or wire the listener above for chat-from-anywhere.
