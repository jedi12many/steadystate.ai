# k8s-cronjob — in-cluster scheduled scan (Rancher / Kubernetes)

**Shape: in-cluster CronJob.** Run steadystate *inside* the cluster with a **read-only
ServiceAccount** — then there's no kubeconfig file to mount at all; the pod's SA is the auth. (For
an external runner, mount the kubeconfig and set `KUBECONFIG` instead.)

The default in [`../../deploy/kubernetes/cronjob.yaml`](../../deploy/kubernetes/cronjob.yaml) rides
Rancher/Fleet — it reads a Fleet `GitRepo`'s sync status, so there are no declared manifests to
render in-cluster. Full manifests (namespace, ServiceAccount, ClusterRole/Binding, state PVC) are
in [`../../deploy/kubernetes/rbac.yaml`](../../deploy/kubernetes/rbac.yaml):

```sh
kubectl apply -f ../../deploy/kubernetes/rbac.yaml -f ../../deploy/kubernetes/cronjob.yaml
```

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
volume), then `--source k8s`. To check live cluster *health* (crash-looping pods) with no declared
manifests at all, see the [fleet-health](../fleet-health/) scenario.

| | |
|---|---|
| **Source** | `rancher` (Fleet GitRepo status) by default; or `k8s` (declared manifests vs `kubectl get`) |
| **Secrets** | the pod's read-only ServiceAccount (no kubeconfig file in-cluster) |
| **Surface** | Slack + console |
| **Act** | `kubectl apply -f` / `kubectl rollout restart` are the plugin's destructive commands |
| **Autonomy** | observe (most clusters self-heal via the operator/Fleet already — let them, and just watch) |

✅ **shipped** — manifests + read-only RBAC at [`../../deploy/kubernetes/`](../../deploy/kubernetes/).
