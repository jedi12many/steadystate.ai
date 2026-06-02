# chat-listener — a persistent listener, chat talks back, state in SQLite

**Shape: a long-lived Deployment.** The [k8s-cronjob](../k8s-cronjob/) scenario *pushes* alerts out
on a timer. The listener is the counterpart that keeps a process running so chat can talk *back*:
approve/decline a remediation, ask `pending` / `help` / `findings`, or **`probe <target>`** to run
the same reasoning engine `scan` runs against a named target on demand (Summon). Both pods write
the **same SQLite file**, so a chat approval clears the very gate a scheduled scan opened, and a
mute in chat silences that finding on the next scan.

Apply [`../../deploy/kubernetes/rbac.yaml`](../../deploy/kubernetes/rbac.yaml) first (namespace,
read-only ServiceAccount, state PVC), then
[`../../deploy/kubernetes/listener.yaml`](../../deploy/kubernetes/listener.yaml):

```yaml
# deploy/kubernetes/listener.yaml (trimmed)
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
per-provider [`../../deploy/`](../../deploy/) READMEs).

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
| **State** | SQLite on a PVC shared with the CronJob — chat approvals + scheduled scans are one memory |
| **Act** | approve/decline from chat clears the same approval gate the CronJob's findings created |
| **Autonomy** | observe + suggest (chat is a trigger and an approval surface, never a bypass) |

✅ **shipped** — [`../../deploy/kubernetes/listener.yaml`](../../deploy/kubernetes/listener.yaml)
(+ `rbac.yaml`, provider READMEs).

No chat provider handy? `steadystate chat` is a local REPL over the **same** command grammar and
`steadystate probe <target>` is the one-shot Summon — both exercise the whole mechanism without a
provider, signing, or a public endpoint.
