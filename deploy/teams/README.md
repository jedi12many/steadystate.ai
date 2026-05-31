# Microsoft Teams setup

Two halves, independent:

- **Alerts → Teams** needs only an **incoming webhook** (no app, no dependency).
- **Approvals from Teams** need an **Outgoing Webhook** (shared-secret HMAC — still no dependency).

Lighter than the Discord path: no application, no public key, no command registration.

## Alerts (outbound) — incoming webhook only

1. Teams → the channel → ⋯ → *Workflows* (or *Connectors*) → add an **Incoming Webhook**, copy the URL.
2. `export TEAMS_WEBHOOK_URL=...`
3. `steadystate scan ./infra --to teams` — one Adaptive Card per alert (the fingerprint is shown on each).

## Approvals (inbound) — Outgoing Webhook

An incoming webhook is send-only, so approving from Teams uses an **Outgoing Webhook** the team
@mentions. Teams signs each call with HMAC-SHA256 over a shared secret, so no extra dependency.

1. **Create the Outgoing Webhook** — in the team, *Manage team* → *Apps* → *Create an Outgoing Webhook*.
   Give it a name (e.g. `steadystate`), set the **Callback URL** to where the listener is reachable
   over HTTPS (a tunnel for local testing), and create it. Teams shows a **security token** once —
   copy it.
2. **Run the listener** where Teams can reach it:
   ```sh
   export STEADYSTATE_TEAMS_SECURITY_TOKEN=<the security token>
   steadystate listen --from teams --port 8723
   ```

### Use it

`scan --autonomy suggest --to teams` posts an alert with its fingerprint. In the channel, @mention
the webhook with the decision and fingerprint:

```
@steadystate approve <the fingerprint from the alert>
```

The listener verifies the HMAC signature, runs the **same** guardrailed remediation the CLI, Slack,
and Discord paths use (actor recorded as the Teams sender's name), and replies in-channel with the
outcome. `@steadystate decline <fingerprint>` declines it.

**Discovery, no fingerprint needed:** `@steadystate help` (commands), `@steadystate targets` (what
`probe` can reach), `@steadystate pending` (awaiting approval, with fingerprints), `@steadystate
findings` (remembered findings + status), `@steadystate history` (the audit log) — handy for an
operator who didn't set up the deployment. And `@steadystate probe <target> verbose` shows the full
evidence per finding. (Teams needs no command registration; these work as soon as you upgrade.)

**Summon a scan:** `@steadystate probe <target>` runs an on-demand scan of a named target and posts
what's wrong back to the channel (read-only), with a one-line spend footer. Targets come from the
listener's `STEADYSTATE_TARGETS` file (name → source + path + label) — see
[deploy/kubernetes/listener.yaml](../kubernetes/listener.yaml). It honors your mutes/snoozes by
default; add `unmute` (`@steadystate probe <target> unmute`) to show everything for that run.

**See spend:** `@steadystate cost` posts the LLM spend rollup, or `@steadystate cost day` / `cost week`
for the trend.

**Silence a finding:** each probe finding shows its fingerprint; `@steadystate mute <fp>` quiets a
benign one on future scans (un-mute with the CLI: `steadystate unmute <fp>`).
