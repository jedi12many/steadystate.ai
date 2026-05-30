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

**Discovery, no fingerprint needed:** `@steadystate help` lists the commands the listener accepts,
and `@steadystate pending` shows the remediations awaiting approval with their fingerprints — handy
for an operator who didn't set up the deployment. (Teams needs no command registration; these work
as soon as you upgrade.)
