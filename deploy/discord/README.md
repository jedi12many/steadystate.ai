# Discord setup

Two halves, independent:

- **Alerts → Discord** needs only a **channel webhook** (no app, no dependency).
- **Approvals from Discord** need a Discord **application** + the optional crypto extra.

## Alerts (outbound) — webhook only

1. Discord → Server Settings → Integrations → Webhooks → *New Webhook*, pick a channel, copy the URL.
2. `export DISCORD_WEBHOOK_URL=...`
3. `steadystate scan ./infra --to discord` — one embed per alert (the fingerprint is shown on each).

## Approvals (inbound) — slash command

A channel webhook is send-only, so approving from Discord uses a `/steadystate approve <fingerprint>`
slash command on a Discord **application**. Discord signs interactions with Ed25519, so install
the extra:

```sh
pip install steadystate[discord]
```

Then:

1. **Create an application** — Discord Developer Portal → *New Application*. Copy the **Public Key**
   (General Information) and the **Application ID**.
2. **Register the command** (one time). Add a **Bot** to the app, copy its token, then:
   ```sh
   DISCORD_APP_ID=... DISCORD_BOT_TOKEN=... DISCORD_GUILD_ID=<your server id> \
     python deploy/discord/register.py
   ```
   `DISCORD_GUILD_ID` registers to one server and updates instantly (best for testing); omit it to
   register globally.
3. **Run the listener** where Discord can reach it (HTTPS in front, e.g. a tunnel for local testing):
   ```sh
   export STEADYSTATE_DISCORD_PUBLIC_KEY=<the app public key>
   steadystate listen --from discord --port 8723
   ```
4. **Point Discord at it** — Developer Portal → your app → General Information →
   **Interactions Endpoint URL** = `https://<your-host>/`. Discord sends a signed PING; the listener
   answers PONG and Discord saves the URL (this fails if the public key or reachability is wrong —
   that's the verification working).

### Use it

`scan --autonomy suggest --to discord` posts an alert with its fingerprint. In the channel:

```
/steadystate approve fingerprint:<the fingerprint from the alert>
```

The listener verifies the Ed25519 signature, runs the **same** guardrailed remediation the CLI and
Slack paths use (actor recorded as the Discord username), and replies in-channel with the outcome.
`/steadystate decline fingerprint:<fp>` declines it.

**Don't know the fingerprint (or what's available)?** The same command registers read-only
subcommands for discovery — `/steadystate help` lists what the listener accepts, and
`/steadystate pending` shows the remediations awaiting approval with their fingerprints. Re-run
`register.py` after upgrading to pick them up (the subcommands ship in `command.json`).

**Summon a scan:** `/steadystate probe <target>` runs an on-demand scan of a named target and
posts what's wrong back to the channel (read-only), with a one-line spend footer. Targets come
from the listener's `STEADYSTATE_TARGETS` file (name → source + path + label) — see
[deploy/kubernetes/listener.yaml](../kubernetes/listener.yaml). It honors your mutes/snoozes by
default; pass the `unmute: true` option to show everything for that run.

**See spend:** `/steadystate cost` posts the LLM spend rollup (or `cost period:day|week` for the
trend).

**Silence a finding:** each probe finding shows its fingerprint; `/steadystate mute fingerprint:<fp>`
quiets a benign one on future scans (un-mute with the CLI: `steadystate unmute <fp>`). Re-run
`register.py` after upgrading so the new `cost` + `mute` subcommands and the `unmute` option appear.
