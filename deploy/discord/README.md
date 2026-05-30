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
