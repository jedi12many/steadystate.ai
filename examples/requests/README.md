# Requests — a vetted ask becomes a review-gated PR

The Tier-1 **fulfillment** loop for a GitOps shop. Someone in the channel says *"I need outbound
access to example.com to download a package"* — and instead of pointing them at a wiki, the agent
**opens the PR for them** in the repo that owns that decision, then replies with the link:

```
@platformbot I need to download packages from example.com on my build server
  -> I can open that request -- send:  request proxy-domain domain=example.com
@platformbot request proxy-domain domain=example.com
  -> opened the request as a PR on your-org/proxy-outbound -- someone will review it soon: <link>
```

## The format — [`requests.json`](./requests.json)

```jsonc
{
  "name": "proxy-domain",
  "problem": "a server needs outbound access to a new domain",
  "repo": "your-org/proxy-outbound",       // where the PR opens
  "file": "allowlist.txt",                 // the file the recipe edits
  "edit": "append-line",                   // deterministic edit kinds only
  "value": "{domain}",                     // the line template -- params fill it
  "params": { "domain": "^[a-z0-9.-]+\\.[a-z]{2,}$" },  // regex-validated input
  "title": "request: allow outbound to {domain}",
  "author": "ops"                          // who vouched for the recipe -- the audit anchor
}
```

Commit it as `steadystate/requests.json`, beside `config.toml` / `solutions.json` — the same
repo-native posture: **the recipe is reviewed code**, not a chat behavior.

## Why this shape is safe to hand to a channel

- **The edit is operator intent.** The recipe names the repo, the file, the edit kind, and the
  value template. The requester — or the model suggesting the command — only ever fills **named,
  regex-validated parameters**. Nobody composes a diff in chat; a parameter can't carry a newline.
- **The PR is the gate.** steadystate's part ends at "proposal opened" (reversible by close); the
  target repo's own review and branch protections decide whether the change happens. The PR body
  names who asked and which recipe vouched.
- **Effect-tiered like everything else.** `request` is never auto-fired from natural language —
  the agent *suggests* the exact command and a human sends it. Over MCP it needs the `--write`
  grant. Every fulfillment is **audited** (`history`): who, which recipe, which values, the outcome.
- **Deduped.** One deterministic branch per (recipe, values): asking twice replies with the
  already-open PR; a value already present in the file is "nothing to request."

## Use it

```sh
steadystate requests                                  # what can be asked for
steadystate request proxy-domain domain=example.com   # open the PR, get the link
```

Same verbs in chat (`@platformbot requests` / `request …`) and over MCP. Needs
`STEADYSTATE_GITHUB_TOKEN` (or `GITHUB_TOKEN`) with contents + pull-requests write on the target
repo — scope a fine-grained token to exactly the repos your recipes name.
