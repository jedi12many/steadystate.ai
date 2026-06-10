# The committed knowledge base — `ask` and `steadystate/kb/`

`ask` turns the repo into a **Tier-1 service desk**: anyone in chat (or at the CLI, or an agent
over MCP) asks a question and gets an answer **from the docs your team already writes** — with the
source cited.

```
@platformbot ask how do I request a new project?
@platformbot ask what services does this team offer?
```

This is the *process* half of the chat surface. The *live* half — "are the runners ok?" — is
answered from state (`summary` / `health` / `findings`). Together they make one channel where
another team can ask either kind of question and get a grounded answer.

## The convention

Commit markdown under **`steadystate/kb/`**, beside `config.toml` / `checks.json` /
`solutions.json` — the same repo-native posture: docs as code, reviewed in PRs, no second
system to keep in sync.

```
steadystate/
  config.toml
  checks.json
  solutions.json
  kb/
    services.md          # what this team offers, and how to get started
    projects.md          # how to request a project / quota / access
    onboarding.md        # the new-consumer walkthrough
    runners.md           # who owns the CI runners, escalation path
```

Any markdown works. **Headings matter**: each `#`–`######` section is a retrieval unit, so a doc
with clear headings ("Requesting a new project", "Escalation path") answers more precisely than
one long page. Content before the first heading is findable under the file's name.

Point elsewhere with `STEADYSTATE_KB` (env) or in the committed config:

```toml
[knowledge]
dir = "steadystate/kb"
```

Precedence is the usual 12-factor: `env > config.toml > default`. The path is CWD-relative like
the other intent files, so `--silo` gets a per-silo KB.

## How an answer is produced

1. **Deterministic retrieval** — the question's content words are scored against every section
   (a filename/heading hit outweighs body mentions; no index, no embeddings — a KB is a folder of
   docs, not a corpus). The top sections are selected.
2. **Grounded synthesis** — the model is given ONLY those sections and told to answer from them,
   repeat links/contacts/steps exactly, cite the file, and say plainly when the docs don't cover
   it. It never free-recalls a policy.
3. **Honest degrade** — with no LLM configured (or a failed call), `ask` returns the matching
   sections verbatim with their sources. No KB at all, or no match, says exactly that.

`ask` is **read-only** everywhere it's exposed — CLI (`steadystate ask how do I ...`), the chat
listener, and the MCP server (no grant needed). Its model spend lands in the same `cost` ledger
as every other call, under the `ask` caller.

## Why this shape

- **The repo is the source of truth.** The same PR that changes the service changes the doc that
  answers questions about it — and the answerer picks it up on the next question, no re-indexing.
- **The model can't overstep.** Retrieval decides what the model may see; the prompt forbids
  inventing what isn't there; and `ask` carries no write power — it's a reader, like `show`.
- **Degrades like everything else.** steadystate's posture is that the LLM is an enhancer, not a
  dependency: keyword retrieval + verbatim excerpts is still a working Tier-1 answer.
