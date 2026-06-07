# LLM Safety — keeping the agent in bounds

steadystate.ai uses an LLM to **explain** a finding ("why this matters"), to **correlate** events by root cause, to **author a custom health check** from your words (`define-check` / `add-check`), and — the parts that need real discipline — to **propose** a remediation (the decider) and to be **driven by an agent** (the MCP server). This document states, end to end, *how a language model acting **through steadystate** can never move your infrastructure outside the envelope you set* — **and, just as important, where that guarantee ends.** If you're evaluating this with agents in mind, read the next section first; we would rather be clear about the boundary than have you over-trust it.

The one sentence to remember:

> **The model proposes _what_. A deterministic gate decides _whether_. The model is never the authority that changes your infrastructure — on steadystate's path.**

Everything below is how that sentence is enforced — as **defense in depth**, so no single check is load-bearing.

---

## What this does — and does not — keep safe

Be precise about the boundary, because it's exactly what someone wary of agents needs to trust:

**steadystate gates every action that flows _through_ steadystate.** When the decider proposes a fix, or an agent drives the MCP server, the action runs the bound + catalog + (optional) approval + audit described below. Make steadystate the *only* way the agent can touch your infrastructure — an agent with **no shell and no cluster credentials of its own**, where **steadystate holds the kubeconfig** — and these gates are a **real fence**: its entire authority is the vetted, bounded, audited catalog, and it cannot go around them.

**steadystate is _not_ a sandbox around an agent that also has a shell.** If you run an agent (a Copilot CLI, say) that has its own shell *and* your cluster credentials, steadystate is one tool among many it can call. With its shell it can run `kubectl` directly, edit a kubeconfig, or hit any API — none of which passes our gates, because none of it goes *through* steadystate. **The gate's strength is a function of the agent's tool surface, not of the gate itself.**

> **steadystate is guardrails on a road, not a fence around the car.** If the agent drives on steadystate's road, the guardrails hold. It can also drive off-road — and there, the boundary is the agent's own permissions, not us.

**The real enforcement boundary for a shell-enabled agent is the credentials you give it.** If its kubeconfig has read-only RBAC on a cluster, it physically cannot delete a pod there, whatever tool it reaches for. Use steadystate as the *governed, audited path* to act (and for the bound + the record when it does go through us); enforce the *hard* limits at **RBAC / IAM**. The two are complementary: RBAC says what's _possible_; steadystate makes one path _safe and recorded_.

So you can choose per environment, with eyes open:

| Posture | The agent has | steadystate is | For |
|---|---|---|---|
| **Sole actuator + approval** | only the MCP, no creds of its own | a real fence; you approve each act | prod / not ready for autonomy |
| **Sole actuator + auto** | only the MCP, no creds | a real fence; autonomous *within* the catalog + bound | trusted-but-contained |
| **Broad access + resilience** | a shell + cluster creds | the eyes, the audit, the loop; **DR is the net** | recoverable / mature resilience |

Everything below describes the gate on steadystate's own path. It is strong — and it is exactly as load-bearing as you make steadystate the only road.

---

## The shape of the system

```
              proposes WHAT                       decides WHETHER                does it
  ┌─────────┐   (advice)    ┌──────────────────┐   (deterministic)   ┌──────────────────┐
  │   LLM   │ ────────────▶ │   the gate        │ ─────────────────▶ │  guardrailed      │
  │ decider │               │  • vetted action? │                    │  executor         │
  │  / MCP  │               │  • valid command? │   authorize         │  • claim-once     │
  │  agent  │               │  • within bound?  │   escalate ─▶ human │  • re-validate    │
  └─────────┘               └──────────────────┘   reject  ─▶ drop    │  • snapshot/verify│
       │                              ▲                                │  • audit log      │
       │                              │                                └──────────────────┘
       └─ can only NAME a catalog ────┘
          action; anything else is
          dropped before the gate
```

The LLM's entire authority is to **name one item from a fixed menu** and suggest its arguments. It cannot invent an action, widen an envelope, or reach the executor directly.

One adjacent capability follows the *same* discipline: the LLM (or an agent) can **author a custom health check**, but only one that passes `parse_check` — a fixed schema of **vetted, read-only reads** (a metric threshold, a log pattern, a service state). A check can only ever **observe** (emit a finding); it never runs operator-supplied code and never acts. So check-authoring is *propose WHAT to watch / the schema decides WHETHER it's valid* — the same split, applied to config: the model writes the rule, the deterministic gate admits it, and acting on what it finds still passes the action bound + catalog above.

---

## The controls, layer by layer

### 1. Detection, scoring, and the can-apply verdict are deterministic
The model is **not in the detection or decision path**. Whether something drifted, how severe it is, whether a fix is even *applicable*, and whether a drift is *destructive* (and therefore never auto-eligible) are all computed by deterministic code. The model only adds prose and a *suggestion*. Turn the model off entirely (next point) and detection, scoring, correlation, and the apply decision are unchanged.

### 2. Kill switch + egress gate (nothing leaves the box unseen)
- **Kill switch** — `--no-llm`, or `STEADYSTATE_LLM_ENABLED=false`, makes **zero** model calls. Every LLM-backed feature degrades honestly to its deterministic behaviour; nothing crashes, nothing silently does the wrong thing.
- **Egress gate** — `--confirm-llm` shows the **exact** prompt and its destination and asks *before* anything is sent. Decline and nothing leaves the machine. It's a per-call data-egress review and a hard spend gate.
- **Minimal prompt** — no capability list and no configuration/secret data is put in a prompt. The model is told to recommend the infrastructure fix only, never to reason about what the tool itself can or may do.
- **Honest degrade** — no provider, no API key, or the SDK not installed → the feature behaves exactly as if no model were configured. (`steadystate doctor` reports the LLM "ready" only when a provider **and** its client are actually present.)

### 3. The decider can only name a vetted catalog action
When the decider proposes a remediation (`LLMDecider`), the model returns a JSON object naming **one action from the catalog menu** plus a command. Before the gate ever sees it:
- a reply naming an action **not in the catalog** is dropped;
- a non-JSON / empty reply is dropped (honest degrade);
- the model is given the resource's explicit `name`/`namespace` so it targets the *right* resource, not one parsed out of an identity string.

The deterministic `CatalogDecider` is the baseline and the no-LLM fallback — so the autonomous path works with **no model at all**.

### 4. Every command is re-validated against a flexible, injection-proof allow-pattern
A named action carries a concrete command, and that command is **re-tokenised and checked against the action's allow-pattern** — at propose time *and again at run time* (defense in depth), so even a tampered stored command can't execute.

The checker (`safe_kubectl`) is **flexible on shape but strict on safety**:
- **flexible** — argument order doesn't matter (`-n ns --replicas=0` and `--replicas=0 -n ns` both pass), and both `--flag=value` and `--flag value` forms are accepted. (A correct-but-cosmetically-different command from a model is no longer rejected on a technicality.)
- **strict** — it rejects any **shell metacharacter** (`;`, `&`, `|`, `` ` ``, `$`, redirects, globs — chaining/injection), any **unknown or extra flag**, any **wrong value** (`--replicas=5` is not `--replicas=0`), and any **out-of-shape target** (a bare pod can't be named where a self-healing controller is required). The command can vary in shape but can **never do anything other than the one vetted operation**.

### 5. The bound — an envelope the proposer cannot talk past
Every catalog action has a fixed **envelope**: its *impact* (tenant / service / fleet) × its *reversibility* (lossless / recoverable / irreversible). The **bound** is a policy that maps how much of that envelope may be crossed autonomously. The gate judges each proposal on the **catalog's** envelope, **not** the proposer's claim — so a model cannot understate an action's blast radius to slip it through.

A proposal whose envelope is **outside the bound** is not run — it is **escalated to a human** (advisory), through the break-glass confirmation. A reclaim of dead (evicted) pods is lossless and tenant-scoped → within the bound. Scaling a workload to zero, or deleting a node, is outside it → escalates, every time.

### 6. Autonomy is a switch, never something the model earns
Autonomous action is **off by default** and is granted by an explicit operator switch — `STEADYSTATE_DECIDER_AUTO` for the decider, `STEADYSTATE_REFLEX_AUTO` for reflexes. There is **no track record or "trust score" that quietly promotes the model into acting**; the operator grants the switch, the bound still governs what the switch permits, and the operator's DR plan is the backstop. Granted ≠ earned.

### 7. Chat (natural language) tiers reads vs. writes
In chat, a deterministic grammar handles anything that parses; genuinely free text falls back to the model, which maps it onto **one vetted verb**. There:
- a **read-only** verb (summary, findings, show, probe, …) runs;
- an **effectful** verb (approve, fix, run, mute, send, …) is **never fired from fuzzy text** — it's echoed back as the concrete command for a human to send. The model can *suggest* a remediation; only a human (re)issuing the exact command runs it.

### 8. The MCP server is read-only by default; writes are a deliberate grant
Driven as an MCP server, an agent gets the **same** vetted verbs through the **same** guardrails — it can never do anything a chat user couldn't.
- **Read-only by default** — only observe/diagnose verbs are exposed. Effectful verbs appear only with `--write` (or `STEADYSTATE_MCP_WRITE=1`) — the same "autonomy is a switch" philosophy.
- **Annotated** — effectful tools carry `readOnlyHint`/`destructiveHint`, so an MCP client confirms a destructive call with the human.
- **Audited** — every agent-driven action is attributed to the `mcp` actor in the immutable history.
- **Still gated** — an effectful call runs through `run_command` → the bound + catalog + executor, exactly like a human's.

### 9. The executor itself re-checks, claims once, and records
Reaching the executor doesn't end the discipline. An apply requires **both** apply-eligibility **and** an explicit confirm; a destructive reconciliation (e.g. a `REMOVED` drift) is never automatically eligible; the action is **claimed once** (no double-run), **re-validated** against the allow-pattern, snapshotted/verified where the source supports it, and appended to an **immutable audit log** attributed to its actor (human / `mcp` / `auto`).

---

## Defense in depth, at a glance

| If this failed… | …this still stops an out-of-bounds change |
|---|---|
| Model hallucinates an action | Not in the catalog → dropped before the gate |
| Model emits a malformed/injected command | Allow-pattern rejects metacharacters/unknown flags — at propose **and** run time |
| Model understates blast radius | Gate judges the **catalog's** envelope, not the proposal's |
| Action is genuinely risky | Outside the bound → **escalates to a human**, never auto-runs |
| Operator never granted autonomy | Default is off; no "trust score" promotes the model |
| Fuzzy chat text names a write | Effectful verbs are echoed for human confirm, not run |
| An agent drives the MCP server | Read-only by default; writes need a grant, are annotated, and are audited |
| A stored action is tampered with | Re-validated against the allow-pattern at run time |

No single row is load-bearing. To move infrastructure outside your envelope, a model would have to defeat *every* row at once.

---

## A worked example (from a live soak)

On a real Kubernetes cluster, with the decider granted autonomy:

- **Evicted pods** → the model proposed `reclaim-evicted-pods`. Lossless, tenant-scoped, in the catalog, command valid, **within the bound** → authorized, run, and **audited**. The homeostat acted on the known-safe.
- **A crash-looping workload** → the model proposed scaling it to zero. A real, valid catalog action — but **outside the bound** (recoverable, service impact). The gate **escalated it to a human** rather than running it. The model's advice was surfaced; the change was not made autonomously.

That's the thesis in practice: **act on the known-safe, escalate the rest — and the model never gets the last word.**

---

## Reporting

The guardrails are the highest-severity area of the codebase. If you find a way for *any* model- or agent-driven input to reach a live change without the same eligibility + bound + confirmation checks a human hits, please report it privately — see **[SECURITY.md](./SECURITY.md)**.
