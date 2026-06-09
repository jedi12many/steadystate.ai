# custom-checks — define what *healthy* means for your app

**The situation:** generic probing tells you a pod is `Running`, a service is `active`, a container
is up. But **running ≠ working** — a postfix pod can be `Running` and not routing a single message;
a "hot" region is the one actually *serving*, not just scheduled. You want steadystate to check the
thing you actually care about: **is it doing its job?** — and to do it *per deployment*, since every
app's "healthy" is different.

A **custom check** is a **declarative rule** — a vetted read + a condition — that emits a finding
when it doesn't hold. It is **data in a vetted schema, never code**: a check can only *observe* (a
finding rides the normal pipeline — tracked, muteable, feeds `resolve`/`learn`, scoped to your apps),
never act. So a wrong check is *noise*, never damage. Same safety model as the action catalog.

## 1. Author a check — by talking, or with JSON

Two paths, by who's driving:

```sh
# A human, in plain English -- steadystate's LLM fills the vetted schema, validates, stores:
steadystate define-check "alert if postfix stops routing mail"
steadystate define-check "warn if squid isn't running on a proxy host"

# An agent over MCP (Copilot/Claude) fills the schema itself and calls the add-check tool;
# or you pass JSON directly:
steadystate add-check '{"name":"postfix-routing","read":{"kind":"kubectl-log","selector":"app=postfix","namespace":"mail"},"when":{"pattern":"status=sent","expect":"present"},"emit":{"severity":"high","title":"postfix is not routing mail"}}'

steadystate checks        # list what's defined
```

**Either way `parse_check` is the gate** — only a schema-valid, observe-only check is ever stored.
The LLM (yours or the agent's) *authors*; it can't slip in code or an unvetted read.

## 2. The read kinds — functional health wherever your app lives

| Kind | Answers | `read` | `when` |
|---|---|---|---|
| `kubectl-cpu` / `kubectl-mem` | thresholds on live usage | `selector` (label), `namespace`, `agg?` | `op`, `value` (millicores / MiB) |
| `kubectl-log` | "doing its job?" (pods) | `selector`, `namespace`, `tail?` | `pattern` (regex), `expect: present\|absent` |
| `docker-log` | same, for compose | `selector` (a `docker ps` filter), `tail?` | `pattern`, `expect` |
| `ansible-service` | host/VM service state | `selector` (host pattern), `service` | `expect: active\|inactive` |

`expect: present` fires when a **success signal is missing** (`status=sent` gone → not routing);
`expect: absent` fires when an **error appears** (`fatal|panic` in the logs). A read steadystate
*couldn't take* → **no finding** — a *down* app is the generic prober's job; a custom check answers
the complementary *"running, but working?"*.

```jsonc
// .steadystate/checks.json (or your versioned file -- see step 4)
[
  { "name": "postfix-routing",
    "read": { "kind": "kubectl-log", "selector": "app=postfix", "namespace": "mail" },
    "when": { "pattern": "status=sent", "expect": "present" },
    "emit": { "severity": "high", "title": "postfix is not routing mail" } },

  { "name": "squid-up",
    "read": { "kind": "ansible-service", "selector": "proxies", "service": "squid" },
    "when": { "expect": "active" },
    "emit": { "severity": "high", "title": "squid is not running on a proxy host" } },

  { "name": "gateway-cold",
    "read": { "kind": "kubectl-cpu", "selector": "app=gateway", "namespace": "prod" },
    "when": { "op": "<", "value": 5 },
    "emit": { "severity": "medium", "title": "gateway region looks cold (CPU < 5m)" } }
]
```

## 3. "Is my app healthy?" means *your* workloads

Custom-check findings ride the same pipeline as everything else — and `summary` (CLI / chat /
MCP-connect) **leads with your apps and sets the platform aside**:

```
$ steadystate summary
  1 open finding (1 high)  |  2 platform   (as of 4m ago)
  worst: postfix is not routing mail  [high]
```

The Rancher/k8s plumbing (`coredns`, `svclb`, the `cattle-*` operators) is labeled `platform`, not
hidden. Name *your* cluster's own system namespaces with `STEADYSTATE_PLATFORM_NAMESPACES` (additive).

## 4. Treat checks as intent — version them, **per silo**

Checks are **IaC-grade config** (what *healthy* means), not runtime state — so the home is the
**committed `steadystate/checks.json`**. It sits right next to the gitignored `.steadystate/` (where
the ephemeral `state.db` lives), but it's **version-controlled**: authored/agent-written checks get a
**git diff to review and commit**.

steadystate resolves the checks file **CWD-relative**, in this order:

```
  --checks <path>   →   STEADYSTATE_CHECKS   →   steadystate/checks.json   →   .steadystate/checks.json
```

So with a **silo** (`--silo <name>` chdirs into that deployment's folder — and any per-deployment
folder works the same), **each wall reads its own** `steadystate/checks.json`. Drop one per silo and
you're done — no env var — scoped exactly like that wall's `state.db`, targets, and kubeconfig. When
an **agent** authors a check via `add-check`, it writes to that committed file, so you get a diff to
review. (`state.db` stays the local runtime bit.)

> **Don't set a _global_ `STEADYSTATE_CHECKS`.** Because it wins over the per-folder file, one
> exported path makes *every* silo read that *one* file — defeating per-silo checks, and able to
> hide a wall's real `steadystate/checks.json`. Use `STEADYSTATE_CHECKS` / `--checks` only to point
> at a *non-default* file for a single run; for the per-wall setup, just commit
> `steadystate/checks.json` in each folder. `steadystate doctor` prints the **resolved path**, so you
> can confirm which file a wall is actually reading.

| | |
|---|---|
| **Shape** | declarative checks in a (versioned) JSON file, evaluated on every probe/sweep |
| **Source** | rides any live backend — `kubectl` (pods), `docker` (compose), `ansible` (hosts) |
| **Authoring** | `define-check "<plain English>"` (your LLM) · `add-check <json>` (an agent/MCP) |
| **Safety** | data in a vetted schema, **observe-only** — emits a finding, never runs code or acts |
| **Surface** | findings ride the pipeline (tracked / muteable / `resolve` / `learn`), app-focused in `summary` |

✅ Uses only shipped pieces. The LLM (yours or an agent's) authors *what* to check; `parse_check`
decides *whether* it's valid; steadystate does the reading. Same propose-vs-decide split as the rest
of the tool — see **[LLM_SAFETY.md](../../LLM_SAFETY.md)**.
