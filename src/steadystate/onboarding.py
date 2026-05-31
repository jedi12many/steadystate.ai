"""The environment a steadystate deployment needs -- declared once.

`steadystate init` (collect + write a .env) and `steadystate doctor` (audit what's set) both read
this one catalog, so a new env var is a single entry here, not edits in two commands. The catalog
is the honest, complete config surface: every var the engine actually reads, grouped by the
capability it switches on.

Nothing here ever prints a secret *value* -- `doctor` reports only whether a var is set, and
`init` hides secret input. The written .env is gitignored; secrets stay out of the repo.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

Env = Mapping[str, str]


class Status(str, Enum):
    READY = "ready"  # everything the capability needs is set
    PARTIAL = "partial"  # some set, the rest missing -- almost always a mistake
    OFF = "off"  # nothing set -- intentionally unconfigured (most are optional)


@dataclass(frozen=True)
class Setting:
    """One environment variable the wizard can prompt for."""

    env: str
    prompt: str
    secret: bool = False  # hide on input, and never echo the value back
    required: bool = True  # required *within its capability* (for the readiness verdict)
    example: str = ""


def _truthy_off(value: str | None) -> bool:
    return (value or "").strip().lower() in {"false", "0", "no", "off"}


def _default_assess(settings: tuple[Setting, ...], env: Env) -> tuple[Status, str]:
    """OFF if nothing is set, READY if every *required* var is set, else PARTIAL with the gap."""
    if not any(env.get(s.env) for s in settings):
        return Status.OFF, ""
    missing = [s.env for s in settings if s.required and not env.get(s.env)]
    if missing:
        return Status.PARTIAL, "missing " + ", ".join(missing)
    return Status.READY, ""


@dataclass(frozen=True)
class Capability:
    """A feature the operator can switch on, and the settings that switch it on."""

    key: str
    title: str
    blurb: str
    settings: tuple[Setting, ...]
    # Some capabilities don't reduce to "all required set" (the LLM accepts EITHER an Anthropic
    # key OR a custom endpoint) -- those supply their own verdict.
    assessor: Callable[[Env], tuple[Status, str]] | None = field(default=None)

    def assess(self, env: Env) -> tuple[Status, str]:
        if self.assessor is not None:
            return self.assessor(env)
        return _default_assess(self.settings, env)


def _assess_llm(env: Env) -> tuple[Status, str]:
    """LLM reasoning is optional and accepts two shapes: a plain Anthropic key, or a custom
    OpenAI-compatible endpoint (base URL + model). The kill switch overrides both."""
    if _truthy_off(env.get("STEADYSTATE_LLM_ENABLED")):
        return Status.OFF, "disabled via STEADYSTATE_LLM_ENABLED"
    if env.get("ANTHROPIC_API_KEY"):
        return Status.READY, "Anthropic"
    base, model = env.get("STEADYSTATE_LLM_BASE_URL"), env.get("STEADYSTATE_LLM_MODEL")
    if base and model:
        return Status.READY, f"custom endpoint ({model})"
    if base or model:
        return Status.PARTIAL, "set both STEADYSTATE_LLM_BASE_URL and STEADYSTATE_LLM_MODEL"
    return Status.OFF, "no provider -> deterministic reasoning"


# -- the catalog, grouped by what each capability switches on ---------------------------------

_LLM = Capability(
    "llm",
    "LLM reasoning",
    "AI 'why this matters' + cross-type correlation. Optional -- degrades to deterministic.",
    (
        Setting(
            "ANTHROPIC_API_KEY",
            "Anthropic API key (leave blank to use a custom OpenAI-compatible endpoint)",
            secret=True,
            required=False,
            example="sk-ant-...",
        ),
        Setting(
            "STEADYSTATE_LLM_BASE_URL",
            "Custom OpenAI-compatible base URL",
            required=False,
            example="https://llm.internal/v1",
        ),
        Setting("STEADYSTATE_LLM_MODEL", "Custom endpoint model id", required=False),
        Setting("STEADYSTATE_LLM_API_KEY", "Custom endpoint API key", secret=True, required=False),
    ),
    assessor=_assess_llm,
)

_SLACK = Capability(
    "slack",
    "Slack alerts",
    "Post alerts to a Slack incoming webhook (--to slack).",
    (Setting("SLACK_WEBHOOK_URL", "Slack incoming webhook URL", secret=True),),
)
_TEAMS = Capability(
    "teams",
    "Teams alerts",
    "Post alerts to a Microsoft Teams webhook (--to teams).",
    (Setting("TEAMS_WEBHOOK_URL", "Teams incoming webhook URL", secret=True),),
)
_DISCORD = Capability(
    "discord",
    "Discord alerts",
    "Post alerts to a Discord webhook (--to discord).",
    (Setting("DISCORD_WEBHOOK_URL", "Discord webhook URL", secret=True),),
)
_PROM_PUSH = Capability(
    "prometheus",
    "Prometheus metrics",
    "Push drift/cost metrics to a Pushgateway (--to prometheus).",
    (Setting("PROMETHEUS_PUSHGATEWAY_URL", "Prometheus Pushgateway URL"),),
)
_GRAFANA = Capability(
    "grafana",
    "Grafana annotations",
    "Annotate dashboards when drift is found (--to grafana).",
    (
        Setting("GRAFANA_URL", "Grafana base URL", example="https://grafana.internal"),
        Setting("GRAFANA_TOKEN", "Grafana API token", secret=True),
    ),
)
_WEBHOOK = Capability(
    "webhook",
    "Generic webhook",
    "POST each alert as JSON to any endpoint -- Opsgenie/Jira/ServiceNow/a bus (--to webhook).",
    (Setting("STEADYSTATE_WEBHOOK_URL", "Webhook URL (receives alert JSON)", secret=True),),
)
_PAGERDUTY = Capability(
    "pagerduty",
    "PagerDuty",
    "Open an incident per alert via the Events API v2 (--to pagerduty).",
    (
        Setting(
            "STEADYSTATE_PAGERDUTY_ROUTING_KEY",
            "PagerDuty Events API v2 integration/routing key",
            secret=True,
        ),
    ),
)

_SLACK_LISTEN = Capability(
    "slack-listen",
    "Slack chat-back",
    "Verify inbound Slack approvals/commands (listen --from slack).",
    (Setting("STEADYSTATE_SLACK_SIGNING_SECRET", "Slack signing secret", secret=True),),
)
_TEAMS_LISTEN = Capability(
    "teams-listen",
    "Teams chat-back",
    "Verify inbound Teams @mention commands (listen --from teams).",
    (
        Setting(
            "STEADYSTATE_TEAMS_SECURITY_TOKEN", "Teams outgoing-webhook security token", secret=True
        ),
    ),
)
_DISCORD_LISTEN = Capability(
    "discord-listen",
    "Discord chat-back",
    "Verify inbound Discord slash commands (listen --from discord).",
    (Setting("STEADYSTATE_DISCORD_PUBLIC_KEY", "Discord application public key", secret=True),),
)

_ARGOCD = Capability(
    "argocd",
    "ArgoCD source",
    "Read live Application diffs (--source argocd).",
    (
        Setting("ARGOCD_SERVER", "ArgoCD server (host:port)"),
        Setting("ARGOCD_TOKEN", "ArgoCD auth token", secret=True),
    ),
)
_RANCHER = Capability(
    "rancher",
    "Rancher / Fleet source",
    "Read Fleet GitRepo sync status (--source rancher).",
    (
        Setting("RANCHER_URL", "Rancher URL"),
        Setting("RANCHER_TOKEN", "Rancher API token", secret=True),
    ),
)
_ANSIBLE = Capability(
    "ansible",
    "Ansible source / executor",
    "Playbook + inventory for --check drift and guardrailed remediation.",
    (
        Setting("STEADYSTATE_ANSIBLE_PLAYBOOK", "Playbook path", example="site.yml"),
        Setting("STEADYSTATE_ANSIBLE_INVENTORY", "Inventory path", required=False),
    ),
)

_ENRICH = Capability(
    "enrich",
    "Prometheus enrichment",
    "Escalate a drift whose resource breaches a PromQL bar right now (--enrich prometheus).",
    (
        Setting("PROMETHEUS_URL", "Prometheus base URL"),
        Setting(
            "STEADYSTATE_ENRICH_QUERY",
            "PromQL template ({name} is filled per resource)",
            example='up{instance="{name}"} == 0',
        ),
    ),
)
_SENTINEL_ENRICH = Capability(
    "sentinel",
    "Sentinel enrichment",
    "Escalate a drift that ALSO has an active Microsoft Sentinel incident now (--enrich sentinel).",
    (
        Setting("STEADYSTATE_SENTINEL_WORKSPACE_ID", "Log Analytics workspace ID (GUID)"),
        Setting(
            "STEADYSTATE_SENTINEL_QUERY",
            "KQL template returning active incidents for {name}",
            example="SecurityIncident | where Status in ('New','Active') | where Title has '{name}'",  # noqa: E501
        ),
        Setting("STEADYSTATE_AZURE_TENANT_ID", "Azure AD tenant ID"),
        Setting("STEADYSTATE_AZURE_CLIENT_ID", "Azure AD app (client) ID"),
        Setting("STEADYSTATE_AZURE_CLIENT_SECRET", "Azure AD client secret", secret=True),
    ),
)


def _assess_github_pr(env: Env) -> tuple[Status, str]:
    """github-pr delivery accepts either steadystate's own token or the CI ``GITHUB_TOKEN``."""
    if env.get("STEADYSTATE_GITHUB_TOKEN") or env.get("GITHUB_TOKEN"):
        return Status.READY, "token present"
    return Status.OFF, "set STEADYSTATE_GITHUB_TOKEN (or rely on the CI GITHUB_TOKEN)"


_GITHUB_PR = Capability(
    "github-pr",
    "GitHub PR delivery",
    "Open a PR codifying drift (--deliver github-pr). CI: the Actions GITHUB_TOKEN; else a token.",
    (
        Setting(
            "STEADYSTATE_GITHUB_TOKEN",
            "GitHub token with contents + pull_requests write (blank to use the CI GITHUB_TOKEN)",
            secret=True,
            required=False,
        ),
        Setting(
            "STEADYSTATE_GITHUB_REPO",
            "owner/repo (optional -- auto-detected from the git remote)",
            required=False,
        ),
    ),
    assessor=_assess_github_pr,
)

# Ordered sections -- the order `init` walks and `doctor` prints.
SECTIONS: tuple[tuple[str, tuple[Capability, ...]], ...] = (
    ("Reasoning", (_LLM,)),
    ("Alerts out (--to)", (_SLACK, _TEAMS, _DISCORD, _PROM_PUSH, _GRAFANA, _WEBHOOK, _PAGERDUTY)),
    ("Chat back (listen --from)", (_SLACK_LISTEN, _TEAMS_LISTEN, _DISCORD_LISTEN)),
    ("Source credentials", (_ARGOCD, _RANCHER, _ANSIBLE)),
    ("Live-health enrichment", (_ENRICH, _SENTINEL_ENRICH)),
    ("Remediation delivery (--deliver)", (_GITHUB_PR,)),
)


def capabilities() -> list[Capability]:
    """Every capability in the catalog, flattened (section order)."""
    return [cap for _section, caps in SECTIONS for cap in caps]


# -- audit (the data behind `doctor`) --------------------------------------------------------


@dataclass(frozen=True)
class Row:
    section: str
    capability: Capability
    status: Status
    detail: str


def audit(env: Env) -> list[Row]:
    """Assess every capability against ``env``. Pure: no I/O, no secret values -- the input for
    rendering ``doctor`` and the post-write summary in ``init``."""
    rows: list[Row] = []
    for section, caps in SECTIONS:
        for cap in caps:
            status, detail = cap.assess(env)
            rows.append(Row(section, cap, status, detail))
    return rows


def summary(rows: list[Row]) -> dict[Status, int]:
    counts = {Status.READY: 0, Status.PARTIAL: 0, Status.OFF: 0}
    for row in rows:
        counts[row.status] += 1
    return counts


# -- .env read / write -----------------------------------------------------------------------


def read_env_file(path: Path) -> dict[str, str]:
    """Parse a .env (``KEY=value`` lines; ``#`` comments and blanks ignored). Missing file -> {}.
    Surrounding single/double quotes on a value are stripped, mirroring common dotenv loaders."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def write_env_file(path: Path, updates: Mapping[str, str]) -> dict[str, str]:
    """Merge ``updates`` into the existing .env at ``path`` and write it back, preserving keys
    already there (including ones outside the catalog). Empty-string updates are dropped, never
    written. On POSIX the file is chmod 600 (it holds secrets). Returns the merged mapping.

    Non-destructive by design: re-running `init` to add one capability never wipes the others."""
    merged = dict(read_env_file(path))
    for key, value in updates.items():
        if value:  # only write a value the operator actually supplied
            merged[key] = value
    lines = ["# steadystate environment -- gitignored, holds secrets. Do not commit.", ""]
    lines += [f"{key}={value}" for key, value in merged.items()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if os.name == "posix":  # best-effort tighten; harmless/no-op elsewhere
        with contextlib.suppress(OSError):
            path.chmod(0o600)
    return merged
