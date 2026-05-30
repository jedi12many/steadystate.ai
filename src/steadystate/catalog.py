"""A self-describing catalog of what steadystate can do: every plugin and every command.

The plugin system is already a set of in-memory registries (one per seam) and the CLI is a
Typer/click app, so "show me everything" is just *introspection* -- no new source of truth. We
gather both into a small data model (`Catalog`) once, then render it two ways: a rich console
overview (`render_console`) and a self-contained HTML page (`render_html`). Adding a plugin or a
command makes it appear here automatically; there is nothing to keep in sync.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any

from .act import EXECUTORS
from .domains import DEFAULT_DOMAINS
from .inbound import INBOUND
from .notify import SURFACES
from .reason.enrich import ENRICHERS
from .reason.pipeline import CORRELATORS
from .sources import CAPABILITIES, DRIFT_SOURCES


@dataclass
class PluginItem:
    name: str
    detail: str = ""  # an optional one-liner (e.g. a source's command counts)


@dataclass
class Seam:
    title: str  # "Sources"
    flag: str  # how you select it, e.g. "--source" or "listen --from" ("" if none)
    items: list[PluginItem]


@dataclass
class OptionInfo:
    flags: str  # "--source"
    help: str


@dataclass
class CommandInfo:
    name: str
    help: str
    options: list[OptionInfo] = field(default_factory=list)


@dataclass
class Catalog:
    seams: list[Seam]
    commands: list[CommandInfo]


def _names(registry: dict) -> list[PluginItem]:
    return [PluginItem(name) for name in sorted(registry)]


def _source_items() -> list[PluginItem]:
    """Sources, annotated with how many observe vs act commands each declares."""
    items = []
    for name in sorted(DRIFT_SOURCES):
        caps = CAPABILITIES.get(name)
        detail = ""
        if caps is not None:
            detail = f"{len(caps.observe)} observe, {len(caps.destructive)} act"
        items.append(PluginItem(name, detail))
    return items


def _seams() -> list[Seam]:
    """Every plugin seam and what's registered in it, read live from the registries."""
    return [
        Seam("Sources", "--source", _source_items()),
        Seam("Domains", "(auto)", [PluginItem(d.name) for d in DEFAULT_DOMAINS]),
        Seam("Surfaces (out)", "--to", _names(SURFACES)),
        Seam("Inbound (approvals)", "listen --from", _names(INBOUND)),
        Seam("Executors", "fix --source", _names(EXECUTORS)),
        Seam("Correlators", "--correlator", [PluginItem("auto"), *_names(CORRELATORS)]),
        Seam("Enrichers", "--enrich", _names(ENRICHERS)),
    ]


def _commands(cli: Any) -> list[CommandInfo]:
    """Each CLI command + its options, introspected from the (click) command group typer builds,
    so the help text is the same single source the `--help` output uses. Duck-typed -- click
    isn't a direct import here -- via each param's ``param_type_name`` ('option' vs 'argument')."""
    commands = []
    for name in sorted(cli.commands):
        command = cli.commands[name]
        options = []
        for param in command.params:
            # list options only; arguments are positional and the --help flag is auto-added.
            if getattr(param, "param_type_name", "") != "option" or param.name == "help":
                continue
            options.append(OptionInfo(" / ".join(param.opts), (param.help or "").strip()))
        commands.append(CommandInfo(name, (command.help or "").strip().split("\n")[0], options))
    return commands


def gather_catalog(cli: Any) -> Catalog:
    """Build the full catalog from the live plugin registries and the CLI's own command tree."""
    return Catalog(seams=_seams(), commands=_commands(cli))


# -- renderers ------------------------------------------------------------------


def render_console(catalog: Catalog, console) -> None:
    """Print the catalog as a rich console overview (plugins table + commands list)."""
    from rich.table import Table

    plugins = Table(title="Plugins", header_style="bold", title_justify="left")
    plugins.add_column("Seam", style="bold")
    plugins.add_column("Select with", style="cyan")
    plugins.add_column("Available")
    for seam in catalog.seams:
        rendered = " · ".join(
            f"{item.name} [dim]({item.detail})[/dim]" if item.detail else item.name
            for item in seam.items
        )
        plugins.add_row(seam.title, seam.flag, rendered or "[dim]none[/dim]")
    console.print(plugins)

    console.print("\n[bold]Commands[/bold]")
    for command in catalog.commands:
        console.print(f"  [bold]{command.name}[/bold]  [dim]{command.help}[/dim]")
        for option in command.options:
            console.print(f"      [cyan]{option.flags}[/cyan]  [dim]{option.help}[/dim]")


_HTML_STYLE = """
body { font: 15px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 900px;
       margin: 2rem auto; padding: 0 1rem; color: #1f2328; background: #fff; }
h1 { font-size: 1.6rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #d0d7de; padding-bottom: .3rem; }
.seam { margin: .6rem 0; }
.seam .title { font-weight: 600; }
.seam .flag { color: #0969da; font-family: ui-monospace, monospace;
              font-size: .85em; margin-left: .4rem; }
.chip { display: inline-block; background: #eaeef2; border-radius: 6px;
        padding: .1rem .5rem; margin: .15rem .2rem;
        font-family: ui-monospace, monospace; font-size: .85em; }
.chip .d { color: #57606a; font-size: .85em; }
.cmd { margin: .8rem 0; }
.cmd .name { font-weight: 600; font-family: ui-monospace, monospace; }
.cmd .help { color: #57606a; }
.opt { margin: .15rem 0 .15rem 1.4rem; }
.opt code { color: #0969da; }
.opt .h { color: #57606a; }
"""


def render_html(catalog: Catalog) -> str:
    """Render the catalog as a single self-contained HTML page (no external assets)."""

    def esc(text: str) -> str:
        return html.escape(text)

    rows = []
    for seam in catalog.seams:
        chips = "".join(
            f'<span class="chip">{esc(item.name)}'
            + (f' <span class="d">{esc(item.detail)}</span>' if item.detail else "")
            + "</span>"
            for item in seam.items
        )
        rows.append(
            f'<div class="seam"><span class="title">{esc(seam.title)}</span>'
            f'<span class="flag">{esc(seam.flag)}</span><div>{chips or "<em>none</em>"}</div></div>'
        )

    cmds = []
    for command in catalog.commands:
        opts = "".join(
            f'<div class="opt"><code>{esc(option.flags)}</code> '
            f'<span class="h">{esc(option.help)}</span></div>'
            for option in command.options
        )
        cmds.append(
            f'<div class="cmd"><span class="name">{esc(command.name)}</span> '
            f'<span class="help">— {esc(command.help)}</span>{opts}</div>'
        )

    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>steadystate.ai — catalog</title><style>{_HTML_STYLE}</style></head><body>"
        "<h1>steadystate.ai — catalog</h1>"
        "<p>Every plugin and command this build offers, generated from the live registries.</p>"
        "<h2>Plugins</h2>" + "".join(rows) + "<h2>Commands</h2>" + "".join(cmds) + "</body></html>"
    )
