#!/usr/bin/env python3
"""Register the /steadystate approve|decline slash command on your Discord application.

One-time setup so an operator can approve a pending remediation from Discord. Stdlib only
(urllib) -- no install needed. Reads the command shape from command.json next to this file.

Environment:
  DISCORD_APP_ID     your application's ID (Developer Portal -> General Information)
  DISCORD_BOT_TOKEN  a bot token for that application (Developer Portal -> Bot)
  DISCORD_GUILD_ID   (optional) register to one server -- updates instantly, ideal for testing;
                     omit to register globally (can take up to an hour to propagate)

Usage:
  DISCORD_APP_ID=... DISCORD_BOT_TOKEN=... DISCORD_GUILD_ID=... python deploy/discord/register.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

_API = "https://discord.com/api/v10"
# Discord's Cloudflare edge bans the default "Python-urllib/x" User-Agent (error 1010); send a
# real one, matching the Discord surface (notify/discord.py).
_USER_AGENT = "steadystate (+https://github.com/jedi12many/steadystate.ai)"


def main() -> int:
    app_id = os.environ.get("DISCORD_APP_ID")
    token = os.environ.get("DISCORD_BOT_TOKEN")
    guild_id = os.environ.get("DISCORD_GUILD_ID")
    if not app_id or not token:
        print("set DISCORD_APP_ID and DISCORD_BOT_TOKEN", file=sys.stderr)
        return 2

    command = json.loads((Path(__file__).parent / "command.json").read_text())
    if guild_id:
        url = f"{_API}/applications/{app_id}/guilds/{guild_id}/commands"
        scope = f"guild {guild_id} (instant)"
    else:
        url = f"{_API}/applications/{app_id}/commands"
        scope = "global (may take up to an hour)"

    request = urllib.request.Request(
        url,
        data=json.dumps(command).encode(),
        headers={
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        },
        method="POST",  # create-or-update by name
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            response.read()
    except urllib.error.HTTPError as exc:
        print(
            f"registration failed: {exc.code} {exc.read().decode('utf-8', 'replace')}",
            file=sys.stderr,
        )
        return 1
    except urllib.error.URLError as exc:
        print(f"registration failed: {exc}", file=sys.stderr)
        return 1

    print(f"registered /steadystate on {scope}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
