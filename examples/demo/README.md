# The 60-second demo

The lowest-friction story steadystate tells: **drop it in CI, it catches a drift, fails the gate,
and hands you the fix.** Deterministic and **offline** — a captured terraform plan, no cloud, no
token — so it records clean every time.

> Heads-up: this folder is the *video material*, not the video. Run it, then **record** it (below).

## Run it

```bash
pip install steadystate          # or run from a checkout
./demo.sh                        # ~60s, paced;  DEMO_PAUSE=0 ./demo.sh  for a fast pass
```

What it shows, in five beats:

1. **The setup** — a normal IaC repo with a committed `steadystate/` (config + runbook).
2. **The break** — someone removed an S3 *logs* bucket's public-access-block (it's now world-readable).
3. **The gate** — `steadystate ci` flags it **CRITICAL** (MITRE T1530) and **fails the build**.
4. **The fix** — `show` surfaces the matched **runbook** entry: the exact command, *signed by an author*.
5. **The point** — detect → gate the merge → hand over the documented fix. `git clone` + a token + one line.

## Record it

### asciinema (recommended for a terminal demo — crisp, tiny, embeddable)

```bash
# capture the run into a cast file
asciinema rec demo.cast -c "./demo.sh"

# share it: upload to asciinema.org ...
asciinema upload demo.cast
# ... or render a GIF for a README / slide (needs `agg`)
agg demo.cast demo.gif
```

An asciinema cast is text, so it's a few KB, stays sharp at any size, and embeds in the main README,
a docs page, or a tweet. For a true `.mp4`, screen-record the asciinema player or the terminal.

### Screen recorder (if you want a voiceover)

Record your terminal (QuickTime / OBS / ScreenStudio), run `./demo.sh`, and read the narration below
over it. Keep the window ~100 cols; a dark theme reads best for the colored output.

## Narration (voiceover script, ~60s)

> **[layout]** "This is a normal infrastructure repo — Terraform — with steadystate committed right
> beside it: a config, and a runbook of known fixes."
>
> **[the break]** "Now someone opens an S3 logs bucket to the world — removes its public-access-block.
> It happens. On the pull request, CI runs one line."
>
> **[`steadystate ci` fails]** "And steadystate stops it. A *critical* exposure — MITRE T1530, data
> exposed — so the merge can't land. No cloud credentials, no agent, no server. Just the repo."
>
> **[`show` → the fix]** "And it doesn't just say no. It already knows the fix — it's in your
> committed runbook, matched to this finding, signed by whoever vouched for it."
>
> **[close]** "Detect, gate the merge, hand you the documented fix. That's steadystate in CI:
> git clone, a token, one line. `pip install steadystate`."

## Posting it

- Embed the asciinema cast or GIF at the top of the main [README](../../README.md).
- The same story is the [`repo-native`](../repo-native/) example (the real GitHub Actions workflow).
- In a real repo, point `steadystate/config.toml`'s `path` at your terraform dir (and use
  `source = "terraform-state"` for a no-cloud-creds gate) instead of the captured `plan.json` here.
