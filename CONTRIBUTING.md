# Contributing to steadystate.ai

Thanks for helping build the drift-reasoning engine. This guide mirrors what CI
actually does, so if it passes locally it passes on the runner.

Read **[ARCHITECTURE.md](./ARCHITECTURE.md)** first. The whole codebase is organized
around a handful of plugin seams — StateSource · Domain · Surface (and its Inbound
counterpart) · Executor · Correlator, plus the Enricher and Probe seams (ARCHITECTURE.md
§6); most contributions are a plugin against one of those seams, not a change to the core.

## Dev setup

Python 3.11+. Same steps CI runs (venv-based; we don't rely on a system install):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

(The `[llm]` extra pulls in `anthropic` for the LLM-backed reasoning; it's
optional and not needed to run the tests.)

## The checks (these mirror CI)

Run all of these before opening a PR. They are the CI gates:

```sh
ruff check src tests             # lint
ruff format --check src tests    # formatting
mypy src                         # types
pytest                           # tests (with coverage)
bandit -r src -c pyproject.toml  # security lint (SAST)
```

CI additionally runs **pip-audit** (dependency CVEs) and **CodeQL** (deeper SAST) from
`.github/workflows/security.yml` and `codeql.yml`. You don't need to run those locally, but a
PR must pass them; the bandit config (reviewed skips + rationale) lives in `[tool.bandit]` in
`pyproject.toml`.

CI runs on **GitHub-hosted runners**, so keep the test suite fast, deterministic, and free of
network/live-infra calls (the live `terraform` paths in `act/` are deliberately not exercised
by unit tests). **All PRs must pass CI before merge.**

## Branches & commits

- Branch names: `feat/<seam>-<thing>` (e.g. `feat/sources-pulumi`,
  `feat/domains-cis`).
- [Conventional Commits](https://www.conventionalcommits.org/), scoped to the
  seam you touched: `feat(sources): add pulumi DriftSource`,
  `feat(domains): add CIS compliance pack`, `fix(act): ...`, `docs: ...`.

## Adding a plugin

The plugin registries are live, so a new plugin is a module plus **one** registry
line plus a test. The registry tests (`tests/test_registry.py`) fail if a
registered plugin isn't actually reachable, so a built-but-unwired plugin can't
ship silently.

### A new drift source

1. Write `src/steadystate/sources/<name>.py` implementing the `DriftSource`
   Protocol (`name` + `collect_drift() -> list[Drift]`; see
   `src/steadystate/sources/base.py`).
2. Add **one** line to `DRIFT_SOURCES` in `src/steadystate/sources/__init__.py`:
   `"<name>": <factory>`, mapping the `--source <name>` choice to a
   `factory(path) -> DriftSource`.
3. Add a representative input for `<name>` to `_inputs()` in
   `tests/test_registry.py` (the wiring test constructs and runs every
   registered source), plus a focused test under `tests/`.

The CLI dispatcher (`scan --source <name>`) and its tests then pick it up
automatically -- no other edits.

### A new domain pack

1. Write `src/steadystate/domains/<name>.py` implementing the `Domain` Protocol
   (`name` + `score(drift) -> Severity | None`; see
   `src/steadystate/domains/base.py`). This is how security/compliance (CIS,
   STIG, ...) enter -- as packs, never as core.
2. Append your pack to `DEFAULT_DOMAINS` in
   `src/steadystate/domains/__init__.py`. `pipeline.py` doesn't change.
3. Add a test under `tests/`.

For the Surface and Executor seams, see their Protocols in
`src/steadystate/notify/base.py` and `src/steadystate/act/base.py`, and
ARCHITECTURE.md §6.

## Anything that can act on live infrastructure

Remediation goes through the guardrails -- apply-eligibility, snapshot, verify,
revert -- and a live apply runs only behind **both** apply-eligibility **and** an
explicit confirm (`--apply`). If your change touches `act/` (the planner,
executors, or the eligibility rules), keep the guardrails intact, keep the
eligibility logic pure and deterministic so it stays unit-testable without real
infra, and cover it with tests. See also [SECURITY.md](./SECURITY.md).

## License

By contributing you agree your contributions are licensed under the project's
[Apache-2.0](./LICENSE) license.
