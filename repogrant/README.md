# RepoGrant

**Compute the effective agent authority a repository grants — per tool, under each tool's documented semantics, including the silent-config defaults.**

A repository now carries a second, invisible configuration layer: the files that tell AI coding agents what they may do (`.claude/settings.json`, `.codex/config.toml`, `.cursor/*`, `.gemini/settings.json`, `.mcp.json`, `AGENTS.md`, …). Each agent tool reads a *different* subset of that surface, under *different* documented semantics and *different* defaults. The same repo can look locked down in one tool and be wide open in another, and a cloned repo's hooks can run code the moment a session starts.

RepoGrant is an offline, deterministic verifier. Input: a repository tree. Output, per tool: the effective authority the repo grants across six dimensions, with the gaps flagged — and what each tool grants **when the repo is silent**.

## Install / run

Stdlib only (Python ≥ 3.11 for `tomllib`). No network, no state.

```bash
python3 -m repogrant check /path/to/repo            # JSON report to stdout
python3 -m repogrant check /path/to/repo --out r.json
python3 -m repogrant defaults --md --out DEFAULTS_MATRIX.md   # Part B
# or install the console script:
pip install -e .
repogrant check /path/to/repo
```

## What it computes

**Authority model** — per tool, per dimension, resolved from config **plus the documented default where config is silent**:

| Dimension | meaning |
|---|---|
| `command_execution` | can the agent run shell without per-call consent? |
| `filesystem_read` / `filesystem_write` | read/write scope (workspace / +dirs / unrestricted) |
| `network_egress` | off / allowlist / on, and how it's gated |
| `secret_reach` | can the agent read secret-bearing paths (`.env`, keys)? |
| `auto_approval` | hooks / trusted servers that execute without per-run consent |

Every cell is `config`, `default` (with a verbatim doc quote + URL), or **`not-judgeable`** with a reason. Malformed or unknown config is **never silently dropped**.

**Checks**

- **R1 — hook execution surface.** Hooks / auto-run commands that run without per-run consent. *Models the real divergence:* Claude Code repo hooks run with **no trust prompt under `claude -p`/CI**; Codex repo hooks are **per-hash trust-gated** (lower severity); a Gemini `trust: true` server bypasses all confirmations.
- **R2 — pre-approval overreach.** Allowlist breadth resolved **semantically** (`Bash(git:*)` auto-approves every `git` invocation; the docs call Bash arg-constraints "fragile" and "not a security boundary"), not by regex.
- **R3 — cross-tool divergence.** The same repo grants materially different authority to different tools (locked in X, open in Y), plus instruction-file contradictions.
- **R4 — silence-is-not-safety.** Where the repo is silent, the documented default grants more than it looks (Gemini honors `.gemini/` + `.env` by default with Folder Trust off; Codex defaults to `workspace-write` in a version-controlled folder).
- **R5 — secret-reach composition.** read-secret ∧ (network egress ∨ write-outside) = a composed exfiltration path, even when no single setting is alarming.
- **R6 — unpinned execution supply chain.** `npx -y pkg`, `pkg@latest`, unpinned `uvx`, `curl … | bash` in MCP launch specs and hooks.

> Scope (ratified Gate 0): the **semantic effective-authority model + R3/R4/R5** is the headline wedge. R1/R6 and pattern-level R2 are measured and reported but are already commoditized by agent-config linters — not pitched as novel. Copilot is **instruction-divergence only**; its command/sandbox authority is `not-judgeable` from the repo.

## Determinism

Same input tree → **byte-identical** report (no timestamps, no absolute paths, no randomness). `repogrant.report.to_json` is the canonical serialisation.

## Layout

```
repogrant/            core package (parsers, authority model, checks, CLI)
  parsers/            one module per tool + shared instruction handling
  checks/             R1–R6
  defaults.py         documented-defaults registry (Part B + R4 source of truth)
  authority.py        the semantic effective-authority model
bench/                dev bench: fixture generator, repos, labels, runner
tests/                unit tests (parsers, authority, checks)
DEFAULTS_MATRIX.md    Part B rendered audit document
```

## Dev bench / Gate 1

```bash
python3 bench/make_repos.py    # (re)generate fixtures + labels
python3 bench/runner.py        # score against the Gate 1 bars
python3 -m unittest discover -s tests
```

The bench is a **self-consistency / regression** harness, not evidence of generalization; the sealed holdout (Gate 2) is Phase 2.
