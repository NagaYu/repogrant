# RepoGrant

**Compute the effective agent authority a repository grants — per tool, under
each tool's documented semantics, including the silent-config defaults.**

A repository now carries a second, invisible configuration layer: the files
that tell AI coding agents what they may do (`.claude/settings.json`,
`.codex/config.toml`, `.cursor/*`, `.gemini/settings.json`, `.mcp.json`,
`AGENTS.md`, …). Each agent tool (Claude Code, OpenAI Codex CLI, Cursor, GitHub
Copilot, Gemini CLI) reads a *different* subset of that surface, under
*different* documented semantics and *different* defaults. The same repo can
look locked down in one tool and be wide open in another, and a cloned repo's
hooks can run code the moment a session starts. Nobody computes that
cross-tool effective authority. RepoGrant does.

RepoGrant is an **offline, deterministic** verifier. Input: a repository tree.
Output, per tool: the effective authority the repo grants across six
dimensions, with the gaps flagged — and what each tool grants **when the repo
is silent**. Stdlib only (Python ≥ 3.11 for `tomllib`); no network, no state;
same input tree → **byte-identical** JSON report.

```bash
python3 -m repogrant check /path/to/repo            # JSON report to stdout
python3 -m repogrant check /path/to/repo --out r.json
python3 -m repogrant defaults --md                  # Part B: the defaults matrix
```

See `repogrant/README.md` for the full dimension/check reference,
`SEMANTICS.md` for the primary-source documented semantics (verbatim quotes +
citations), `repogrant/DEFAULTS_MATRIX.md` for Part B, and
`field-audit/README.md` for the wild-repo validation.

## Checks

- **R1 — hook / auto-run execution surface.** Claude Code repo hooks run with
  **no trust prompt under `claude -p`/CI**; Codex repo hooks are **per-hash
  trust-gated** (lower severity); a Gemini `trust: true` server bypasses all
  confirmations; a Cursor `terminalAllowlist`/`autoRun: true` auto-runs.
- **R2 — pre-approval overreach.** Allowlist breadth resolved **semantically**
  (`Bash(git:*)` auto-approves every `git`; the docs call Bash arg-constraints
  "fragile" and "not a security boundary").
- **R3 — cross-tool divergence.** The same repo grants materially different
  authority to different tools, plus instruction-file contradictions.
- **R4 — silence-is-not-safety.** Where the repo is silent, the documented
  default grants more than it looks (Gemini honors `.gemini/` + `.env` by
  default with Folder Trust off; Codex defaults to `workspace-write` in a
  version-controlled folder).
- **R5 — secret-reach composition.** read-secret ∧ (network egress ∨
  write-outside) = a composed exfiltration path.
- **R6 — unpinned execution supply chain.** `npx -y pkg`, `pkg@latest`,
  unpinned `uvx`, `pnpm dlx`/`yarn dlx`/`bunx`, `pip install git+…`,
  `curl … | bash` in MCP launch specs and hooks.

The **semantic effective-authority model + R3/R4/R5** is the headline wedge.
R1/R6 and pattern-level R2 are measured and reported but already commoditized
by agent-config linters. Copilot is **instruction-divergence only**; its
command/sandbox authority is `not-judgeable` from the repo. Malformed or
unknown config is surfaced as `not-judgeable`, **never silently dropped**.

## Validation

**Gate 1 — dev bench (self-consistency / regression).** 10 clean, 15 mutation,
2 malformed fixtures. **GO:** per-class recall **1.00**, clean-repo false
positives **0 / 60** (repo,check) pairs, zero silent drops, byte-identical
determinism. The dev bench is a self-authored regression harness, not evidence
of generalization.

**Gate 2 — sealed holdout (scored once).** 8 clean, 16 mutation, 1 malformed
(59 files), authored from the semantics register and sealed by content hash
before scoring. **GO:** recall **1.00** on every class (bars ≥0.85 / ≥0.75),
severity **34/34**, clean FP **1/48 = 0.021** (bar ≤0.03), zero silent drops,
determinism. The holdout is stronger than Gate 1 (novel scenarios; it exposed a
real false positive) but is **not fully independent** — the holdout author is
the checker author.

**Field audit — wild public repos (the decisive test).** 120 real public
GitHub repos nobody curated for this tool. **94.2%** trip the R4 defaults trap;
**27.5%** show cross-tool divergence; parse problems surfaced, never dropped.
Hand-checked precision is reported honestly in `field-audit/README.md`,
including two named residual limitations. This is the un-gameable validation
the self-authored benches cannot provide.

## Disclosed defect-and-fix history

RepoGrant is shipped with its defects disclosed, not hidden. The sealed holdout
(Gate 2) and an adversarial fuzz + the field audit found the following, all
fixed and regression-tested before this export:

- **Cursor `autoRun:false` false positive (owner-named).** A team *explicitly
  disabling* auto-run (`{"autoRun": false}`) was flagged as auto-running
  commands. **Root cause:** presence-based, not value-aware. **Fix:** boolean
  toggles are interpreted with a safe coercion (`"false"`/`0`/`null` read as
  off); `autoRun` grants only on a real `true`. The same value-aware fix was
  applied to every boolean toggle (Gemini Folder Trust, Codex `features.hooks`,
  Codex / Gemini network access, MCP `trust`).
- **Crash on non-string permission entries.** A `.claude/settings.json` with a
  non-string `permissions.allow` entry crashed the rule parser. **Fix:**
  non-string rules are ignored.
- **False finding on a non-list allowlist.** A Cursor `terminalAllowlist` given
  an object was read as entries. **Fix:** list-type guard.
- **Present-file-read-as-absent.** A config file whose top-level JSON is `null`
  was treated as absent. **Fix:** surfaced as a parse-problem (not-judgeable).
- **R6 evasion via alternative runners.** `pnpm dlx` / `yarn dlx` / `bunx` were
  not recognized. **Fix:** treated like `npx`.
- **Secret over-match (found by the field audit).** `.env.example` /
  `.env.template` / `.env.sample` / `.envrc` were treated as secret-bearing,
  inflating R4/R5. **Fix:** these template variants are excluded.

**Known residual limitations (disclosed):** the `.pem`/`.key` secret matcher
does not distinguish public certificates from private keys (possible
low-actionability R4); the Codex parser does not model the newer granular
`[permissions.*]` config grammar. Both are named in `field-audit/README.md`.

## Layout

```
README.md             this file (lead)
SEMANTICS.md          primary-source documented semantics (quotes + citations)
repogrant/            the checker package, dev bench, tests, Part B matrix
field-audit/          wild-repo validation: aggregates.json + method/results
```
