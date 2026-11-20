# RepoGrant — field audit over wild public repos

The decisive, un-gameable validation: RepoGrant run against **real public
GitHub repositories that nobody curated for this tool**. This file documents
the method and the aggregate results. `aggregates.json` holds the machine
numbers. **Individual repository names are deliberately not published** — the
audit judges a population, not named projects.

## Method

- **Sampling.** GitHub code search (authenticated, read-only, public data
  only) over five surfaces, up to 40 repos per surface, deduplicated to **120
  unique repositories**:
  - `.claude/settings.json`, `.codex/config.toml`, `.gemini/settings.json`,
    `.cursor/permissions.json`, `.mcp.json`.
- **Materialization.** For each repo, the git tree was read and only the
  canonical agent-config surfaces were fetched (settings/config/hooks/mcp/rules
  and instruction files). Public GitHub repos are version-controlled, so each
  materialized tree carries a `.git/` marker (Codex's version-controlled
  default applies, exactly as it would for a real clone). Downloaded files are
  treated as untrusted data: they are only ever parsed (JSON/TOML), never
  executed.
- **Determinism caveat.** The sample reflects GitHub's live search index at
  audit time; re-running may draw a slightly different population. The numbers
  below are a snapshot, not a byte-stable artifact (unlike the checker's
  per-repo output, which is deterministic).

## Headline results (post-fix checker)

- **120 repos analyzed, 0 errored**, 1 with a truncated (very large) tree.
- **119 / 120 (99.2%)** carry at least one finding.
- **R4 "silence-is-not-safety" defaults trap: 113 / 120 (94.2%)** — the single
  most prevalent class. The dominant driver is Codex's version-controlled
  `workspace-write` default firing on any git repo that is silent for Codex
  (correct per the documented default; see the actionability note below).
- **R3 cross-tool divergence: 33 / 120 (27.5%)** — more than a quarter of
  sampled repos grant materially different authority across tools, or have
  instruction files that contradict their machine config.
- **Parse problems surfaced (never silently dropped): 8 / 120 (6.7%)**.
- Findings by class: R1 363 · R2 288 · R3 36 · R4 174 · R5 5 · R6 33.
- Findings by tool: Claude Code 585 · Codex 208 · Gemini 82 · Cursor 84 ·
  Copilot 33.

## Hand-checked precision (honest)

A sample of findings was verified against the actual repo config, and a sample
of zero-finding verdicts was checked for missed risk:

- **Confirmed true positives** included: a Codex config with
  `sandbox_mode = "danger-full-access"` + `approval_policy = "never"` (wide
  open, R5 composition); `network_access = true` under workspace-write (R5);
  unpinned `npx -y …@latest` MCP servers (R6); a Claude `Stop` hook driving an
  R3 auto-approval divergence; broad `Bash(<prog>:*)` allows (R2); a Cursor
  `terminalAllowlist` auto-running `git` (R1).
- **Residual over-report (named):** the secret matcher flags any `.pem`/`.key`
  file, and does **not** distinguish a public certificate (`*-cert.pem`) from a
  private key. A repo carrying only public/test certs can therefore trip a
  medium R4 "secret reach" with low actionability. Disclosed, not hidden.
- **Residual under-coverage (named):** the Codex parser models
  `approval_policy` / `sandbox_mode` / `sandbox_workspace_write` / `features`,
  but not the newer granular `[permissions.*]` tables some repos now use. In
  the one hand-checked case the verdict was still appropriate (the config was
  restrictive), but RepoGrant does not yet model that grammar.
- **Actionability note on R4.** The near-universal R4 rate is dominated by the
  Codex version-controlled `workspace-write` default, which is a property of
  Codex (it holds for essentially every git repo) rather than of the specific
  repo. The higher-signal R4s are Claude secret-reach *when a real secret is
  committed* and Gemini Folder-Trust *when a `.gemini/` config is present*.

## Effect of the Phase 3 fixes (same 120 repos, byte-identical inputs)

Re-running the audit on the identical cached inputs after the fixes removed
**67 spurious findings and added none**:

| Removed finding (defect family) | count |
|---|---|
| R4 Claude "in-workspace secrets" firing on `.env.example`/templates | 31 |
| R4 Gemini Folder-Trust firing with no real secret and no `.gemini/` config | 28 |
| R1 Cursor `autoRun:false` false positive | 8 |

No real finding was lost (R2/R3/R5/R6 counts unchanged); the only deltas were
the spurious removals. This confirms the defect families' effect is gone in the
wild, not just on the authored bench.
