# RepoGrant — documented config semantics (primary-source register)

This document records the **documented semantics** RepoGrant relies on to
compute effective agent authority, per tool. Every claim carries a **verbatim
quote** (in quotation marks) and the **primary-source URL** it came from.
Where a tool's primary docs are silent or ambiguous on a point RepoGrant would
otherwise judge, that cell is **`not-judgeable` by design** — recorded, never
guessed.

Quotes are reproduced as captured from the official docs; some were
length-capped at the source. This file contains only documented facts and
citations — no product-internal decisions.

Dimensions per tool: **(A)** repo-side files read + precedence · **(B)**
permission / sandbox / approval model · **(C)** hook / auto-run execution
surface and its consent model · **(D)** documented defaults with no repo
config · **(E)** how repo-declared MCP servers launch.

---

## 1. Claude Code (Anthropic)

Sources: `code.claude.com/docs/en/settings`,
`code.claude.com/docs/en/settings-reference`,
`code.claude.com/docs/en/permissions`, `code.claude.com/docs/en/hooks`,
`code.claude.com/docs/en/mcp`.

**(A) Files + precedence.** `Project` is `.claude/settings.json`, `Local` is
`.claude/settings.local.json` (settings-reference). "Settings precedence,
highest first: managed settings, command line, project local, shared project,
user." For list keys: "When you set the same list key, such as
`permissions.allow`, in more than one file, Claude Code combines the lists
instead of picking one." Trust gating: "`permissions.allow` rules,
`permissions.additionalDirectories` … apply only after each teammate trusts
the folder"; "`deny` and `ask` rules apply right away." (settings)

**(B) Permission model.** "Permission rules follow the format `Tool` or
`Tool(specifier)`." "Bash rules match the whole command text, with `*`
standing in for any text." "`Bash(ls *)` requires a space after `ls`, so
`lsof` doesn't match. `Bash(ls*)` has no space, so it matches `lsof` too."
"The `:*` suffix is an equivalent way to write a trailing wildcard." Evaluation:
"Rules are evaluated in order: deny, then ask, then allow." "An allow rule
can't carve an exception out of a deny rule." **Fragility (central to R2):**
"Bash permission patterns that try to constrain command arguments are
fragile." "…isn't a security boundary around the program." "If Bash is
allowed, Claude can still use `curl`, `wget`, or other tools to reach any
URL." (permissions)

Modes (permissions): `default` "Prompts before most edits, shell commands, and
network requests."; `acceptEdits` "Automatically accepts file edits and common
filesystem commands such as `mkdir`, `touch`, `mv`, and `cp`…"; `plan` "reads
files and runs read-only shell commands … but doesn't edit your source files".
"`auto` and `bypassPermissions` don't take effect from project or local
settings" (settings-reference).

**(C) Hooks (the key R1 finding).** "Hooks are user-defined shell commands …
that execute automatically at specific points in Claude Code's lifecycle."
"Claude Code checks workspace trust before it runs any hook from a settings
file." Interactive runs hold hooks until the workspace-trust dialog is
accepted; but for a **`-p` or SDK session**: "Claude Code never shows the
dialog and treats the folder as trusted, so hooks committed in a repository's
`.claude/settings.json` run in a folder you've never trusted." (hooks) →
repo-committed hooks run **with no per-run consent under `claude -p`/CI**.

**(D) Defaults.** Default mode `default` ("Prompts before most edits, shell
commands, and network requests"), plus file access to the launch directory
("By default, Claude has access to files in the directory where you launched
it"); no sandbox unless opted into (permissions). The docs give no single
"no-config authority" sentence.

**(E) MCP launch.** "add the entry under `mcpServers` in `.mcp.json` at your
project root and commit it." Project servers are approval-gated: "A cloned
repository can't approve its own servers"; `enableAllProjectMcpServers` /
`enabledMcpjsonServers` "is ignored in an untrusted folder". Docs show
unpinned `npx -y` examples and make **no** version-pinning statement (R6).
(mcp)

---

## 2. OpenAI Codex CLI

Sources: `learn.chatgpt.com/docs/config-file/config-reference`,
`learn.chatgpt.com/docs/sandboxing`,
`learn.chatgpt.com/docs/agent-approvals-security`,
`learn.chatgpt.com/docs/hooks.md`.

**(A) Files + precedence.** Project overrides live in `.codex/config.toml`;
"Codex loads project-scoped config files only when you trust the project."
"Untrusted projects skip project-scoped `.codex/` layers, including
project-local config, hooks, and rules." (config-reference)

**(B) Permission model (approvals × sandbox).** "Sandboxing and approvals are
different controls that work together." `approval_policy`: "`on-request |
never | { granular = … }`". `sandbox_mode`: "`read-only | workspace-write |
danger-full-access`". Per-value (sandboxing): read-only "The agent can inspect
files, but it can't edit files or run commands without approval.";
workspace-write "The agent can read files, edit within the workspace, and run
routine local commands inside that boundary. This is the default low-friction
mode for local work."; danger-full-access "removes the filesystem and network
boundaries". Network: "the default `workspace-write` sandbox mode keeps network
access turned off unless you enable it" (`sandbox_workspace_write.network_access
= true`). "`<writable_root>/.git` is protected as read-only."

**(C) Hooks (per-hash trust-gated — the R1 divergence from Claude).** "Hooks
are enabled by default." To disable: `[features]` / `hooks = false`.
Consent: "Non-managed hooks must be reviewed and trusted before they run."
"Codex records trust against the hook's current hash, so new or changed hooks
are marked for review and skipped until trusted." The only no-prompt path:
"pass `--dangerously-bypass-hook-trust` to run enabled hooks without requiring
persisted hook trust for that invocation." (hooks) → repo hooks are
**consent-gated**, a lower R1 severity than Claude's silent `-p` execution.
How a layer becomes "trusted", and which shell runs `command` handlers, are
**not stated** → not asserted.

**(D) Defaults.** "By default, the agent runs with network access turned off."
"Version-controlled folders: `Auto` (workspace write + on-request approvals)";
"Non-version-controlled folders: `read-only`." (The sandboxing page separately
calls workspace-write "the default low-friction mode for local work"; the docs
do not reconcile the two statements — recorded, not resolved.)

**(E) MCP launch.** `mcp_servers.<id>.command` "Launcher command for an MCP
stdio server.", `.args`, `.env`. No version-pinning statement on the page (R6).

---

## 3. Cursor (Anysphere)

Sources: `cursor.com/docs/reference/permissions` (IDE `permissions.json`),
`cursor.com/docs/agent/security/run-modes`, `cursor.com/docs/context/rules`,
`cursor.com/docs/context/mcp`.

**(A) Files + precedence.** Rules: "Stored in `.cursor/rules`,
version-controlled… Project rules must use the `.mdc` extension. A plain `.md`
file in `.cursor/rules` is ignored." IDE `permissions.json` is read per-user
and per-repo; "When both exist, Cursor concatenates the arrays inside every
field." The IDE `permissions.json` uses `mcpAllowlist`, `terminalAllowlist`,
`autoRun` (no allow/deny/ask arrays).

**(B) Permission model.** `terminalAllowlist` matching: "Matching is
case-sensitive and uses prefix semantics: `git` matches `git status` but not
`gitk`." "Non-string entries inside either array are silently dropped."
Requirement: "`permissions.json` only takes effect when Run Mode is enabled in
Cursor Settings (Auto-review, Allowlist, or Run Everything)." **Security
caveats (central to R2):** "Not a security boundary. Allowlists and `autoRun`
instructions are best-effort convenience. They are not a security guarantee."
`autoRun` is a boolean toggle; it enables auto-run only when set `true` — a
`false`/absent value grants nothing.

**(C) Execution surface.** No repo-declared shell-**hook** mechanism is
documented; Cursor's repo-side execution surface is `.cursor/rules`
instructions plus the auto-run allowlist. Launch-time consent for a
project-declared MCP server is **not documented** → not-judgeable; only the
documented per-tool-call default is recorded: "Cursor asks for approval before
using MCP tools by default." (mcp)

**(D) Defaults.** The docs state **no** repo-side "no-config" default authority;
"default behaviour depends on the user's Run Mode selection (Cursor Settings),
which is not a repo-side artifact." → Cursor's non-MCP authority is
`not-judgeable` from the repo.

**(E) MCP launch.** "Create `.cursor/mcp.json` in your project for
project-specific tools." Stdio fields: `command` ("Must be available on your
system path…"), `args`, `env`, `envFile`; example `"command": "npx"`,
`"args": ["-y", "mcp-server"]`. RepoGrant parses these for R6.

---

## 4. GitHub Copilot (coding/cloud agent)

Sources: `docs.github.com/en/copilot/reference/custom-instructions-support`,
`docs.github.com/en/copilot/how-tos/.../customize-the-agent-firewall`.

**(A) Files.** "Repository-wide instructions (using the
`.github/copilot-instructions.md` file)."; "Path-specific instructions (using
`.github/instructions/**/*.instructions.md` files)."; "Agent instructions
(using `AGENTS.md`, `CLAUDE.md` or `GEMINI.md` files)." No precedence stated.

**(B) Model — egress firewall, not an allowlist grammar.** "By default,
Copilot's access to the internet is limited by a firewall." "By default, a
recommended allowlist is also enabled to allow the agent to download
dependencies." "Disabling the firewall will allow Copilot to connect to any
host," "increasing risks of exfiltration…". "The firewall only operates within
the environment where Copilot runs, either a GitHub Actions runner or a cloud
sandbox."

**(C)/(E) Hooks / MCP.** No repo-declared shell-hook mechanism is documented;
the instruction files are natural-language guidance, not an execution grammar.
→ Copilot's command/sandbox/filesystem authority is **not-judgeable** from the
repo; RepoGrant treats Copilot as **instruction-divergence (R3) only**.

---

## 5. Gemini CLI (Google)

Sources: `.../gemini-cli/.../docs/cli/settings.md`,
`.../docs/cli/trusted-folders.md`, `.../docs/reference/configuration.md`,
`.../docs/cli/sandbox.md`, `.../docs/tools/mcp-server.md`.

**(A) Files + precedence.** "User settings: `~/.gemini/settings.json`" and
"Workspace settings: `your-project/.gemini/settings.json`". Full chain
(configuration.md): "Default values < System defaults file < User settings <
Project settings < System settings < Environment variables < Command-line
arguments." A repo's `.gemini/settings.json` can therefore be overridden by a
machine-level system file the repo does not control (a ceiling, not a repo
grant).

**(B) Permission model.** `general.defaultApprovalMode` default `"default"` —
"'default' prompts for approval, 'auto_edit' auto-approves edit tools, and
'plan' is read-only mode." "YOLO mode … can only be enabled via command line."
`tools.sandboxNetworkAccess` "Whether the sandbox is allowed to access the
network." (default `false`). The default of `tools.sandbox` itself is **not**
documented verbatim → Gemini's silent network-egress cell is `not-judgeable`.

**(C) Folder Trust (the R4 defaults trap).** "The Trusted Folders feature is
disabled by default." In untrusted ("safe mode"): "Workspace settings are
ignored: The CLI will not load the `.gemini/settings.json` file from the
project."; "Environment variables are ignored: … not load any `.env` files".
Because Folder Trust is **off by default**, by default a cloned repo's
`.gemini/settings.json` and `.env` **are** honored — the protective safe mode
only applies once the feature is turned on.

**(D)/(E) MCP launch + `trust` bypass.** "Add an `mcpServers` object to your
`settings.json` file" with `command`, `args`, `env`. **`trust` field:** "When
`true`, bypasses all tool call confirmations for this server (default:
`false`)." A repo-committed `trust: true` server auto-runs its tool calls with
no confirmation (R1). `trust` is honored only when set `true`.

---

## 6. Cross-tool summary

| Dimension | Claude Code | Codex | Cursor | Copilot | Gemini CLI |
|---|---|---|---|---|---|
| Repo instruction file | `CLAUDE.md` / `.claude/` | `.codex/`, `AGENTS.md` | `.cursor/rules/*.mdc`, `AGENTS.md` | `.github/copilot-instructions.md`, `AGENTS.md` | `GEMINI.md`, `.gemini/` |
| Repo settings | `.claude/settings.json` | `.codex/config.toml` | `.cursor/permissions.json`, `sandbox.json` | repo Copilot settings (UI) | `.gemini/settings.json` |
| Allowlist grammar | `Tool(specifier)`, `*`/`:*` | approvals × sandbox | `terminalAllowlist` prefix / glob | n/a (egress firewall) | approval modes |
| Repo hooks run shell | **Yes**, trust-gated (no prompt in `-p`/CI) | project hooks, **per-hash trust-gated** | not documented (rules/allowlist only) | not documented | via `trust:true` server (no confirm) |
| Default when silent | `default` mode, launch-dir access | network off; VC ⇒ workspace-write | depends on user Run Mode (not repo) | firewall on + recommended allowlist | Folder Trust **off** ⇒ repo config honored |
| MCP launch | `.mcp.json`, approval-gated, `npx -y` unpinned | `[mcp_servers]`, no pin stmt | `.cursor/mcp.json` stdio entries | not covered | `mcpServers` + `trust` bypass |

The same five tools read **different repo-side files**, express permission
under **different grammars**, gate repo-declared execution under **different
trust models**, and carry **different silent-config defaults**. No tool
computes the others' semantics.

---

## 7. `not-judgeable` by design (never guessed)

- **Cursor** command / filesystem / network / secret-reach defaults — governed
  by the user-global Run Mode, not the repo.
- **Cursor** MCP launch-time auto-approval — docs state per-tool-call approval
  only, not launch-time behavior.
- **Copilot** command / filesystem / secret-reach — platform/runner-side, not
  a repo grammar.
- **Gemini** silent network-egress — `tools.sandbox` default is not documented
  verbatim.
- Any **malformed or structurally-unexpected** config surface (bad JSON/TOML,
  wrong top-level type, literal `null`) → surfaced as a parse-problem, never
  silently dropped.
