"""Documented silent-config defaults per (tool, dimension).

This table is the single source of truth for both Part B (the defaults
matrix) and check R4 (silence-is-not-safety). Every judgeable cell carries
a VERBATIM primary-source quote and the URL it came from (traceable to the
DECISIONS.md register). Cells that the primary docs do not state are marked
judgeable=False with a reason -> they emit `not-judgeable`, never a guess.

`dual` holds documented default conflicts/branches (e.g. Codex
version-controlled vs not) shown as parallel cells, never resolved by us.
"""
from __future__ import annotations

from .model import Dimension, Tool

# URLs (official hosts; see DECISIONS.md source-host note).
U_CC_PERM = "https://code.claude.com/docs/en/permissions"
U_CC_SET = "https://code.claude.com/docs/en/settings"
U_CC_HOOKS = "https://code.claude.com/docs/en/hooks"
U_CODEX_APPR = "https://learn.chatgpt.com/docs/agent-approvals-security"
U_CODEX_SAND = "https://learn.chatgpt.com/docs/sandboxing"
U_CODEX_HOOKS = "https://learn.chatgpt.com/docs/hooks.md"
U_CURSOR_RUN = "https://cursor.com/docs/agent/security/run-modes"
U_CURSOR_MCP = "https://cursor.com/docs/context/mcp"
U_COPILOT_FW = "https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall"
U_GEM_SET = "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md"
U_GEM_TRUST = "https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/cli/trusted-folders.md"


def cell(value, consent, quote, url, judgeable=True, reason="", note="", dual=None):
    return {
        "value": value,
        "consent_required": consent,
        "judgeable": judgeable,
        "quote": quote,
        "url": url,
        "reason": reason,
        "note": note,
        "dual": dual or [],
    }


D = Dimension

DEFAULTS = {
    Tool.CLAUDE_CODE: {
        D.COMMAND_EXECUTION: cell(
            "consent-required", True,
            "Prompts before most edits, shell commands, and network requests.",
            U_CC_PERM,
            note="`default` permission mode when the repo sets nothing effective.",
        ),
        D.FILESYSTEM_READ: cell(
            "workspace", None,
            "By default, Claude has access to files in the directory where you launched it",
            U_CC_PERM,
            note="Reads outside the working directory are not stated to be blocked by default.",
        ),
        D.FILESYSTEM_WRITE: cell(
            "workspace / consent-required", True,
            "Prompts before most edits, shell commands, and network requests.",
            U_CC_PERM,
        ),
        D.NETWORK_EGRESS: cell(
            "reachable-on-consent", True,
            "If Bash is allowed, Claude can still use `curl`, `wget`, or other tools to reach any URL.",
            U_CC_PERM,
            note="No network sandbox by default; egress follows shell/WebFetch consent.",
        ),
        D.SECRET_REACH: cell(
            "reachable", None,
            "By default, Claude has access to files in the directory where you launched it",
            U_CC_PERM,
            note="In-workspace secret files (.env, keys) fall within the default read scope.",
        ),
        D.AUTO_APPROVAL: cell(
            "none", None,
            "Claude Code checks workspace trust before it runs any hook from a settings file.",
            U_CC_HOOKS,
            note="No repo config => no hooks/trusted servers. NB: committed hooks DO run with no "
                 "trust prompt under `claude -p`/SDK (see R1).",
        ),
    },
    Tool.CODEX: {
        D.COMMAND_EXECUTION: cell(
            "consent-required", True,
            "Version-controlled folders: `Auto` (workspace write + on-request approvals)",
            U_CODEX_APPR,
            dual=[
                {"label": "version-controlled",
                 "value": "on-request (Auto / workspace-write)",
                 "quote": "Version-controlled folders: `Auto` (workspace write + on-request approvals)",
                 "url": U_CODEX_APPR},
                {"label": "non-version-controlled",
                 "value": "read-only (no command run without approval)",
                 "quote": "Non-version-controlled folders: `read-only`",
                 "url": U_CODEX_APPR},
                {"label": "conflict (sandboxing page)",
                 "value": "workspace-write called the default low-friction mode",
                 "quote": "This is the default low-friction mode for local work.",
                 "url": U_CODEX_SAND},
            ],
        ),
        D.FILESYSTEM_READ: cell(
            "workspace", None,
            "The agent can inspect files, but it can't edit files or run commands without approval.",
            U_CODEX_SAND,
        ),
        D.FILESYSTEM_WRITE: cell(
            "depends-on-vcs", True,
            "The agent can read files, edit within the workspace, and run routine local commands inside that boundary.",
            U_CODEX_SAND,
            dual=[
                {"label": "version-controlled",
                 "value": "workspace (workspace-write)",
                 "quote": "edit within the workspace, and run routine local commands inside that boundary",
                 "url": U_CODEX_SAND},
                {"label": "non-version-controlled",
                 "value": "none (read-only)",
                 "quote": "it can't edit files or run commands without approval",
                 "url": U_CODEX_SAND},
            ],
            note="`<writable_root>/.git` is protected as read-only.",
        ),
        D.NETWORK_EGRESS: cell(
            "off", None,
            "the default `workspace-write` sandbox mode keeps network access turned off unless you enable it in your configuration:",
            U_CODEX_APPR,
        ),
        D.SECRET_REACH: cell(
            "reachable", None,
            "The agent can inspect files",
            U_CODEX_SAND,
            note="Read scope covers the workspace; in-workspace secrets are inspectable.",
        ),
        D.AUTO_APPROVAL: cell(
            "none", None,
            "Non-managed hooks must be reviewed and trusted before they run.",
            U_CODEX_HOOKS,
            note="Hooks are enabled by default but repo hooks are per-hash trust-gated; no silent auto-run.",
        ),
    },
    Tool.CURSOR: {
        D.COMMAND_EXECUTION: cell(
            None, None, "", U_CURSOR_RUN, judgeable=False,
            reason="Cursor's effective default depends on the user's global Run Mode selection "
                   "(Cursor Settings), which is not a repo-side artifact.",
        ),
        D.FILESYSTEM_READ: cell(
            None, None, "", U_CURSOR_RUN, judgeable=False,
            reason="Not determined by the repo; governed by user-global Run Mode / sandbox settings.",
        ),
        D.FILESYSTEM_WRITE: cell(
            None, None, "", U_CURSOR_RUN, judgeable=False,
            reason="Not determined by the repo; governed by user-global Run Mode / sandbox settings.",
        ),
        D.NETWORK_EGRESS: cell(
            None, None, "", U_CURSOR_RUN, judgeable=False,
            reason="Cursor documents no repo-side network-egress grammar.",
        ),
        D.SECRET_REACH: cell(
            None, None, "", U_CURSOR_RUN, judgeable=False,
            reason="Read scope is user-global (Run Mode), not repo-determined.",
        ),
        D.AUTO_APPROVAL: cell(
            "ask (MCP)", True,
            "Cursor asks for approval before using MCP tools by default.",
            U_CURSOR_MCP,
            note="MCP tool calls ask by default; shell auto-run still depends on user-global Run Mode "
                 "(not repo). Launch-time consent for a project-declared server is not documented.",
        ),
    },
    Tool.COPILOT: {
        D.COMMAND_EXECUTION: cell(
            None, None, "", U_COPILOT_FW, judgeable=False,
            reason="Copilot's command authority is platform/runner-side, not a repo grammar (D-02); "
                   "Copilot is treated as R3 instruction-divergence only.",
        ),
        D.FILESYSTEM_READ: cell(
            None, None, "", U_COPILOT_FW, judgeable=False,
            reason="Filesystem scope of the Actions/cloud runner is not described as a repo grant.",
        ),
        D.FILESYSTEM_WRITE: cell(
            None, None, "", U_COPILOT_FW, judgeable=False,
            reason="Filesystem scope of the Actions/cloud runner is not described as a repo grant.",
        ),
        D.NETWORK_EGRESS: cell(
            "firewall+recommended-allowlist (platform-side)", None,
            "By default, Copilot's access to the internet is limited by a firewall.",
            U_COPILOT_FW,
            note="Documented platform default, not a repo-granted authority; the repo cannot widen it here.",
        ),
        D.SECRET_REACH: cell(
            None, None, "", U_COPILOT_FW, judgeable=False,
            reason="Not a repo-side grant; governed by the runner/secret-store, not repo config.",
        ),
        D.AUTO_APPROVAL: cell(
            "none", None,
            "", U_COPILOT_FW,
            note="No repo-declared shell-hook mechanism is documented for Copilot.",
        ),
    },
    Tool.GEMINI_CLI: {
        D.COMMAND_EXECUTION: cell(
            "consent-required", True,
            "'default' prompts for approval, 'auto_edit' auto-approves edit tools, and 'plan' is read-only mode.",
            U_GEM_SET,
            note="`general.defaultApprovalMode` default is `default`.",
        ),
        D.FILESYSTEM_READ: cell(
            "workspace", None,
            "Workspace settings are ignored: The CLI will not load the `.gemini/settings.json` file from the project.",
            U_GEM_TRUST,
            note="Folder Trust is OFF by default, so a repo's `.gemini/` config and `.env` ARE honored by "
                 "default (the protective safe mode only applies once the feature is enabled).",
        ),
        D.FILESYSTEM_WRITE: cell(
            "workspace / consent-required", True,
            "'default' prompts for approval, 'auto_edit' auto-approves edit tools, and 'plan' is read-only mode.",
            U_GEM_SET,
        ),
        D.NETWORK_EGRESS: cell(
            None, None, "", U_GEM_SET, judgeable=False,
            reason="`tools.sandbox` default is not documented verbatim (only asserted `undefined` in a "
                   "non-verbatim summary); without a confirmed sandbox default the egress default is "
                   "undetermined. `tools.sandboxNetworkAccess` (default false) only applies when the "
                   "sandbox is on.",
        ),
        D.SECRET_REACH: cell(
            "reachable", None,
            "Environment variables are ignored: … not load any `.env` files",
            U_GEM_TRUST,
            note="That protection applies only in safe mode; Folder Trust is off by default, so `.env` is "
                 "loaded/reachable by default.",
        ),
        D.AUTO_APPROVAL: cell(
            "none", None,
            "When `true`, bypasses all tool call confirmations for this server (default: `false`)",
            U_GEM_TRUST,
            note="Default `mcpServers.*.trust` is false; no config => no trusted servers. A committed "
                 "`trust:true` server auto-runs with no confirmation (see R1).",
        ),
    },
}


def default_cell(tool: Tool, dim: Dimension) -> dict:
    return DEFAULTS[tool][dim]
