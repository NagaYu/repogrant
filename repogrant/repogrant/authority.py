"""Effective-authority model: per tool, per dimension, resolved from the repo
config PLUS the documented defaults where config is silent.

This is the headline semantic layer (not pattern-flagging). Every cell is
either computed from config, filled from the documented default (defaults.py),
or emitted as not-judgeable with a reason. Output is deterministic.
"""
from __future__ import annotations

from .defaults import default_cell
from .model import (NOT_JUDGEABLE, AuthorityCell, Dimension, Evidence, Source,
                    Tool, ToolConfig)
from .semantics import bash_breadth, parse_tool_rule

D = Dimension


def _ev(item, excerpt_key="value") -> Evidence:
    exc = item.get(excerpt_key, "")
    return Evidence(file=item.get("file", ""), locator=item.get("locator", ""),
                    excerpt=str(exc) if exc != "" else "")


def from_default(tool: Tool, dim: Dimension) -> AuthorityCell:
    dc = default_cell(tool, dim)
    if not dc["judgeable"]:
        return AuthorityCell(dim, NOT_JUDGEABLE, None, Source.NOT_JUDGEABLE,
                             rationale="Repo is silent and the documented default is not judgeable from the repo.",
                             reason=dc["reason"])
    ev = [Evidence("<docs>", "<default>", dc["quote"], dc["url"])]
    note = (" " + dc["note"]) if dc["note"] else ""
    return AuthorityCell(dim, dc["value"], dc["consent_required"], Source.DEFAULT,
                         rationale=f"Repo silent; documented default applies.{note}", evidence=ev)


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------

def _claude(cfg: ToolConfig, ctx) -> dict:
    d = cfg.data
    perms = d["permissions"]
    allow, deny = perms["allow"], perms["deny"]
    mode = d["default_mode"]["value"] if d["default_mode"] else "default"
    cells = {}

    bash_allow = [(r, bash_breadth(parse_tool_rule(r["value"])[1]))
                  for r in allow if parse_tool_rule(r["value"])[0] == "Bash"]
    bash_deny = [(r, bash_breadth(parse_tool_rule(r["value"])[1]))
                 for r in deny if parse_tool_rule(r["value"])[0] == "Bash"]
    has_unrestricted_allow = any(b["breadth"] == "unrestricted" for _, b in bash_allow)
    has_unrestricted_deny = any(b["breadth"] == "unrestricted" for _, b in bash_deny)

    # command execution
    if has_unrestricted_deny:
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "blocked", None, Source.CONFIG,
            "A deny rule blocks Bash entirely (deny is evaluated before allow).",
            [_ev(r) for r, b in bash_deny if b["breadth"] == "unrestricted"])
    elif has_unrestricted_allow:
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "unrestricted", False, Source.CONFIG,
            "An allow rule grants unrestricted Bash (matches any command); shell runs with no per-call consent.",
            [_ev(r) for r, b in bash_allow if b["breadth"] == "unrestricted"])
    elif bash_allow:
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "conditional", True, Source.CONFIG,
            "Allowlisted Bash commands run without consent; other shell still prompts. "
            "Note: Bash arg-constraints are fragile and not a security boundary (see R2).",
            [_ev(r) for r, _ in bash_allow])
    elif mode == "acceptEdits":
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "conditional", True, Source.CONFIG,
            "`acceptEdits` auto-approves common filesystem commands (mkdir/touch/mv/cp); other shell prompts.",
            [_ev(d["default_mode"])])
    elif mode == "plan":
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "consent-required", True, Source.CONFIG,
            "`plan` mode is read-only: reads and read-only shell only, no edits.",
            [_ev(d["default_mode"])])
    else:
        cells[D.COMMAND_EXECUTION] = from_default(Tool.CLAUDE_CODE, D.COMMAND_EXECUTION)

    cmd_unrestricted = cells[D.COMMAND_EXECUTION].level == "unrestricted"

    # filesystem read
    add_dirs = perms["additionalDirectories"]
    if add_dirs:
        cells[D.FILESYSTEM_READ] = AuthorityCell(
            D.FILESYSTEM_READ, "workspace+additional", None, Source.CONFIG_DEFAULT,
            "`additionalDirectories` extends read access beyond the launch directory.",
            [_ev(x) for x in add_dirs])
    else:
        cells[D.FILESYSTEM_READ] = from_default(Tool.CLAUDE_CODE, D.FILESYSTEM_READ)

    # filesystem write
    if cmd_unrestricted:
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(
            D.FILESYSTEM_WRITE, "unrestricted", False, Source.CONFIG,
            "Unrestricted Bash can write anywhere the user can; write is effectively unrestricted.",
            cells[D.COMMAND_EXECUTION].evidence)
    elif mode == "acceptEdits":
        lvl = "workspace+additional" if add_dirs else "workspace"
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(
            D.FILESYSTEM_WRITE, lvl, False, Source.CONFIG,
            "`acceptEdits` auto-accepts file edits in the working directory (and additionalDirectories).",
            [_ev(d["default_mode"])])
    elif mode == "plan":
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(
            D.FILESYSTEM_WRITE, "none", None, Source.CONFIG,
            "`plan` mode does not edit source files.", [_ev(d["default_mode"])])
    else:
        cells[D.FILESYSTEM_WRITE] = from_default(Tool.CLAUDE_CODE, D.FILESYSTEM_WRITE)

    # network egress
    if cmd_unrestricted:
        cells[D.NETWORK_EGRESS] = AuthorityCell(
            D.NETWORK_EGRESS, "on", False, Source.CONFIG,
            "No network sandbox; with unrestricted Bash the agent can reach any URL (curl/wget) without consent.",
            cells[D.COMMAND_EXECUTION].evidence)
    else:
        cells[D.NETWORK_EGRESS] = from_default(Tool.CLAUDE_CODE, D.NETWORK_EGRESS)

    # secret reach
    deny_read = [r for r in deny if parse_tool_rule(r["value"])[0] == "Read"]
    secret_denied = [r for r in deny_read
                     if any(tok in r["value"].lower() for tok in (".env", "secret", ".pem", "credential", ".key"))]
    if secret_denied:
        cells[D.SECRET_REACH] = AuthorityCell(
            D.SECRET_REACH, "reduced", None, Source.CONFIG,
            "A deny Read rule blocks some secret-bearing paths (deny cannot be overridden by allow).",
            [_ev(r) for r in secret_denied])
    else:
        cells[D.SECRET_REACH] = from_default(Tool.CLAUDE_CODE, D.SECRET_REACH)

    # auto approval
    hooks = d["hooks"]
    if hooks:
        cells[D.AUTO_APPROVAL] = AuthorityCell(
            D.AUTO_APPROVAL, "present", False, Source.CONFIG,
            "Repo commits settings-file hooks. Under `claude -p`/SDK these run with NO trust prompt "
            "(\"hooks committed in a repository's .claude/settings.json run in a folder you've never trusted\"); "
            "interactively they need one-time workspace trust.",
            [Evidence(h["file"], h["locator"], f'{h["event"]}: {h["command"]}') for h in hooks])
    else:
        cells[D.AUTO_APPROVAL] = from_default(Tool.CLAUDE_CODE, D.AUTO_APPROVAL)

    return cells


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------

def _codex(cfg: ToolConfig, ctx) -> dict:
    d = cfg.data
    cells = {}
    approval = d["approval_policy"]["value"] if d["approval_policy"] else None
    sandbox = d["sandbox_mode"]["value"] if d["sandbox_mode"] else None
    net = d["network_access"]

    # command execution
    if sandbox or approval:
        ev = [e for e in (d["approval_policy"], d["sandbox_mode"]) if e]
        if sandbox == "danger-full-access" and approval == "never":
            lvl, consent, why = "unrestricted", False, \
                "`danger-full-access` + `approval_policy=never`: commands run with no sandbox and no approval."
        elif approval == "never":
            lvl, consent, why = "unrestricted", False, \
                "`approval_policy=never`: the agent never stops to ask before executing commands."
        elif sandbox == "read-only":
            lvl, consent, why = "consent-required", True, \
                "`read-only` sandbox: the agent can't run commands without approval."
        elif sandbox == "workspace-write":
            lvl, consent, why = "conditional", True, \
                "`workspace-write`: routine local commands run inside the boundary; crossing it needs approval."
        else:
            lvl, consent, why = "consent-required", True, \
                f"approval_policy={approval!r}, sandbox_mode={sandbox!r}: resolved to on-request approval."
        cells[D.COMMAND_EXECUTION] = AuthorityCell(D.COMMAND_EXECUTION, lvl, consent, Source.CONFIG, why, [_ev(x) for x in ev])
    else:
        cells[D.COMMAND_EXECUTION] = from_default(Tool.CODEX, D.COMMAND_EXECUTION)

    # filesystem read
    if sandbox:
        cells[D.FILESYSTEM_READ] = AuthorityCell(
            D.FILESYSTEM_READ, "unrestricted" if sandbox == "danger-full-access" else "workspace",
            None, Source.CONFIG, f"`sandbox_mode={sandbox}` read scope.", [_ev(d["sandbox_mode"])])
    else:
        cells[D.FILESYSTEM_READ] = from_default(Tool.CODEX, D.FILESYSTEM_READ)

    # filesystem write
    if sandbox == "read-only":
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(D.FILESYSTEM_WRITE, "none", None, Source.CONFIG,
            "`read-only`: cannot edit files without approval.", [_ev(d["sandbox_mode"])])
    elif sandbox == "workspace-write":
        lvl = "workspace+additional" if d["writable_roots"] else "workspace"
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(D.FILESYSTEM_WRITE, lvl, False, Source.CONFIG,
            "`workspace-write`: edits within the workspace (and writable_roots) run inside the boundary. "
            "`<writable_root>/.git` is protected read-only.", [_ev(d["sandbox_mode"])])
    elif sandbox == "danger-full-access":
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(D.FILESYSTEM_WRITE, "unrestricted", False, Source.CONFIG,
            "`danger-full-access`: filesystem boundary removed.", [_ev(d["sandbox_mode"])])
    else:
        # silent: version-controlled branch of the documented default
        base = from_default(Tool.CODEX, D.FILESYSTEM_WRITE)
        if ctx.get("version_controlled"):
            base.level = "workspace"
            base.rationale = ("Repo silent; version-controlled default is `Auto`/`workspace-write` "
                              "(edits within the workspace).")
        else:
            base.level = "none"
            base.rationale = "Repo silent; non-version-controlled default is `read-only` (no edits without approval)."
        cells[D.FILESYSTEM_WRITE] = base

    # network egress
    if net is not None:
        cells[D.NETWORK_EGRESS] = AuthorityCell(
            D.NETWORK_EGRESS, "on" if net["value"] else "off", None, Source.CONFIG,
            "`sandbox_workspace_write.network_access` " + ("enables" if net["value"] else "disables") + " outbound network.",
            [_ev(net)])
    elif sandbox == "danger-full-access":
        cells[D.NETWORK_EGRESS] = AuthorityCell(D.NETWORK_EGRESS, "on", None, Source.CONFIG,
            "`danger-full-access` removes the network boundary.", [_ev(d["sandbox_mode"])])
    else:
        cells[D.NETWORK_EGRESS] = from_default(Tool.CODEX, D.NETWORK_EGRESS)

    cells[D.SECRET_REACH] = from_default(Tool.CODEX, D.SECRET_REACH)

    # auto approval (hooks are per-hash trust-gated -> consent gated, not silent auto)
    hooks = d["hooks"]
    feat = d["hooks_feature"]
    hooks_off = feat is not None and feat["value"] is False
    if hooks and not hooks_off:
        cells[D.AUTO_APPROVAL] = AuthorityCell(
            D.AUTO_APPROVAL, "present-trust-gated", True, Source.CONFIG,
            "Repo declares Codex hooks. Hooks are enabled by default, but non-managed repo hooks require "
            "per-hash trust before they run (no silent auto-run); the only no-prompt path is the explicit "
            "`--dangerously-bypass-hook-trust` flag.",
            [Evidence(h["file"], h["locator"], f'{h["event"]}: {h["command"]}') for h in hooks])
    elif hooks and hooks_off:
        cells[D.AUTO_APPROVAL] = AuthorityCell(
            D.AUTO_APPROVAL, "none", None, Source.CONFIG,
            "Repo declares hooks but `[features] hooks = false` disables the hooks engine.",
            [_ev(feat)])
    else:
        cells[D.AUTO_APPROVAL] = from_default(Tool.CODEX, D.AUTO_APPROVAL)

    return cells


# ---------------------------------------------------------------------------
# Cursor  (thin, per D-02)
# ---------------------------------------------------------------------------

def _cursor(cfg: ToolConfig, ctx) -> dict:
    d = cfg.data
    cells = {}
    term = d["terminal_allowlist"]
    auto_run = d["auto_run"]

    if term or auto_run:
        ev = [_ev(x) for x in term] + ([_ev(auto_run)] if auto_run else [])
        cells[D.COMMAND_EXECUTION] = AuthorityCell(
            D.COMMAND_EXECUTION, "conditional", True, Source.CONFIG,
            "A repo `.cursor/permissions.json` allowlist/autoRun auto-runs matching commands WHEN a Run Mode "
            "is enabled (case-sensitive prefix match); the effective default otherwise is user-global Run Mode. "
            "Cursor states this allowlist is \"not a security boundary\".", ev)
    else:
        cells[D.COMMAND_EXECUTION] = from_default(Tool.CURSOR, D.COMMAND_EXECUTION)

    for dim in (D.FILESYSTEM_READ, D.FILESYSTEM_WRITE, D.NETWORK_EGRESS, D.SECRET_REACH):
        if dim in (D.FILESYSTEM_READ, D.FILESYSTEM_WRITE) and d["sandbox"]:
            cells[dim] = AuthorityCell(dim, "sandbox-configured", None, Source.CONFIG,
                "A repo `.cursor/sandbox.json` is present; exact scope depends on Cursor's sandbox interpretation.",
                [_ev(d["sandbox"])])
        else:
            cells[dim] = from_default(Tool.CURSOR, dim)

    if auto_run or term or d["mcp_allowlist"]:
        ev = ([_ev(auto_run)] if auto_run else []) + [_ev(x) for x in d["mcp_allowlist"]]
        cells[D.AUTO_APPROVAL] = AuthorityCell(
            D.AUTO_APPROVAL, "present-runmode-gated", True, Source.CONFIG,
            "Repo autoRun/allowlist entries auto-run only when a Run Mode is enabled; MCP tool calls ask by "
            "default. Launch-time consent for a project-declared MCP server is not documented (not-judgeable).",
            ev)
    else:
        cells[D.AUTO_APPROVAL] = from_default(Tool.CURSOR, D.AUTO_APPROVAL)

    return cells


# ---------------------------------------------------------------------------
# Copilot  (instruction-only, per D-02)
# ---------------------------------------------------------------------------

def _copilot(cfg: ToolConfig, ctx) -> dict:
    return {dim: from_default(Tool.COPILOT, dim) for dim in D}


# ---------------------------------------------------------------------------
# Gemini CLI
# ---------------------------------------------------------------------------

def _gemini(cfg: ToolConfig, ctx) -> dict:
    d = cfg.data
    cells = {}
    mode = d["approval_mode"]["value"] if d["approval_mode"] else None

    if mode:
        if mode == "plan":
            cmd = ("consent-required", True, "`plan` approval mode is read-only.")
        elif mode == "auto_edit":
            cmd = ("conditional", True, "`auto_edit` auto-approves edit tools; other actions still prompt.")
        elif mode == "yolo":
            cmd = ("unrestricted", False, "`yolo` auto-approves all actions (note: YOLO is only honored from the CLI flag, not settings).")
        else:
            cmd = ("consent-required", True, "`default` approval mode prompts for approval.")
        cells[D.COMMAND_EXECUTION] = AuthorityCell(D.COMMAND_EXECUTION, cmd[0], cmd[1], Source.CONFIG, cmd[2], [_ev(d["approval_mode"])])
    else:
        cells[D.COMMAND_EXECUTION] = from_default(Tool.GEMINI_CLI, D.COMMAND_EXECUTION)

    cells[D.FILESYSTEM_READ] = from_default(Tool.GEMINI_CLI, D.FILESYSTEM_READ)

    if mode == "auto_edit":
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(D.FILESYSTEM_WRITE, "workspace", False, Source.CONFIG,
            "`auto_edit` auto-approves edit tools.", [_ev(d["approval_mode"])])
    elif mode == "plan":
        cells[D.FILESYSTEM_WRITE] = AuthorityCell(D.FILESYSTEM_WRITE, "none", None, Source.CONFIG,
            "`plan` mode is read-only.", [_ev(d["approval_mode"])])
    else:
        cells[D.FILESYSTEM_WRITE] = from_default(Tool.GEMINI_CLI, D.FILESYSTEM_WRITE)

    # network egress depends on the sandbox, whose default is not-judgeable (6.3)
    snet = d["sandbox_network"]
    sandbox = d["sandbox"]
    if sandbox and snet is not None:
        cells[D.NETWORK_EGRESS] = AuthorityCell(D.NETWORK_EGRESS, "on" if snet["value"] else "off", None, Source.CONFIG,
            "Sandbox configured; `tools.sandboxNetworkAccess` " + ("permits" if snet["value"] else "blocks") + " network.",
            [_ev(sandbox), _ev(snet)])
    elif sandbox and snet is None:
        cells[D.NETWORK_EGRESS] = AuthorityCell(D.NETWORK_EGRESS, "off", None, Source.CONFIG_DEFAULT,
            "Sandbox configured; `tools.sandboxNetworkAccess` defaults false.", [_ev(sandbox)])
    else:
        cells[D.NETWORK_EGRESS] = from_default(Tool.GEMINI_CLI, D.NETWORK_EGRESS)

    cells[D.SECRET_REACH] = from_default(Tool.GEMINI_CLI, D.SECRET_REACH)

    trusted = [s for s in d["mcp_servers"] if s.get("trust")]
    if trusted:
        cells[D.AUTO_APPROVAL] = AuthorityCell(
            D.AUTO_APPROVAL, "present", False, Source.CONFIG,
            "A repo `mcpServers` entry sets `trust: true`, which \"bypasses all tool call confirmations for "
            "this server\" — the server's tool calls auto-run with no confirmation.",
            [Evidence(s["file"], s["locator"], f'{s["name"]}: trust=true') for s in trusted])
    else:
        cells[D.AUTO_APPROVAL] = from_default(Tool.GEMINI_CLI, D.AUTO_APPROVAL)

    return cells


_DISPATCH = {
    Tool.CLAUDE_CODE: _claude,
    Tool.CODEX: _codex,
    Tool.CURSOR: _cursor,
    Tool.COPILOT: _copilot,
    Tool.GEMINI_CLI: _gemini,
}


def compute(configs: dict, ctx: dict) -> dict:
    """Return {Tool: {Dimension: AuthorityCell}}."""
    out = {}
    for tool, cfg in configs.items():
        out[tool] = _DISPATCH[tool](cfg, ctx)
    return out
