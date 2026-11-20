"""Checks R1-R6, computed from the authority model + parsed config.

R3/R4/R5 are first-class semantic checks (compare/compose authority models),
not pattern lists. R1/R2/R6 are measured and reported but are not pitched as
the novel wedge (see ratification). Unparseable/unknown config surfaces are
surfaced as not-judgeable, never silently dropped.
"""
from __future__ import annotations

from ..model import (Dimension, Evidence, Finding, Severity, Source, Tool,
                     TOOL_LABEL, TOOL_ORDER)
from ..parsers import instructions
from ..semantics import (POWERFUL_BASES, bash_breadth, cursor_prefix_breadth,
                         detect_unpinned, parse_tool_rule)

D = Dimension


def _hook_evidence(items):
    return [Evidence(h["file"], h["locator"], f'{h["event"]}: {h["command"]}') for h in items]


# --- R1: hook / auto-run execution surface ---------------------------------

def r1(configs, authority, ctx):
    out = []
    # Claude hooks (silent under -p => high)
    for h in configs[Tool.CLAUDE_CODE].data["hooks"]:
        out.append(Finding(
            "R1", "hook-execution-surface", Tool.CLAUDE_CODE, dimension=D.AUTO_APPROVAL,
            severity=Severity.HIGH,
            title=f"Claude Code repo hook on `{h['event']}` executes a shell command",
            detail="Committed `.claude/settings.json` hooks run with NO trust prompt under `claude -p`/SDK "
                   "(CI), and after one-time workspace trust interactively.",
            evidence=_hook_evidence([h])))
    # Codex hooks (per-hash trust-gated => medium)
    cfeat = configs[Tool.CODEX].data["hooks_feature"]
    hooks_off = cfeat is not None and cfeat["value"] is False
    if not hooks_off:
        for h in configs[Tool.CODEX].data["hooks"]:
            out.append(Finding(
                "R1", "hook-execution-surface", Tool.CODEX, dimension=D.AUTO_APPROVAL,
                severity=Severity.MEDIUM,
                title=f"Codex repo hook on `{h['event']}` declares a command handler",
                detail="Hooks are enabled by default, but non-managed repo hooks require per-hash trust before "
                       "they run; the no-prompt path is the explicit `--dangerously-bypass-hook-trust` flag.",
                evidence=_hook_evidence([h])))
    # Gemini trusted servers (bypass all confirmations => high)
    for s in configs[Tool.GEMINI_CLI].data["mcp_servers"]:
        if s.get("trust"):
            out.append(Finding(
                "R1", "hook-execution-surface", Tool.GEMINI_CLI, dimension=D.AUTO_APPROVAL,
                severity=Severity.HIGH,
                title=f"Gemini MCP server `{s['name']}` sets `trust: true`",
                detail="`trust: true` bypasses all tool-call confirmations for this server; its tool calls "
                       "auto-run with no confirmation.",
                evidence=[Evidence(s["file"], s["locator"], f'{s["name"]}: trust=true, command={s.get("command","")}')]))
    # Cursor autoRun / terminalAllowlist (run-mode gated => medium)
    cur = configs[Tool.CURSOR].data
    if cur["auto_run"] or cur["terminal_allowlist"]:
        ev = []
        if cur["auto_run"]:
            ev.append(Evidence(cur["auto_run"]["file"], cur["auto_run"]["locator"], str(cur["auto_run"]["value"])))
        ev += [Evidence(x["file"], x["locator"], x["value"]) for x in cur["terminal_allowlist"]]
        out.append(Finding(
            "R1", "hook-execution-surface", Tool.CURSOR, dimension=D.AUTO_APPROVAL,
            severity=Severity.MEDIUM,
            title="Cursor repo allowlist/autoRun auto-runs terminal commands",
            detail="Allowlisted/autoRun commands run without prompting WHEN a Run Mode is enabled; Cursor states "
                   "this is \"not a security boundary\".",
            evidence=ev))
    return out


# --- R2: pre-approval overreach (semantic breadth) -------------------------

def r2(configs, authority, ctx):
    out = []
    for r in configs[Tool.CLAUDE_CODE].data["permissions"]["allow"]:
        tool, spec = parse_tool_rule(r["value"])
        if tool != "Bash":
            continue
        b = bash_breadth(spec)
        if b["breadth"] == "unrestricted":
            sev, title = Severity.HIGH, f"Claude allow rule `{r['value']}` grants unrestricted shell"
        elif b["breadth"] == "program-wide":
            sev = Severity.MEDIUM if b["base"] in POWERFUL_BASES else Severity.INFO
            title = f"Claude allow rule `{r['value']}` is broader than it looks (`{b['base']}`-wide)"
        else:
            continue
        out.append(Finding(
            "R2", "preapproval-overreach", Tool.CLAUDE_CODE, dimension=D.COMMAND_EXECUTION,
            severity=sev, title=title, detail=b["note"],
            evidence=[Evidence(r["file"], r["locator"], r["value"])]))
    # Cursor terminalAllowlist prefix breadth
    for r in configs[Tool.CURSOR].data["terminal_allowlist"]:
        b = cursor_prefix_breadth(r["value"])
        sev = Severity.MEDIUM if b["base"] in POWERFUL_BASES else Severity.INFO
        out.append(Finding(
            "R2", "preapproval-overreach", Tool.CURSOR, dimension=D.COMMAND_EXECUTION,
            severity=sev,
            title=f"Cursor terminalAllowlist `{r['value']}` prefix-matches a command family",
            detail=b["note"], evidence=[Evidence(r["file"], r["locator"], r["value"])]))
    return out


# --- R3: cross-tool divergence (semantic) ----------------------------------

_OPEN = {
    D.COMMAND_EXECUTION: {"unrestricted"},
    D.NETWORK_EGRESS: {"on"},
    D.AUTO_APPROVAL: {"present"},
}
_CLOSED = {
    D.COMMAND_EXECUTION: {"blocked", "consent-required", "conditional"},
    D.NETWORK_EGRESS: {"off"},
    D.AUTO_APPROVAL: {"none"},
}


def r3(configs, authority, ctx):
    out = []
    for dim in (D.COMMAND_EXECUTION, D.NETWORK_EGRESS, D.AUTO_APPROVAL):
        open_tools, closed_tools = [], []
        for t in TOOL_ORDER:
            cell = authority[t][dim]
            if cell.source == Source.NOT_JUDGEABLE:
                continue
            if cell.level in _OPEN[dim]:
                open_tools.append(t)
            elif cell.level in _CLOSED[dim]:
                closed_tools.append(t)
        # only material if at least one side is from config (not pure defaults on both ends)
        any_config = any(authority[t][dim].source in (Source.CONFIG, Source.CONFIG_DEFAULT)
                         for t in open_tools + closed_tools)
        if open_tools and closed_tools and any_config:
            ev = []
            for t in open_tools + closed_tools:
                ev += authority[t][dim].evidence[:1]
            out.append(Finding(
                "R3", "cross-tool-divergence", None, tools=open_tools + closed_tools, dimension=dim,
                severity=Severity.HIGH if dim != D.COMMAND_EXECUTION else Severity.HIGH,
                title=f"{dim.value}: open in {', '.join(TOOL_LABEL[t] for t in open_tools)} but "
                      f"restricted in {', '.join(TOOL_LABEL[t] for t in closed_tools)}",
                detail="The same repo grants materially different authority across tools on this dimension "
                       "(the cross-tool divergence the repo's reviewer cannot see from one tool alone).",
                evidence=ev))
    # instruction contradictions
    shared = ctx.get("root")
    for t in TOOL_ORDER:
        for rel in configs[t].instructions:
            sig = instructions.extract_signals(shared, rel)
            net_open = [x for x in TOOL_ORDER if authority[x][D.NETWORK_EGRESS].level == "on"
                        and authority[x][D.NETWORK_EGRESS].source != Source.NOT_JUDGEABLE]
            if sig["forbids_network"] and net_open:
                out.append(Finding(
                    "R3", "instruction-divergence", None, tools=net_open, dimension=D.NETWORK_EGRESS,
                    severity=Severity.MEDIUM,
                    title=f"Instruction file `{rel}` forbids network, but config enables egress in "
                          f"{', '.join(TOOL_LABEL[x] for x in net_open)}",
                    detail="A repo instruction file prohibits network access while a tool's config grants it: "
                           "prose and machine authority diverge.",
                    evidence=[Evidence(rel, "prose", sig["network_lines"][0] if sig["network_lines"] else "")]
                             + [authority[x][D.NETWORK_EGRESS].evidence[0] for x in net_open if authority[x][D.NETWORK_EGRESS].evidence]))
    # dedupe identical instruction findings deterministically
    seen = set()
    uniq = []
    for f in out:
        key = f.sort_key()
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


# --- R4: silence-is-not-safety ---------------------------------------------

def r4(configs, authority, ctx):
    out = []
    secret_present = bool(ctx.get("secret_paths"))

    # Gemini: Folder Trust OFF by default => repo .gemini config and .env honored.
    g = configs[Tool.GEMINI_CLI]
    ft = g.data["folder_trust"]
    gem_surface = any(s.present and s.parsed for s in g.surfaces if s.kind in ("settings",))
    if (ft is None or ft["value"] is False) and (gem_surface or secret_present):
        from ..defaults import default_cell
        dc = default_cell(Tool.GEMINI_CLI, D.FILESYSTEM_READ)
        out.append(Finding(
            "R4", "silent-default", Tool.GEMINI_CLI, dimension=D.FILESYSTEM_READ,
            severity=Severity.HIGH if gem_surface else Severity.MEDIUM,
            title="Gemini Folder Trust is off by default, so the repo's config and `.env` are honored silently",
            detail="With Folder Trust disabled (the default), a cloned repo's `.gemini/settings.json`, `.env` and "
                   "MCP servers are loaded without the protective safe mode ever engaging.",
            evidence=[Evidence("<docs>", "<default>", dc["quote"], dc["url"])]
                     + ([Evidence(ft["file"], ft["locator"], "folderTrust.enabled=false")] if ft else [])))

    # Codex: silent + version-controlled => workspace-write default (writes + local command exec).
    c = configs[Tool.CODEX]
    codex_silent = c.data["sandbox_mode"] is None and c.data["approval_policy"] is None
    if codex_silent and ctx.get("version_controlled"):
        from ..defaults import default_cell
        dc = default_cell(Tool.CODEX, D.FILESYSTEM_WRITE)
        out.append(Finding(
            "R4", "silent-default", Tool.CODEX, dimension=D.FILESYSTEM_WRITE,
            severity=Severity.MEDIUM,
            title="Codex is silent in a version-controlled repo: default is `workspace-write` (not read-only)",
            detail="The documented default for version-controlled folders is Auto / workspace-write, which lets "
                   "the agent edit the workspace and run routine local commands inside the boundary without the "
                   "repo configuring anything.",
            evidence=[Evidence("<docs>", "<default>", dc["dual"][0]["quote"], dc["dual"][0]["url"])]))

    # Claude: silent secret reach + a secret file present in the tree.
    cc = authority[Tool.CLAUDE_CODE][D.SECRET_REACH]
    if cc.source == Source.DEFAULT and secret_present:
        out.append(Finding(
            "R4", "silent-default", Tool.CLAUDE_CODE, dimension=D.SECRET_REACH,
            severity=Severity.MEDIUM,
            title="Claude Code's silent default read scope includes in-workspace secrets",
            detail=f"Secret-bearing files are present ({', '.join(ctx['secret_paths'][:3])}) and the repo sets no "
                   "deny Read rule, so the default launch-directory read scope reaches them.",
            evidence=cc.evidence))
    return out


# --- R5: secret-reach composition ------------------------------------------

def r5(configs, authority, ctx):
    out = []
    secret_present = bool(ctx.get("secret_paths"))
    for t in TOOL_ORDER:
        sr = authority[t][D.SECRET_REACH]
        eg = authority[t][D.NETWORK_EGRESS]
        wr = authority[t][D.FILESYSTEM_WRITE]
        if sr.source == Source.NOT_JUDGEABLE or sr.level not in ("reachable",):
            continue
        egress_on = eg.source != Source.NOT_JUDGEABLE and eg.level == "on"
        write_out = wr.source != Source.NOT_JUDGEABLE and wr.level in ("workspace+additional", "unrestricted")
        if not (egress_on or write_out):
            continue
        vector = "network egress" if egress_on else "write outside the workspace"
        sev = Severity.HIGH if (secret_present and egress_on) else Severity.MEDIUM
        detail = (f"The agent can read secret-bearing paths and also {vector}: a composed exfiltration path. "
                  + (f"Secret files present: {', '.join(ctx['secret_paths'][:3])}."
                     if secret_present else "No secret file is in the tree yet, but the composition would hold if one is added."))
        ev = sr.evidence[:1] + (eg.evidence[:1] if egress_on else wr.evidence[:1])
        out.append(Finding(
            "R5", "secret-reach-composition", t, dimension=D.SECRET_REACH, severity=sev,
            title=f"{TOOL_LABEL[t]}: readable secrets composed with {vector}",
            detail=detail, evidence=ev))
    return out


# --- R6: unpinned execution supply chain -----------------------------------

def _scan_specs(specs, tool, origin_label):
    out = []
    for s in specs:
        for hit in detect_unpinned(s.get("command", ""), s.get("args", [])):
            sev = Severity.HIGH if hit["kind"] == "pipe-to-shell" else Severity.MEDIUM
            out.append(Finding(
                "R6", "unpinned-supply-chain", tool,
                severity=sev,
                title=f"{TOOL_LABEL[tool]} {origin_label} runs unpinned remote code ({hit['kind']})",
                detail=hit["detail"] + f" — invocation: `{hit['invocation']}`.",
                evidence=[Evidence(s.get("file", ""), s.get("locator", ""), hit["invocation"])]))
    return out


def r6(configs, authority, ctx):
    out = []
    out += _scan_specs(configs[Tool.CLAUDE_CODE].data["mcp_servers"], Tool.CLAUDE_CODE, "MCP server (.mcp.json)")
    out += _scan_specs(configs[Tool.CODEX].data["mcp_servers"], Tool.CODEX, "MCP server")
    out += _scan_specs(configs[Tool.CURSOR].data["mcp_servers"], Tool.CURSOR, "MCP server (.cursor/mcp.json)")
    out += _scan_specs(configs[Tool.GEMINI_CLI].data["mcp_servers"], Tool.GEMINI_CLI, "MCP server")
    # hook commands as single-string specs
    for h in configs[Tool.CLAUDE_CODE].data["hooks"]:
        out += _scan_specs([{"command": h["command"], "args": [], "file": h["file"], "locator": h["locator"]}],
                           Tool.CLAUDE_CODE, f"hook `{h['event']}`")
    for h in configs[Tool.CODEX].data["hooks"]:
        out += _scan_specs([{"command": h["command"], "args": [], "file": h["file"], "locator": h["locator"]}],
                           Tool.CODEX, f"hook `{h['event']}`")
    return out


ALL_CHECKS = [("R1", r1), ("R2", r2), ("R3", r3), ("R4", r4), ("R5", r5), ("R6", r6)]


def run_all(configs, authority, ctx):
    findings = []
    for _, fn in ALL_CHECKS:
        findings.extend(fn(configs, authority, ctx))
    findings.sort(key=lambda f: f.sort_key())
    return findings


def collect_not_judgeable(configs, authority):
    """Every surface/cell we could not judge, with a reason. Never silent."""
    out = []
    for t in TOOL_ORDER:
        for p in configs[t].problems:
            out.append({"tool": t.value, "kind": "parse-problem", "file": p.file, "reason": p.reason})
        for dim, cell in authority[t].items():
            if cell.source == Source.NOT_JUDGEABLE:
                out.append({"tool": t.value, "kind": "dimension", "dimension": dim.value,
                            "reason": cell.reason})
    out.sort(key=lambda x: (x["tool"], x["kind"], x.get("dimension", ""), x.get("file", ""), x["reason"]))
    return out
