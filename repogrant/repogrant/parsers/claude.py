"""Claude Code: .claude/settings.json, .claude/settings.local.json, .mcp.json, CLAUDE.md."""
from __future__ import annotations

from ..model import Surface, Tool, ToolConfig
from . import expect_dict, load_json, read_text

# From project/local settings only default/acceptEdits/plan take effect
# ("auto and bypassPermissions don't take effect from project or local settings").
EFFECTIVE_MODES = {"default", "acceptEdits", "plan"}
IGNORED_MODES = {"auto", "bypassPermissions"}

_LIST_KEYS = ["allow", "deny", "ask", "additionalDirectories"]


def _collect_hooks(hooks_obj, file, out):
    if not isinstance(hooks_obj, dict):
        return
    for event in sorted(hooks_obj.keys()):
        entries = hooks_obj[event]
        if not isinstance(entries, list):
            out.append({"event": event, "command": repr(entries), "file": file,
                        "locator": f"hooks.{event}"})
            continue
        for i, matcher_block in enumerate(entries):
            cmds = []
            if isinstance(matcher_block, dict):
                for h in matcher_block.get("hooks", []) or []:
                    if isinstance(h, dict):
                        cmds.append(h.get("command") or h.get("type") or repr(h))
            if not cmds:
                cmds = [repr(matcher_block)]
            for cmd in cmds:
                out.append({"event": event, "command": str(cmd), "file": file,
                            "locator": f"hooks.{event}[{i}]"})


def parse(root: str) -> ToolConfig:
    cfg = ToolConfig(tool=Tool.CLAUDE_CODE)
    perms = {k: [] for k in _LIST_KEYS}
    block_reads = (None, None)
    default_mode = None
    ignored_modes = []
    hooks = []

    # settings.json (shared project) is lower precedence than settings.local.json.
    for rel in [".claude/settings.json", ".claude/settings.local.json"]:
        data, prob = load_json(root, rel)
        if prob:
            cfg.problems.append(prob)
            cfg.surfaces.append(Surface(rel, "settings", True, False, prob.reason))
            continue
        if data is None:
            cfg.surfaces.append(Surface(rel, "settings", False, False))
            continue
        data = expect_dict(data, rel, cfg.problems)
        if data is None:
            cfg.surfaces.append(Surface(rel, "settings", True, False, "non-object top level"))
            continue
        cfg.surfaces.append(Surface(rel, "settings", True, True))
        p = data.get("permissions", {})
        if isinstance(p, dict):
            for k in _LIST_KEYS:
                vals = p.get(k)
                if isinstance(vals, list):
                    for i, v in enumerate(vals):
                        # Permission rules are strings (e.g. "Bash(git:*)"). A
                        # non-string entry is not a valid rule; keep it out of the
                        # rule lists so the semantic parser never runs .strip() on
                        # a non-string (Phase 3 crash fix).
                        if isinstance(v, str):
                            perms[k].append({"value": v, "file": rel, "locator": f"permissions.{k}[{i}]"})
            if "blockReadsOutsideWorkingDirectories" in p:
                block_reads = (bool(p["blockReadsOutsideWorkingDirectories"]), rel)
        # defaultMode may appear under permissions or top-level per docs variants.
        dm = p.get("defaultMode") if isinstance(p, dict) else None
        dm = dm or data.get("defaultMode")
        if isinstance(dm, str):
            if dm in EFFECTIVE_MODES:
                default_mode = (dm, rel)      # later file (local) wins
            elif dm in IGNORED_MODES:
                ignored_modes.append({"value": dm, "file": rel})
        _collect_hooks(data.get("hooks"), rel, hooks)
        cfg.data.setdefault("mcp_approval", {})
        for key in ("enableAllProjectMcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers"):
            if key in data:
                cfg.data["mcp_approval"][key] = {"value": data[key], "file": rel}

    # .mcp.json
    mcp_servers = []
    data, prob = load_json(root, ".mcp.json")
    if prob:
        cfg.problems.append(prob)
        cfg.surfaces.append(Surface(".mcp.json", "mcp", True, False, prob.reason))
    elif data is None:
        cfg.surfaces.append(Surface(".mcp.json", "mcp", False, False))
    else:
        data = expect_dict(data, ".mcp.json", cfg.problems)
        if data is None:
            cfg.surfaces.append(Surface(".mcp.json", "mcp", True, False, "non-object top level"))
        else:
            cfg.surfaces.append(Surface(".mcp.json", "mcp", True, True))
            servers = data.get("mcpServers", {})
            if isinstance(servers, dict):
                for name in sorted(servers.keys()):
                    s = servers[name]
                    if isinstance(s, dict):
                        mcp_servers.append({
                            "name": name,
                            "command": s.get("command", ""),
                            "args": s.get("args", []) if isinstance(s.get("args"), list) else [],
                            "file": ".mcp.json",
                            "locator": f"mcpServers.{name}",
                        })

    # CLAUDE.md (instruction only, R3)
    if read_text(root, "CLAUDE.md") is not None:
        cfg.surfaces.append(Surface("CLAUDE.md", "instruction", True, True))
        cfg.instructions.append("CLAUDE.md")

    cfg.data.update({
        "permissions": perms,
        "block_reads_outside": {"value": block_reads[0], "file": block_reads[1]},
        "default_mode": {"value": default_mode[0], "file": default_mode[1]} if default_mode else None,
        "ignored_modes": ignored_modes,
        "hooks": hooks,
        "mcp_servers": mcp_servers,
    })
    return cfg
