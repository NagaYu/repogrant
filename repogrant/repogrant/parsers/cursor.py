"""Cursor: .cursor/permissions.json (IDE), .cursor/sandbox.json, .cursor/mcp.json, .cursor/rules/*.mdc."""
from __future__ import annotations

from ..model import Surface, Tool, ToolConfig
from . import as_bool, expect_dict, list_files, load_json


def parse(root: str) -> ToolConfig:
    cfg = ToolConfig(tool=Tool.CURSOR)
    terminal_allow = []
    mcp_allow = []
    auto_run = None
    sandbox = None
    mcp_servers = []

    # .cursor/permissions.json (IDE form: mcpAllowlist / terminalAllowlist / autoRun)
    data, prob = load_json(root, ".cursor/permissions.json")
    if prob:
        cfg.problems.append(prob)
        cfg.surfaces.append(Surface(".cursor/permissions.json", "settings", True, False, prob.reason))
    elif data is None:
        cfg.surfaces.append(Surface(".cursor/permissions.json", "settings", False, False))
    else:
        data = expect_dict(data, ".cursor/permissions.json", cfg.problems)
        if data is None:
            cfg.surfaces.append(Surface(".cursor/permissions.json", "settings", True, False, "non-object top level"))
        else:
            cfg.surfaces.append(Surface(".cursor/permissions.json", "settings", True, True))
            # Non-string entries inside the arrays are silently dropped by Cursor; a
            # non-list value for the allowlist key is ignored (not iterated as keys).
            ta = data.get("terminalAllowlist")
            if isinstance(ta, list):
                for i, v in enumerate(ta):
                    if isinstance(v, str):
                        terminal_allow.append({"value": v, "file": ".cursor/permissions.json",
                                               "locator": f"terminalAllowlist[{i}]"})
            ma = data.get("mcpAllowlist")
            if isinstance(ma, list):
                for i, v in enumerate(ma):
                    if isinstance(v, str):
                        mcp_allow.append({"value": v, "file": ".cursor/permissions.json",
                                          "locator": f"mcpAllowlist[{i}]"})
            # autoRun is a boolean toggle: it grants auto-run ONLY when it is a
            # real `true`. A falsy/absent/non-boolean value grants nothing (a team
            # setting `autoRun:false` is DISABLING auto-run). Phase 3 fix: this is
            # the owner-named `autoRun:false` false positive and its family.
            if "autoRun" in data and as_bool(data["autoRun"]) is True:
                auto_run = {"value": data["autoRun"], "file": ".cursor/permissions.json",
                            "locator": "autoRun"}

    # .cursor/sandbox.json
    sdata, sprob = load_json(root, ".cursor/sandbox.json")
    if sprob:
        cfg.problems.append(sprob)
        cfg.surfaces.append(Surface(".cursor/sandbox.json", "sandbox", True, False, sprob.reason))
    elif sdata is None:
        cfg.surfaces.append(Surface(".cursor/sandbox.json", "sandbox", False, False))
    else:
        cfg.surfaces.append(Surface(".cursor/sandbox.json", "sandbox", True, True))
        if isinstance(sdata, dict):
            sandbox = {"value": sdata, "file": ".cursor/sandbox.json", "locator": "<root>"}

    # .cursor/mcp.json (project MCP servers)
    mdata, mprob = load_json(root, ".cursor/mcp.json")
    if mprob:
        cfg.problems.append(mprob)
        cfg.surfaces.append(Surface(".cursor/mcp.json", "mcp", True, False, mprob.reason))
    elif mdata is None:
        cfg.surfaces.append(Surface(".cursor/mcp.json", "mcp", False, False))
    else:
        mdata = expect_dict(mdata, ".cursor/mcp.json", cfg.problems)
        if mdata is None:
            cfg.surfaces.append(Surface(".cursor/mcp.json", "mcp", True, False, "non-object top level"))
        else:
            cfg.surfaces.append(Surface(".cursor/mcp.json", "mcp", True, True))
            servers = mdata.get("mcpServers", {})
            if isinstance(servers, dict):
                for name in sorted(servers.keys()):
                    s = servers[name]
                    if isinstance(s, dict) and "command" in s:
                        mcp_servers.append({"name": name, "command": s.get("command", ""),
                                            "args": s.get("args", []) if isinstance(s.get("args"), list) else [],
                                            "file": ".cursor/mcp.json",
                                            "locator": f"mcpServers.{name}"})

    # .cursor/rules/*.mdc  (plain .md is ignored by Cursor)
    rules = list_files(root, ".cursor/rules", ".mdc")
    ignored_md = list_files(root, ".cursor/rules", ".md")
    ignored_md = [f for f in ignored_md if not f.endswith(".mdc")]
    for r in rules:
        cfg.surfaces.append(Surface(r, "rules", True, True))
        cfg.instructions.append(r)
    for r in ignored_md:
        cfg.surfaces.append(Surface(r, "rules", True, False, "plain .md in .cursor/rules is ignored by Cursor"))

    cfg.data.update({
        "terminal_allowlist": terminal_allow,
        "mcp_allowlist": mcp_allow,
        "auto_run": auto_run,
        "sandbox": sandbox,
        "mcp_servers": mcp_servers,
        "rules_mdc": rules,
    })
    return cfg
