"""Gemini CLI: .gemini/settings.json, GEMINI.md."""
from __future__ import annotations

from ..model import Surface, Tool, ToolConfig
from . import as_bool, expect_dict, load_json, read_text


def _get(d, path):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def parse(root: str) -> ToolConfig:
    cfg = ToolConfig(tool=Tool.GEMINI_CLI)
    rel = ".gemini/settings.json"
    data, prob = load_json(root, rel)
    approval_mode = None
    sandbox = None
    sandbox_network = None
    sandbox_paths = []
    folder_trust = None
    disable_yolo = None
    disable_always_allow = None
    mcp_servers = []

    if prob:
        cfg.problems.append(prob)
        cfg.surfaces.append(Surface(rel, "settings", True, False, prob.reason))
    elif data is None:
        cfg.surfaces.append(Surface(rel, "settings", False, False))
    else:
        data = expect_dict(data, rel, cfg.problems)
        if data is None:
            cfg.surfaces.append(Surface(rel, "settings", True, False, "non-object top level"))
        else:
            cfg.surfaces.append(Surface(rel, "settings", True, True))
            v = _get(data, "general.defaultApprovalMode")
            if isinstance(v, str):
                approval_mode = {"value": v, "file": rel, "locator": "general.defaultApprovalMode"}
            if _get(data, "tools.sandbox") is not None:
                sandbox = {"value": _get(data, "tools.sandbox"), "file": rel, "locator": "tools.sandbox"}
            if _get(data, "tools.sandboxNetworkAccess") is not None:
                # egress enabler: ON only on a real `true` (Phase 3 fix).
                sandbox_network = {"value": as_bool(_get(data, "tools.sandboxNetworkAccess")) is True,
                                   "file": rel, "locator": "tools.sandboxNetworkAccess"}
            sp = _get(data, "tools.sandboxAllowedPaths")
            if isinstance(sp, list):
                sandbox_paths = list(sp)
            ft = _get(data, "security.folderTrust.enabled")
            if ft is not None:
                # protective toggle: Folder Trust counts as ON (safe mode engaged)
                # only on a real `true`; any other value (incl. the string "false")
                # leaves it OFF so the R4 defaults-trap is never missed (Phase 3 fix).
                folder_trust = {"value": as_bool(ft) is True, "file": rel,
                                "locator": "security.folderTrust.enabled"}
            dy = _get(data, "security.disableYoloMode")
            if dy is not None:
                disable_yolo = {"value": as_bool(dy) is True, "file": rel, "locator": "security.disableYoloMode"}
            da = _get(data, "security.disableAlwaysAllow")
            if da is not None:
                disable_always_allow = {"value": as_bool(da) is True, "file": rel,
                                        "locator": "security.disableAlwaysAllow"}
            servers = data.get("mcpServers", {})
            if isinstance(servers, dict):
                for name in sorted(servers.keys()):
                    s = servers[name]
                    if isinstance(s, dict):
                        mcp_servers.append({
                            "name": name, "command": s.get("command", ""),
                            "args": s.get("args", []) if isinstance(s.get("args"), list) else [],
                            # trust bypass is an enabler: honor ONLY a real `true`.
                            "trust": as_bool(s.get("trust")) is True,
                            "file": rel, "locator": f"mcpServers.{name}",
                        })

    if read_text(root, "GEMINI.md") is not None:
        cfg.surfaces.append(Surface("GEMINI.md", "instruction", True, True))
        cfg.instructions.append("GEMINI.md")

    cfg.data.update({
        "approval_mode": approval_mode,
        "sandbox": sandbox,
        "sandbox_network": sandbox_network,
        "sandbox_paths": sandbox_paths,
        "folder_trust": folder_trust,
        "disable_yolo": disable_yolo,
        "disable_always_allow": disable_always_allow,
        "mcp_servers": mcp_servers,
    })
    return cfg
