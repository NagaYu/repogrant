"""OpenAI Codex CLI: .codex/config.toml, .codex/hooks.json, AGENTS.md."""
from __future__ import annotations

from ..model import Surface, Tool, ToolConfig
from . import as_bool, expect_dict, load_json, load_toml, read_text


def _collect_inline_hooks(hooks_obj, file, out):
    if not isinstance(hooks_obj, dict):
        return
    for event in sorted(hooks_obj.keys()):
        blocks = hooks_obj[event]
        if not isinstance(blocks, list):
            continue
        for i, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            inner = block.get("hooks", [])
            if isinstance(inner, list):
                for h in inner:
                    if isinstance(h, dict):
                        out.append({"event": event,
                                    "command": str(h.get("command") or h.get("type") or repr(h)),
                                    "type": h.get("type", ""),
                                    "file": file, "locator": f"hooks.{event}[{i}]"})


def parse(root: str) -> ToolConfig:
    cfg = ToolConfig(tool=Tool.CODEX)
    data, prob = load_toml(root, ".codex/config.toml")
    approval = None
    sandbox = None
    network_access = None
    writable_roots = []
    mcp_servers = []
    hooks = []
    hooks_feature = None

    if prob:
        cfg.problems.append(prob)
        cfg.surfaces.append(Surface(".codex/config.toml", "settings", True, False, prob.reason))
    elif data is None:
        cfg.surfaces.append(Surface(".codex/config.toml", "settings", False, False))
    else:
        data = expect_dict(data, ".codex/config.toml", cfg.problems)
        if data is None:
            cfg.surfaces.append(Surface(".codex/config.toml", "settings", True, False, "non-object top level"))
        else:
            cfg.surfaces.append(Surface(".codex/config.toml", "settings", True, True))
            ap = data.get("approval_policy")
            if isinstance(ap, str):
                approval = {"value": ap, "file": ".codex/config.toml", "locator": "approval_policy"}
            elif isinstance(ap, dict):
                approval = {"value": "granular", "detail": ap, "file": ".codex/config.toml",
                            "locator": "approval_policy"}
            sm = data.get("sandbox_mode")
            if isinstance(sm, str):
                sandbox = {"value": sm, "file": ".codex/config.toml", "locator": "sandbox_mode"}
            sww = data.get("sandbox_workspace_write", {})
            if isinstance(sww, dict):
                if "network_access" in sww:
                    # egress enabler: ON only on a real `true`; any other value
                    # (incl. the string "false") falls back to OFF, the documented
                    # workspace-write default (Phase 3 presence-vs-value fix).
                    network_access = {"value": as_bool(sww["network_access"]) is True,
                                      "file": ".codex/config.toml",
                                      "locator": "sandbox_workspace_write.network_access"}
                if isinstance(sww.get("writable_roots"), list):
                    writable_roots = list(sww["writable_roots"])
            servers = data.get("mcp_servers", {})
            if isinstance(servers, dict):
                for name in sorted(servers.keys()):
                    s = servers[name]
                    if isinstance(s, dict):
                        mcp_servers.append({"name": name, "command": s.get("command", ""),
                                            "args": s.get("args", []) if isinstance(s.get("args"), list) else [],
                                            "file": ".codex/config.toml",
                                            "locator": f"mcp_servers.{name}"})
            feats = data.get("features", {})
            if isinstance(feats, dict) and "hooks" in feats:
                # hooks engine is on by default; a repo disables it with
                # `hooks = false`. Treat the engine as OFF only on a real `false`;
                # any other value leaves it ON so we never suppress a hook finding
                # on an ambiguous value (Phase 3 presence-vs-value fix).
                hooks_feature = {"value": as_bool(feats["hooks"]) is not False,
                                 "file": ".codex/config.toml", "locator": "features.hooks"}
            _collect_inline_hooks(data.get("hooks"), ".codex/config.toml", hooks)

    # .codex/hooks.json
    hdata, hprob = load_json(root, ".codex/hooks.json")
    if hprob:
        cfg.problems.append(hprob)
        cfg.surfaces.append(Surface(".codex/hooks.json", "hooks", True, False, hprob.reason))
    elif hdata is None:
        cfg.surfaces.append(Surface(".codex/hooks.json", "hooks", False, False))
    else:
        cfg.surfaces.append(Surface(".codex/hooks.json", "hooks", True, True))
        if isinstance(hdata, dict):
            _collect_inline_hooks(hdata.get("hooks", hdata), ".codex/hooks.json", hooks)

    if read_text(root, "AGENTS.md") is not None:
        cfg.surfaces.append(Surface("AGENTS.md", "instruction", True, True))
        cfg.instructions.append("AGENTS.md")

    cfg.data.update({
        "approval_policy": approval,
        "sandbox_mode": sandbox,
        "network_access": network_access,
        "writable_roots": writable_roots,
        "mcp_servers": mcp_servers,
        "hooks": hooks,
        "hooks_feature": hooks_feature,
    })
    return cfg
