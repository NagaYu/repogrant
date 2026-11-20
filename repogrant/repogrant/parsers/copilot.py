"""GitHub Copilot: instruction-only surfaces (.github/copilot-instructions.md,
.github/instructions/**/*.instructions.md). Per D-02, Copilot's command/sandbox
authority is not-judgeable from the repo; only instruction files are read (R3)."""
from __future__ import annotations

from ..model import Surface, Tool, ToolConfig
from . import list_files, read_text


def parse(root: str) -> ToolConfig:
    cfg = ToolConfig(tool=Tool.COPILOT)
    main = ".github/copilot-instructions.md"
    if read_text(root, main) is not None:
        cfg.surfaces.append(Surface(main, "instruction", True, True))
        cfg.instructions.append(main)
    else:
        cfg.surfaces.append(Surface(main, "instruction", False, False))
    for rel in list_files(root, ".github/instructions", ".instructions.md"):
        cfg.surfaces.append(Surface(rel, "instruction", True, True))
        cfg.instructions.append(rel)
    cfg.data.update({"instruction_only": True})
    return cfg
