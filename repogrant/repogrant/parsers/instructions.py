"""Shared instruction files (AGENTS.md / CLAUDE.md / GEMINI.md) and a small,
deterministic directive-signal extractor used by R3 (instruction divergence).

The signal extractor is intentionally conservative: it only reports a signal
when a line clearly states a prohibition, so R3 instruction findings do not
fire on vague prose. Authority divergence (the primary R3 path) is computed
from the authority models, not from here."""
from __future__ import annotations

import os
import re

from . import read_text

SHARED_INSTRUCTION_FILES = ["AGENTS.md", "CLAUDE.md", "GEMINI.md"]

_NET_FORBID = re.compile(
    r"\b(no (network|internet)|do not (access|use) the (network|internet)|"
    r"never (access|use|make) (the )?(network|internet|outbound|external)|"
    r"offline only|must (remain|stay) offline|do not make (any )?network)",
    re.IGNORECASE,
)
_EXEC_FORBID = re.compile(
    r"\b(do not (run|execute)|never (run|execute)|no shell commands|"
    r"do not use the shell|never use the shell)",
    re.IGNORECASE,
)


def collect_shared(root: str) -> list[str]:
    out = []
    for rel in SHARED_INSTRUCTION_FILES:
        if os.path.isfile(os.path.join(root, rel)):
            out.append(rel)
    return out


def extract_signals(root: str, rel: str) -> dict:
    text = read_text(root, rel) or ""
    net = [ln.strip() for ln in text.splitlines() if _NET_FORBID.search(ln)]
    ex = [ln.strip() for ln in text.splitlines() if _EXEC_FORBID.search(ln)]
    return {
        "file": rel,
        "forbids_network": bool(net),
        "forbids_exec": bool(ex),
        "network_lines": net[:3],
        "exec_lines": ex[:3],
    }
