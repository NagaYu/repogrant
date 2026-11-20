"""Parsers for the in-scope repo-side agent-config surfaces.

Contract: a surface that is present but malformed, or structurally not what
we expect, yields a ParseProblem (-> not-judgeable downstream). Nothing is
ever silently skipped. A surface that is simply absent is recorded as a
Surface(present=False) so the report can say "repo is silent here".
"""
from __future__ import annotations

import json
import os
import tomllib
from typing import Optional

from ..model import ParseProblem, Surface, Tool, ToolConfig


def read_text(root: str, rel: str) -> Optional[str]:
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except (OSError, UnicodeDecodeError):
        return None


def as_bool(v):
    """Safely interpret a config toggle's value as a boolean.

    Recognises the canonical true/false forms a config can carry — real
    booleans, the strings `"true"/"false"/"yes"/"no"/"on"/"off"/"1"/"0"`
    (case-insensitive), the numbers `1`/`0`, and `null` (treated as off/unset).
    Anything genuinely ambiguous (an arbitrary string, array, object, other
    number) returns **None**, and callers then decide conservatively per the
    toggle's safety direction.

    This deliberately does NOT use Python truthiness: `bool("false")` is True,
    which silently flips a toggle a team wrote as the string `"false"`. The
    Phase 3 presence-vs-value fix hinges on `"false"`/`0`/`null` reading as off.
    """
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if v == 0:
            return False
        if v == 1:
            return True
        return None
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "on", "1"):
            return True
        if s in ("false", "no", "off", "0", ""):
            return False
        return None
    return None


def load_json(root: str, rel: str):
    """Return (data, problem). data is None when the file is ABSENT.
    A present file whose top-level JSON is `null` is a present-but-not-an-object
    surface -> ParseProblem (not-judgeable), never conflated with absent."""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        return None, ParseProblem(rel, f"malformed JSON: {e.msg} (line {e.lineno})")
    except (OSError, UnicodeDecodeError) as e:
        return None, ParseProblem(rel, f"unreadable: {e.__class__.__name__}")
    if data is None:
        # literal top-level `null` in a present file (would otherwise read as absent)
        return None, ParseProblem(rel, "top-level JSON is null (expected an object)")
    return data, None


def load_toml(root: str, rel: str):
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), None
    except tomllib.TOMLDecodeError as e:
        return None, ParseProblem(rel, f"malformed TOML: {e}")
    except OSError as e:
        return None, ParseProblem(rel, f"unreadable: {e.__class__.__name__}")


def list_files(root: str, rel_dir: str, suffix: str) -> list[str]:
    """Deterministically list files under rel_dir with a given suffix (recursive)."""
    base = os.path.join(root, rel_dir)
    out: list[str] = []
    if not os.path.isdir(base):
        return out
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(suffix):
                full = os.path.join(dirpath, name)
                out.append(os.path.relpath(full, root))
    return sorted(out)


def expect_dict(data, rel: str, problems: list[ParseProblem]):
    if data is not None and not isinstance(data, dict):
        problems.append(ParseProblem(rel, f"expected a JSON/TOML object at top level, got {type(data).__name__}"))
        return None
    return data


def parse_repo(root: str) -> dict:
    """Parse every in-scope surface. Returns tool_configs + repo-level facts."""
    from . import claude, codex, copilot, cursor, gemini, instructions

    configs = {
        Tool.CLAUDE_CODE: claude.parse(root),
        Tool.CODEX: codex.parse(root),
        Tool.CURSOR: cursor.parse(root),
        Tool.COPILOT: copilot.parse(root),
        Tool.GEMINI_CLI: gemini.parse(root),
    }
    shared = instructions.collect_shared(root)
    return {
        "configs": configs,
        "shared_instructions": shared,
        "version_controlled": os.path.isdir(os.path.join(root, ".git")),
        "secret_paths": _find_secret_paths(root),
    }


# Secret-bearing path signatures (filename-level; used by R5 and secret_reach).
_SECRET_NAMES = {".env", ".env.local", ".env.production", ".env.development",
                 "credentials", "credentials.json", "secrets.json", ".npmrc",
                 ".pypirc", "id_rsa", "id_ed25519", ".netrc", "service-account.json"}
_SECRET_SUFFIXES = (".pem", ".key", ".pfx", ".p12", ".keystore")
_SECRET_PREFIXES = (".env",)
# `.env.*` variants that are conventionally committed TEMPLATES/config, not real
# secrets. The field audit (Phase 3) found `.env.example` / `.env.template` /
# `.env.sample` and `.envrc` driving spurious R4/R5 findings. Excluded so
# secret_reach / R4 / R5 fire on real secret-bearing files, not placeholders.
_ENV_NONSECRET_SUFFIXES = (".example", ".sample", ".template", ".tmpl",
                           ".dist", ".defaults", ".default")
_ENV_NONSECRET_NAMES = {".envrc"}


def _looks_secret(name: str) -> bool:
    if name in _ENV_NONSECRET_NAMES:
        return False
    if name in _SECRET_NAMES:
        return True
    if name.endswith(_SECRET_SUFFIXES):
        return True
    if name.startswith(_SECRET_PREFIXES):
        # a `.env`-prefixed file is a template, not a secret, when it ends in a
        # known placeholder marker (e.g. `.env.example`, `.env.before.example`).
        if name.endswith(_ENV_NONSECRET_SUFFIXES):
            return False
        return True
    return False


def _find_secret_paths(root: str) -> list[str]:
    out: list[str] = []
    skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            if _looks_secret(name):
                out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)
