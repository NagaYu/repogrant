"""Shared semantic interpreters: allowlist-rule breadth and unpinned supply chain.

These encode the documented matching semantics from the register (Claude Bash
`*`/`:*`, Cursor prefix matching) so breadth is RESOLVED, not pattern-matched.
"""
from __future__ import annotations

import re


def parse_tool_rule(rule: str):
    """Split 'Bash(git:*)' -> ('Bash', 'git:*'). Returns (tool, specifier|None)."""
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$", rule.strip())
    if m:
        return m.group(1), m.group(2)
    return rule.strip(), None


def bash_breadth(specifier: str) -> dict:
    """Resolve the true breadth of a Claude Bash(...) specifier.

    Returns {breadth, base, note}. breadth in
    {'unrestricted','program-wide','narrow','empty'}.
    """
    s = (specifier or "").strip()
    if s == "":
        return {"breadth": "empty", "base": "", "note": "empty specifier"}
    # Unrestricted: matches any command.
    if s in ("*", ":*") or s.startswith("*"):
        return {"breadth": "unrestricted", "base": "",
                "note": "matches any command (wildcard with no fixed program)"}
    # Trailing wildcard forms: 'base *', 'base*', 'base:*'
    base = None
    if s.endswith(":*"):
        base = s[:-2].strip()
        form = "`:*` trailing wildcard"
    elif s.endswith(" *"):
        base = s[:-2].strip()
        form = "`<base> *` (space before wildcard)"
    elif s.endswith("*"):
        base = s[:-1].strip()
        form = "`<base>*` (no space; also matches longer program names)"
    if base is not None and base and " " not in base and ":" not in base:
        return {"breadth": "program-wide", "base": base,
                "note": f"auto-approves every `{base}` invocation via {form}; per the docs Bash "
                        f"arg-constraints are \"fragile\" and \"not a security boundary\""}
    if base is not None:
        # wildcard after a multi-token / arg-constrained specifier
        return {"breadth": "program-wide", "base": base or s,
                "note": "trailing wildcard on an arg-constrained specifier; the docs call such "
                        "arg constraints fragile and not a security boundary"}
    return {"breadth": "narrow", "base": s.split()[0] if s.split() else s,
            "note": "fixed specifier (still not a security boundary per the docs)"}


# Commands that make a program-wide auto-approval materially dangerous.
POWERFUL_BASES = {
    "rm", "sudo", "curl", "wget", "ssh", "scp", "git", "docker", "kubectl",
    "aws", "gcloud", "az", "npm", "pip", "pip3", "npx", "uvx", "bash", "sh",
    "zsh", "python", "python3", "node", "eval", "chmod", "chown", "dd", "mv",
}


def cursor_prefix_breadth(entry: str) -> dict:
    """Cursor terminalAllowlist uses case-sensitive prefix semantics:
    'git' matches 'git status' but not 'gitk'."""
    e = (entry or "").strip()
    base = e.split()[0] if e.split() else e
    return {"base": base,
            "note": f"prefix match: `{base}` auto-runs any command starting with `{base}` "
                    f"(token-boundary), when a Run Mode is enabled"}


# --- Unpinned supply chain (R6) -------------------------------------------

_PIPE_EXEC = re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b", re.IGNORECASE)


def _is_unpinned_pkg(token: str) -> bool:
    """A package arg like 'foo' or 'foo@latest' is unpinned; 'foo@1.2.3' is pinned;
    local paths ('./x', '/x', '../x') and option flags are not packages.

    Handles scoped packages: '@scope/name' is unpinned, '@scope/name@1.2.3' pinned.
    """
    if token.startswith(("-", ".", "/")):
        return False
    if token.endswith(("@latest", "@next", "@canary")):
        return True
    scoped = token.startswith("@")
    at_count = token.count("@")
    if scoped:
        # version present only if there is a second '@'
        if at_count < 2:
            return True
        version = token.rsplit("@", 1)[-1]
    else:
        if at_count == 0:
            return True
        version = token.rsplit("@", 1)[-1]
    # pinned when the version starts with a digit (e.g. 1.2.3)
    return not bool(re.match(r"^[0-9]", version))


def detect_unpinned(command: str, args: list) -> list[dict]:
    """Return a list of unpinned-execution findings for one launch spec.

    Each item: {kind, detail, invocation}.
    """
    out = []
    args = [str(a) for a in (args or [])]
    cmd = str(command or "")
    invocation = (cmd + " " + " ".join(args)).strip()

    # curl|bash style inside the command string or any single arg.
    for blob in [cmd, invocation] + args:
        if _PIPE_EXEC.search(blob):
            out.append({"kind": "pipe-to-shell",
                        "detail": "pipes remote content directly into a shell interpreter",
                        "invocation": invocation})
            break

    base = cmd.rsplit("/", 1)[-1]
    # `npx`, and the equivalent one-off remote-exec runners `pnpm dlx` / `yarn dlx`
    # / `bunx`, all download-and-run a package; an unpinned package is the same
    # supply-chain risk whichever launcher is used (Phase 3 evasion fix).
    dlx_args = None
    if base in ("npx", "bunx"):
        dlx_args = args
    elif base in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        dlx_args = args[1:]
    if dlx_args is not None:
        pkgs = _npx_packages(dlx_args)
        for p in pkgs:
            if _is_unpinned_pkg(p):
                out.append({"kind": "unpinned-npx",
                            "detail": f"`{base}` launches `{p}` with no pinned version",
                            "invocation": invocation})
    elif base in ("uvx",):
        for p in args:
            if not p.startswith("-"):
                if _is_unpinned_pkg(p):
                    out.append({"kind": "unpinned-uvx",
                                "detail": f"`uvx` launches `{p}` with no pinned version",
                                "invocation": invocation})
                break
    elif base in ("pip", "pip3") and args[:1] == ["install"]:
        for p in args[1:]:
            if p.startswith(("git+", "http://", "https://")) and "@" not in p:
                out.append({"kind": "unpinned-pip-url",
                            "detail": f"`pip install` from an unpinned URL `{p}`",
                            "invocation": invocation})
    # dedupe deterministically
    seen = set()
    uniq = []
    for o in out:
        key = (o["kind"], o["detail"])
        if key not in seen:
            seen.add(key)
            uniq.append(o)
    return uniq


def _npx_packages(args: list) -> list:
    pkgs = []
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if a in ("-y", "--yes", "-q", "--quiet"):
            continue
        if a in ("-p", "--package", "-c", "--call"):
            # next token is the package
            if i + 1 < len(args):
                pkgs.append(args[i + 1])
                skip_next = True
            continue
        if a.startswith("-"):
            continue
        # first positional is the package to run
        pkgs.append(a)
        break
    return pkgs
