"""Core data model for RepoGrant.

Everything here is plain, JSON-serialisable data. No timestamps, no
absolute paths, no randomness: the model exists so that the same input
tree yields a byte-identical report (Gate 1 determinism bar).
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

REPORT_VERSION = "1.0"
TOOL_VERSION = "0.1.0"


class Tool(str, Enum):
    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    CURSOR = "cursor"
    COPILOT = "copilot"
    GEMINI_CLI = "gemini_cli"


# Deterministic tool ordering used everywhere we emit tools.
TOOL_ORDER = [
    Tool.CLAUDE_CODE,
    Tool.CODEX,
    Tool.CURSOR,
    Tool.COPILOT,
    Tool.GEMINI_CLI,
]

TOOL_LABEL = {
    Tool.CLAUDE_CODE: "Claude Code",
    Tool.CODEX: "OpenAI Codex CLI",
    Tool.CURSOR: "Cursor",
    Tool.COPILOT: "GitHub Copilot",
    Tool.GEMINI_CLI: "Gemini CLI",
}


class Dimension(str, Enum):
    COMMAND_EXECUTION = "command_execution"
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    NETWORK_EGRESS = "network_egress"
    SECRET_REACH = "secret_reach"
    AUTO_APPROVAL = "auto_approval"


# Deterministic dimension ordering (matches the Phase 1 brief's six axes).
DIMENSION_ORDER = [
    Dimension.COMMAND_EXECUTION,
    Dimension.FILESYSTEM_READ,
    Dimension.FILESYSTEM_WRITE,
    Dimension.NETWORK_EGRESS,
    Dimension.SECRET_REACH,
    Dimension.AUTO_APPROVAL,
]


class Source(str, Enum):
    CONFIG = "config"            # value came from repo config only
    DEFAULT = "default"          # repo silent; value is the documented default
    CONFIG_DEFAULT = "config+default"  # config read, defaults filled the rest
    NOT_JUDGEABLE = "not-judgeable"


NOT_JUDGEABLE = "not-judgeable"


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"
    NOT_JUDGEABLE = "not-judgeable"


SEVERITY_RANK = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.INFO: 2,
    Severity.NOT_JUDGEABLE: 3,
}


@dataclass(frozen=True)
class Evidence:
    """A pointer into a source file or a documented default."""
    file: str            # repo-relative path, or "<docs>" for a default
    locator: str         # e.g. "permissions.allow[0]", "hooks.SessionStart", "<default>"
    excerpt: str = ""    # raw value/snippet, or the doc quote for a default
    url: str = ""        # for documented defaults: the primary-source URL

    def to_dict(self) -> dict:
        d = {"file": self.file, "locator": self.locator}
        if self.excerpt:
            d["excerpt"] = self.excerpt
        if self.url:
            d["url"] = self.url
        return d


@dataclass
class AuthorityCell:
    """What one tool grants on one dimension, resolved from config+defaults."""
    dimension: Dimension
    level: str                               # dimension-specific token, or NOT_JUDGEABLE
    consent_required: Optional[bool]         # True=per-call consent; False=runs without; None=n/a
    source: Source
    rationale: str                           # deterministic human-readable explanation
    evidence: list[Evidence] = field(default_factory=list)
    reason: str = ""                         # only for not-judgeable cells

    def to_dict(self) -> dict:
        d = {
            "dimension": self.dimension.value,
            "level": self.level,
            "consent_required": self.consent_required,
            "source": self.source.value,
            "rationale": self.rationale,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.reason:
            d["reason"] = self.reason
        return d


@dataclass
class Finding:
    check: str                 # "R1".."R6"
    klass: str                 # short class slug
    tool: Optional[Tool]       # None for cross-tool findings (R3)
    tools: list[Tool] = field(default_factory=list)  # for cross-tool findings
    dimension: Optional[Dimension] = None
    severity: Severity = Severity.INFO
    title: str = ""
    detail: str = ""
    evidence: list[Evidence] = field(default_factory=list)

    def sort_key(self) -> tuple:
        return (
            self.check,
            SEVERITY_RANK[self.severity],
            self.tool.value if self.tool else "",
            ",".join(t.value for t in self.tools),
            self.dimension.value if self.dimension else "",
            self.title,
        )

    def to_dict(self) -> dict:
        d = {
            "check": self.check,
            "class": self.klass,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": [e.to_dict() for e in self.evidence],
        }
        if self.tool is not None:
            d["tool"] = self.tool.value
        if self.tools:
            d["tools"] = [t.value for t in self.tools]
        if self.dimension is not None:
            d["dimension"] = self.dimension.value
        return d


@dataclass
class ParseProblem:
    """A surface that could not be parsed -> not-judgeable, never silent."""
    file: str
    reason: str

    def to_dict(self) -> dict:
        return {"file": self.file, "reason": self.reason}


@dataclass
class Surface:
    """A repo-side config surface that a parser found and read."""
    file: str
    kind: str            # "settings" | "mcp" | "hooks" | "sandbox" | "instruction" | "rules"
    present: bool
    parsed: bool
    note: str = ""

    def to_dict(self) -> dict:
        d = {"file": self.file, "kind": self.kind, "present": self.present, "parsed": self.parsed}
        if self.note:
            d["note"] = self.note
        return d


@dataclass
class ToolConfig:
    """Parsed per-tool view of the repo: raw extracted values + problems."""
    tool: Tool
    surfaces: list[Surface] = field(default_factory=list)
    problems: list[ParseProblem] = field(default_factory=list)
    data: dict = field(default_factory=dict)   # normalised extracted values
    instructions: list[str] = field(default_factory=list)  # repo-relative instruction files


def ensure_dataclass_json(obj):
    """Fallback serialiser (not used for the main report, which uses to_dict)."""
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    raise TypeError(type(obj))
