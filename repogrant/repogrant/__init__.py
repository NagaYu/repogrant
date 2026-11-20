"""RepoGrant — cross-tool repo-side effective-authority verifier.

Computes, per agent tool, the effective authority a repository grants —
command execution, filesystem read/write, network egress, secret reach,
auto-approval surface — under each tool's documented semantics, with the
documented defaults filled in where the repo is silent.
"""
from .model import REPORT_VERSION, TOOL_VERSION  # noqa: F401

__version__ = TOOL_VERSION
