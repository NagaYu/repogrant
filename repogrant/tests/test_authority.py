import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repogrant import authority
from repogrant.model import Dimension as D
from repogrant.model import Source, Tool
from repogrant.parsers import parse_repo
from repogrant.semantics import bash_breadth


def mkrepo(files: dict, git=False) -> str:
    d = tempfile.mkdtemp(prefix="rg_auth_")
    for rel, content in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    if git:
        os.makedirs(os.path.join(d, ".git"))
    return d


def auth_for(files, git=False):
    d = mkrepo(files, git=git)
    parsed = parse_repo(d)
    ctx = {"root": d, "version_controlled": parsed["version_controlled"],
           "secret_paths": parsed["secret_paths"]}
    return authority.compute(parsed["configs"], ctx)


class TestAuthority(unittest.TestCase):
    def test_bash_breadth_semantics(self):
        self.assertEqual(bash_breadth("*")["breadth"], "unrestricted")
        self.assertEqual(bash_breadth(":*")["breadth"], "unrestricted")
        self.assertEqual(bash_breadth("git:*")["breadth"], "program-wide")
        self.assertEqual(bash_breadth("git:*")["base"], "git")
        self.assertEqual(bash_breadth("aws *")["breadth"], "program-wide")
        self.assertEqual(bash_breadth("npm run build")["breadth"], "narrow")

    def test_claude_wildcard_is_unrestricted(self):
        a = auth_for({".claude/settings.json": json.dumps({"permissions": {"allow": ["Bash(*)"]}})})
        self.assertEqual(a[Tool.CLAUDE_CODE][D.COMMAND_EXECUTION].level, "unrestricted")
        self.assertEqual(a[Tool.CLAUDE_CODE][D.COMMAND_EXECUTION].consent_required, False)
        self.assertEqual(a[Tool.CLAUDE_CODE][D.NETWORK_EGRESS].level, "on")

    def test_claude_deny_blocks(self):
        a = auth_for({".claude/settings.json": json.dumps({"permissions": {"deny": ["Bash(*)"]}})})
        self.assertEqual(a[Tool.CLAUDE_CODE][D.COMMAND_EXECUTION].level, "blocked")

    def test_codex_readonly(self):
        a = auth_for({".codex/config.toml": 'sandbox_mode="read-only"\napproval_policy="on-request"\n'})
        self.assertEqual(a[Tool.CODEX][D.FILESYSTEM_WRITE].level, "none")
        self.assertEqual(a[Tool.CODEX][D.NETWORK_EGRESS].level, "off")

    def test_codex_silent_vcs_default_is_workspace_write(self):
        a = auth_for({"README.md": "x"}, git=True)
        cell = a[Tool.CODEX][D.FILESYSTEM_WRITE]
        self.assertEqual(cell.level, "workspace")
        self.assertEqual(cell.source, Source.DEFAULT)

    def test_codex_silent_non_vcs_default_is_readonly(self):
        a = auth_for({"README.md": "x"}, git=False)
        self.assertEqual(a[Tool.CODEX][D.FILESYSTEM_WRITE].level, "none")

    def test_gemini_trust_auto_approval(self):
        a = auth_for({".gemini/settings.json": json.dumps(
            {"mcpServers": {"s": {"command": "node", "trust": True}}})})
        self.assertEqual(a[Tool.GEMINI_CLI][D.AUTO_APPROVAL].level, "present")
        self.assertEqual(a[Tool.GEMINI_CLI][D.AUTO_APPROVAL].consent_required, False)

    def test_gemini_egress_default_not_judgeable(self):
        a = auth_for({".gemini/settings.json": json.dumps({"general": {"defaultApprovalMode": "default"}})})
        self.assertEqual(a[Tool.GEMINI_CLI][D.NETWORK_EGRESS].source, Source.NOT_JUDGEABLE)

    def test_cursor_and_copilot_mostly_not_judgeable(self):
        a = auth_for({"README.md": "x"})
        self.assertEqual(a[Tool.CURSOR][D.COMMAND_EXECUTION].source, Source.NOT_JUDGEABLE)
        self.assertEqual(a[Tool.COPILOT][D.COMMAND_EXECUTION].source, Source.NOT_JUDGEABLE)

    def test_codex_danger_full_unrestricted(self):
        a = auth_for({".codex/config.toml": 'sandbox_mode="danger-full-access"\napproval_policy="never"\n'})
        self.assertEqual(a[Tool.CODEX][D.COMMAND_EXECUTION].level, "unrestricted")
        self.assertEqual(a[Tool.CODEX][D.NETWORK_EGRESS].level, "on")


if __name__ == "__main__":
    unittest.main()
