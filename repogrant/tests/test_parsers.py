import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repogrant.model import Tool
from repogrant.parsers import parse_repo
from repogrant.parsers import claude, codex, cursor, gemini


def mkrepo(files: dict) -> str:
    d = tempfile.mkdtemp(prefix="rg_test_")
    for rel, content in files.items():
        path = os.path.join(d, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return d


class TestParsers(unittest.TestCase):
    def test_claude_malformed_json_is_not_silent(self):
        d = mkrepo({".claude/settings.json": "{ not json"})
        cfg = claude.parse(d)
        self.assertTrue(cfg.problems, "malformed JSON must yield a ParseProblem")
        self.assertIn("malformed JSON", cfg.problems[0].reason)
        surf = [s for s in cfg.surfaces if s.file == ".claude/settings.json"][0]
        self.assertTrue(surf.present and not surf.parsed)

    def test_claude_extracts_permissions_and_hooks(self):
        d = mkrepo({".claude/settings.json": json.dumps({
            "permissions": {"allow": ["Bash(git:*)"], "deny": ["Read(.env)"]},
            "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}]},
        })})
        cfg = claude.parse(d)
        self.assertEqual(cfg.data["permissions"]["allow"][0]["value"], "Bash(git:*)")
        self.assertEqual(cfg.data["hooks"][0]["event"], "SessionStart")
        self.assertEqual(cfg.data["hooks"][0]["command"], "echo hi")

    def test_claude_ignored_modes_recorded(self):
        d = mkrepo({".claude/settings.json": json.dumps({"defaultMode": "bypassPermissions"})})
        cfg = claude.parse(d)
        self.assertIsNone(cfg.data["default_mode"])
        self.assertEqual(cfg.data["ignored_modes"][0]["value"], "bypassPermissions")

    def test_codex_malformed_toml_is_not_silent(self):
        d = mkrepo({".codex/config.toml": "x = = ["})
        cfg = codex.parse(d)
        self.assertTrue(cfg.problems)
        self.assertIn("malformed TOML", cfg.problems[0].reason)

    def test_codex_inline_hooks(self):
        d = mkrepo({".codex/config.toml":
                    '[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype="command"\ncommand="echo x"\n'})
        cfg = codex.parse(d)
        self.assertEqual(cfg.data["hooks"][0]["event"], "PreToolUse")

    def test_cursor_rules_md_ignored_mdc_read(self):
        d = mkrepo({".cursor/rules/a.mdc": "rule", ".cursor/rules/b.md": "ignored"})
        cfg = cursor.parse(d)
        mdc = [s for s in cfg.surfaces if s.file.endswith("a.mdc")][0]
        md = [s for s in cfg.surfaces if s.file.endswith("b.md")][0]
        self.assertTrue(mdc.parsed)
        self.assertFalse(md.parsed)
        self.assertIn("ignored", md.note)

    def test_gemini_trust_flag(self):
        d = mkrepo({".gemini/settings.json": json.dumps(
            {"mcpServers": {"s": {"command": "node", "trust": True}}})})
        cfg = gemini.parse(d)
        self.assertTrue(cfg.data["mcp_servers"][0]["trust"])

    def test_parse_repo_detects_secrets_and_vcs(self):
        d = mkrepo({".env": "K=v", "README.md": "x"})
        os.makedirs(os.path.join(d, ".git"))
        parsed = parse_repo(d)
        self.assertIn(".env", parsed["secret_paths"])
        self.assertTrue(parsed["version_controlled"])


if __name__ == "__main__":
    unittest.main()
