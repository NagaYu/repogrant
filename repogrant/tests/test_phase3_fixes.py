"""Phase 3 regression tests: value-aware boolean toggles, type-confusion
hardening, structural-null handling, secret-matcher precision, and the R6
alternative-runner evasion fix.

Each test pins one confirmed Phase 3 defect so a regression re-breaks a test.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repogrant import authority
from repogrant.model import Dimension as D
from repogrant.model import Tool
from repogrant.parsers import as_bool, parse_repo
from repogrant.parsers import _looks_secret
from repogrant.report import analyze
from repogrant.semantics import detect_unpinned


def mkrepo(files, git=False):
    d = tempfile.mkdtemp(prefix="rg_p3_")
    for rel, content in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
    if git:
        os.makedirs(os.path.join(d, ".git"))
    return d


def findings(files, git=False):
    return analyze(mkrepo(files, git=git))["findings"]


def auth(files, git=False):
    d = mkrepo(files, git=git)
    parsed = parse_repo(d)
    ctx = {"root": d, "version_controlled": parsed["version_controlled"],
           "secret_paths": parsed["secret_paths"]}
    return authority.compute(parsed["configs"], ctx)


class TestAsBool(unittest.TestCase):
    def test_canonical_true_forms(self):
        for v in (True, 1, "true", "TRUE", "yes", "on", "1"):
            self.assertIs(as_bool(v), True, v)

    def test_canonical_false_forms(self):
        for v in (False, 0, "false", "FALSE", "no", "off", "0", "", None):
            self.assertIs(as_bool(v), False, v)

    def test_ambiguous_is_none(self):
        for v in (2, "maybe", [], {}, "truthy"):
            self.assertIsNone(as_bool(v), v)


class TestCursorAutoRunValueAware(unittest.TestCase):
    """The owner-named false positive and its presence-vs-value family."""
    def _no_grant(self, raw):
        fs = findings({".cursor/permissions.json": '{"autoRun": %s}' % raw})
        self.assertEqual([f for f in fs if f["check"] == "R1"], [],
                         f"autoRun:{raw} must not fire R1")
        a = auth({".cursor/permissions.json": '{"autoRun": %s}' % raw})
        self.assertNotIn(a[Tool.CURSOR][D.COMMAND_EXECUTION].level,
                         ("conditional", "unrestricted"), raw)
        self.assertNotIn(a[Tool.CURSOR][D.AUTO_APPROVAL].level,
                         ("present", "present-runmode-gated"), raw)

    def test_false_zero_null_strfalse_grant_nothing(self):
        for raw in ("false", "0", "null", '"false"'):
            self._no_grant(raw)

    def test_true_still_fires(self):
        fs = findings({".cursor/permissions.json": '{"autoRun": true}'})
        self.assertTrue([f for f in fs if f["check"] == "R1"],
                        "autoRun:true must still fire R1")


class TestTypeConfusion(unittest.TestCase):
    def test_nonstring_permission_entries_do_not_crash(self):
        fs = findings({".claude/settings.json": json.dumps(
            {"permissions": {"allow": [123, {"x": 1}], "deny": [None]}})})
        self.assertEqual(fs, [], "non-string rules are ignored, no crash, no finding")

    def test_cursor_allowlist_nonlist_not_iterated_as_keys(self):
        fs = findings({".cursor/permissions.json": json.dumps(
            {"terminalAllowlist": {"rm": "yes"}})})
        self.assertEqual(fs, [], "a dict allowlist must not be read as entries")

    def test_codex_approval_array_not_misread(self):
        a = auth({".codex/config.toml": 'approval_policy = ["never"]\n'})
        self.assertNotEqual(a[Tool.CODEX][D.COMMAND_EXECUTION].level, "unrestricted")


class TestStructuralNull(unittest.TestCase):
    def test_json_null_is_not_judgeable_not_absent(self):
        rep = analyze(mkrepo({".claude/settings.json": "null\n", ".mcp.json": "null\n"}))
        nj = {x.get("file") for x in rep["not_judgeable"] if x.get("kind") == "parse-problem"}
        self.assertIn(".claude/settings.json", nj)
        self.assertIn(".mcp.json", nj)
        # and the surface is recorded present, not silently absent
        surfs = {s["file"]: s for s in rep["tools"]["claude_code"]["surfaces"]}
        self.assertTrue(surfs[".claude/settings.json"]["present"])
        self.assertFalse(surfs[".claude/settings.json"]["parsed"])


class TestBooleanToggleDirections(unittest.TestCase):
    def test_folder_trust_strfalse_still_trips_trap(self):
        fs = findings({".gemini/settings.json": '{"security":{"folderTrust":{"enabled":"false"}}}',
                       ".env": "K=v\n"})
        self.assertTrue(any(f["check"] == "R4" and f.get("tool") == "gemini_cli" for f in fs),
                        'folderTrust "false" means OFF -> R4 trap must fire')

    def test_folder_trust_true_suppresses_trap(self):
        fs = findings({".gemini/settings.json":
                       '{"security":{"folderTrust":{"enabled":true}},'
                       '"general":{"defaultApprovalMode":"default"}}',
                       ".env": "K=v\n"})
        self.assertFalse(any(f["check"] == "R4" and f.get("tool") == "gemini_cli" for f in fs))

    def test_codex_hooks_strfalse_disables(self):
        fs = findings({".codex/config.toml":
                       '[features]\nhooks = "false"\n\n'
                       '[[hooks.PreToolUse]]\nmatcher = "*"\n'
                       '[[hooks.PreToolUse.hooks]]\ntype="command"\ncommand="x"\n'})
        self.assertEqual([f for f in fs if f["check"] == "R1"], [])

    def test_codex_network_access_strfalse_is_off(self):
        a = auth({".codex/config.toml":
                  'sandbox_mode="workspace-write"\n\n'
                  '[sandbox_workspace_write]\nnetwork_access="false"\n'})
        self.assertEqual(a[Tool.CODEX][D.NETWORK_EGRESS].level, "off")

    def test_gemini_trust_strtrue_honored_strfalse_not(self):
        a_true = auth({".gemini/settings.json":
                       '{"mcpServers":{"s":{"command":"node","trust":"true"}},'
                       '"security":{"folderTrust":{"enabled":true}}}'})
        self.assertEqual(a_true[Tool.GEMINI_CLI][D.AUTO_APPROVAL].level, "present")
        a_false = auth({".gemini/settings.json":
                        '{"mcpServers":{"s":{"command":"node","trust":"false"}},'
                        '"security":{"folderTrust":{"enabled":true}}}'})
        self.assertNotEqual(a_false[Tool.GEMINI_CLI][D.AUTO_APPROVAL].level, "present")


class TestSecretMatcherPrecision(unittest.TestCase):
    def test_env_templates_are_not_secrets(self):
        for name in (".env.example", ".env.sample", ".env.template",
                     ".env.before.example", ".envrc", ".env.dist"):
            self.assertFalse(_looks_secret(name), name)

    def test_real_env_files_are_secrets(self):
        for name in (".env", ".env.local", ".env.production", "id_rsa", "server.pem"):
            self.assertTrue(_looks_secret(name), name)

    def test_env_example_does_not_trip_claude_r4(self):
        fs = findings({".env.example": "TOKEN=\n", "README.md": "# x\n"})
        self.assertFalse(any(f["check"] == "R4" and f.get("tool") == "claude_code" for f in fs))


class TestR6AltRunners(unittest.TestCase):
    def test_pnpm_dlx_unpinned_caught(self):
        self.assertTrue(detect_unpinned("pnpm", ["dlx", "grab@latest"]))

    def test_yarn_dlx_unpinned_caught(self):
        self.assertTrue(detect_unpinned("yarn", ["dlx", "grab"]))

    def test_bunx_unpinned_caught(self):
        self.assertTrue(detect_unpinned("bunx", ["grab-mcp"]))

    def test_pnpm_dlx_pinned_clean(self):
        self.assertEqual(detect_unpinned("pnpm", ["dlx", "grab@1.2.3"]), [])


if __name__ == "__main__":
    unittest.main()
