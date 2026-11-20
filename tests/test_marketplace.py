"""Invariants for the adibirzu-plugins marketplace.

Run offline with the standard library only:

    python3 -m unittest discover -s tests -v

Nothing here opens a network connection. Remote plugin sources are checked
for shape only. Their upstream manifests are verified by the audit procedure
in CONTRIBUTING.md.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import unittest
from pathlib import Path

# Importing the plugin scripts must not write __pycache__ into a plugin.
sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parent.parent
MARKETPLACE = REPO / ".claude-plugin" / "marketplace.json"
README = REPO / "README.md"
WORKFLOWS = REPO / ".github" / "workflows"
LINTER = REPO / "plugins" / "coding-cicd-hardening" / "scripts" / "check_workflows.py"

SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
KEBAB = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FULL_SHA_USE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
README_ROW = re.compile(
    r"^\| \[(?P<name>[a-z0-9-]+)\]\((?P<link>[^)]+)\) \| (?P<desc>.+) \| (?P<version>\S+) \|$"
)

# Built at runtime so this file passes its own hygiene checks.
EM_DASH = chr(0x2014)
BANNED_WORD = "cap" + "tain"

# Content this change set does not own. src/aetherops is frozen pending the
# owner decision recorded in SECURITY.md. The bodies of the two older plugins
# stay untouched. Their manifests are still checked.
HYGIENE_EXEMPT = (
    "src/",
    "plugins/just-do-it/skills/",
    "plugins/multillm/agents/",
    "plugins/multillm/commands/",
    "plugins/multillm/hooks/",
    "plugins/multillm/skills/",
    "plugins/multillm/AGENTS.md",
)
SKIP_DIRS = {".git", ".ruff_cache", ".venv", "__pycache__", "graphify-out", "node_modules", "sbom"}
SKIP_FILES = {".DS_Store", "firebase-debug.log"}
TEXT_SUFFIXES = {".md", ".json", ".yml", ".yaml", ".py", ".txt", ".in", ".toml", ".sh"}
TEXT_NAMES = {"LICENSE", ".gitignore"}

SECRET_PATTERNS = {
    "aws access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "github fine-grained token": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    "slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "google api key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "anthropic or openai key": re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{32,}\b"),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "service account json": re.compile(r'"private_key"\s*:\s*"-----BEGIN'),
}

NEW_PLUGINS = {
    "poteto-workflow": {
        "version": "1.0.0",
        "files": (
            "skills/poteto-workflow/SKILL.md",
            "skills/poteto-workflow/worker.md",
            "skills/poteto-workflow/references/crew-gates.md",
        ),
    },
    "coding-cicd-hardening": {
        "version": "1.0.0",
        "files": (
            "skills/secure-coding-cicd/SKILL.md",
            "skills/secure-coding-cicd/references/cicd-security-checklist.md",
            "skills/secure-coding-cicd/references/sbom-and-supply-chain.md",
            "scripts/check_workflows.py",
            "scripts/generate_sbom.py",
        ),
    },
}


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def marketplace_plugins() -> list[dict]:
    return load_json(MARKETPLACE)["plugins"]


def local_plugins() -> list[tuple[dict, Path]]:
    found = []
    for plugin in marketplace_plugins():
        if isinstance(plugin["source"], str):
            found.append((plugin, (REPO / plugin["source"]).resolve()))
    return found


def owned_text_files() -> list[Path]:
    files = []
    for current, dirs, names in os.walk(REPO):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = Path(current) / name
            rel = path.relative_to(REPO).as_posix()
            if name in SKIP_FILES or (path.suffix not in TEXT_SUFFIXES and name not in TEXT_NAMES):
                continue
            if any(rel == item or rel.startswith(item) for item in HYGIENE_EXEMPT):
                continue
            files.append(path)
    return files


def skill_files() -> list[Path]:
    return sorted(
        path
        for path in (REPO / "plugins").rglob("SKILL.md")
        if not SKIP_DIRS.intersection(path.parts)
    )


def frontmatter(path: Path) -> dict[str, str]:
    lines = read(path).splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    fields: dict[str, str] = {}
    key = None
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip()
            fields[key] = "" if value in {">", "|", ">-", "|-"} else value.strip("\"'")
        elif key and line.startswith((" ", "\t")):
            fields[key] = (fields[key] + " " + line.strip()).strip()
    return {}


def workflow_files() -> list[Path]:
    if not WORKFLOWS.is_dir():
        return []
    return sorted(p for p in WORKFLOWS.iterdir() if p.suffix in {".yml", ".yaml"})


def uses_refs(path: Path) -> list[str]:
    refs = []
    for line in read(path).splitlines():
        match = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
        if match:
            refs.append(match.group(1).strip("\"'"))
    return refs


class MarketplaceSchemaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data = load_json(MARKETPLACE)

    def test_top_level_fields(self) -> None:
        self.assertEqual(self.data["name"], "adibirzu-plugins")
        self.assertTrue(self.data["description"].strip())
        self.assertEqual(self.data["owner"]["name"], "adibirzu")
        self.assertIsInstance(self.data["plugins"], list)
        self.assertGreaterEqual(len(self.data["plugins"]), 7)

    def test_every_plugin_entry_is_well_formed(self) -> None:
        for plugin in self.data["plugins"]:
            with self.subTest(plugin=plugin.get("name")):
                self.assertRegex(plugin["name"], KEBAB)
                self.assertRegex(plugin["version"], SEMVER)
                self.assertTrue(plugin["description"].strip())
                self.assertLessEqual(len(plugin["description"]), 400)
                self.assertTrue(plugin["author"]["name"].strip())
                self.assertIn(
                    plugin["category"], {"development", "security", "devops", "productivity"}
                )
                self.assertTrue(plugin["homepage"].startswith("https://github.com/adibirzu/"))

    def test_plugin_names_are_unique(self) -> None:
        names = [plugin["name"] for plugin in self.data["plugins"]]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_catalog(self) -> None:
        versions = {plugin["name"]: plugin["version"] for plugin in self.data["plugins"]}
        self.assertEqual(versions.get("rlm"), "4.0.0")
        self.assertEqual(versions.get("poteto-workflow"), "1.0.0")
        self.assertEqual(versions.get("coding-cicd-hardening"), "1.0.0")
        for kept in ("prod-ready", "multillm", "oci-administrator", "just-do-it"):
            self.assertIn(kept, versions)


class SourceResolutionTest(unittest.TestCase):
    def test_local_sources_resolve_inside_the_repo(self) -> None:
        self.assertGreaterEqual(len(local_plugins()), 4)
        for plugin, root in local_plugins():
            with self.subTest(plugin=plugin["name"]):
                self.assertTrue(plugin["source"].startswith("./plugins/"))
                self.assertIn(REPO, root.parents)
                self.assertTrue(root.is_dir(), f"{root} is not a directory")
                self.assertEqual(root.name, plugin["name"])
                self.assertTrue((root / ".claude-plugin" / "plugin.json").is_file())

    def test_remote_sources_are_owner_https_git_urls(self) -> None:
        pattern = re.compile(r"^https://github\.com/adibirzu/[A-Za-z0-9._-]+\.git$")
        remote = [p for p in marketplace_plugins() if not isinstance(p["source"], str)]
        self.assertGreaterEqual(len(remote), 3)
        for plugin in remote:
            with self.subTest(plugin=plugin["name"]):
                self.assertEqual(plugin["source"]["source"], "url")
                self.assertRegex(plugin["source"]["url"], pattern)

    def test_new_plugins_ship_their_files(self) -> None:
        for name, spec in NEW_PLUGINS.items():
            root = REPO / "plugins" / name
            for rel in spec["files"]:
                with self.subTest(plugin=name, file=rel):
                    self.assertTrue((root / rel).is_file(), f"missing {root / rel}")


class VersionParityTest(unittest.TestCase):
    def test_marketplace_matches_local_manifests(self) -> None:
        for plugin, root in local_plugins():
            for kind in (".claude-plugin", ".codex-plugin"):
                manifest = root / kind / "plugin.json"
                if kind == ".codex-plugin" and not manifest.is_file():
                    continue
                with self.subTest(plugin=plugin["name"], manifest=kind):
                    data = load_json(manifest)
                    self.assertEqual(data["name"], plugin["name"])
                    self.assertEqual(data["version"], plugin["version"])

    def test_new_plugins_have_both_manifests_at_expected_version(self) -> None:
        for name, spec in NEW_PLUGINS.items():
            for kind in (".claude-plugin", ".codex-plugin"):
                with self.subTest(plugin=name, manifest=kind):
                    data = load_json(REPO / "plugins" / name / kind / "plugin.json")
                    self.assertEqual(data["name"], name)
                    self.assertEqual(data["version"], spec["version"])
                    self.assertEqual(data["license"], "MIT")

    def test_readme_table_matches_marketplace(self) -> None:
        rows = {}
        for line in read(README).splitlines():
            match = README_ROW.match(line.strip())
            if match:
                rows[match.group("name")] = match.group("version")
        expected = {plugin["name"]: plugin["version"] for plugin in marketplace_plugins()}
        self.assertEqual(rows, expected)

    def test_readme_lists_an_install_command_per_plugin(self) -> None:
        text = read(README)
        for plugin in marketplace_plugins():
            with self.subTest(plugin=plugin["name"]):
                self.assertIn(f"/plugin install {plugin['name']}@adibirzu-plugins", text)

    def test_readme_documents_rlm_version_sync(self) -> None:
        text = read(README)
        self.assertIn("## Version sync", text)
        section = text.split("## Version sync", 1)[1].split("\n## ", 1)[0]
        self.assertIn("adibirzu/rlm-plugin", section)
        self.assertIn("4.0.0", section)


class SkillFrontmatterTest(unittest.TestCase):
    def test_every_local_skill_follows_agentskills_frontmatter(self) -> None:
        skills = skill_files()
        self.assertGreaterEqual(len(skills), 5)
        for path in skills:
            with self.subTest(skill=path.relative_to(REPO).as_posix()):
                fields = frontmatter(path)
                self.assertRegex(fields.get("name", ""), KEBAB)
                self.assertLessEqual(len(fields["name"]), 64)
                self.assertEqual(fields["name"], path.parent.name)
                self.assertTrue(fields.get("description", "").strip())
                self.assertLessEqual(len(fields["description"]), 1024)

    def test_new_skills_declare_a_license(self) -> None:
        for rel in (
            "plugins/poteto-workflow/skills/poteto-workflow/SKILL.md",
            "plugins/coding-cicd-hardening/skills/secure-coding-cicd/SKILL.md",
        ):
            with self.subTest(skill=rel):
                self.assertEqual(frontmatter(REPO / rel).get("license"), "MIT")


class PotetoWorkflowContentTest(unittest.TestCase):
    ROOT = REPO / "plugins" / "poteto-workflow" / "skills" / "poteto-workflow"

    def test_skill_names_the_four_stages_in_order(self) -> None:
        text = read(self.ROOT / "SKILL.md").lower()
        positions = [text.find(stage) for stage in ("interrogate", "arena", "swarm", "show-me-your-work")]
        self.assertNotIn(-1, positions)
        self.assertEqual(positions, sorted(positions))

    def test_crew_gates_reference_covers_every_gate(self) -> None:
        text = read(self.ROOT / "references" / "crew-gates.md").lower()
        for needle in (
            "failing test",
            "cross-family",
            "gitleaks protect --staged",
            "gitleaks detect",
            "full project suite",
            "merge",
            "deploy",
            "force-push",
            "co-author",
            "model tier",
        ):
            with self.subTest(gate=needle):
                self.assertIn(needle, text)

    def test_worker_contract_is_short_and_carries_the_gates(self) -> None:
        text = read(self.ROOT / "worker.md")
        self.assertLessEqual(len(text.splitlines()), 40)
        for needle in ("failing test", "gitleaks", "cross-family", "merge"):
            with self.subTest(gate=needle):
                self.assertIn(needle, text.lower())

    def test_skill_documents_optional_integrations_without_bundling(self) -> None:
        text = read(self.ROOT / "SKILL.md").lower()
        self.assertIn("orca-harness-poteto", text)
        self.assertIn("pstack", text)
        self.assertIn("not bundled", text)


class SecureCodingContentTest(unittest.TestCase):
    ROOT = REPO / "plugins" / "coding-cicd-hardening" / "skills" / "secure-coding-cicd"

    def test_checklist_covers_the_baseline_controls(self) -> None:
        text = read(self.ROOT / "references" / "cicd-security-checklist.md").lower()
        for needle in (
            "40-character commit sha",
            "oidc",
            "permissions: {}",
            "persist-credentials: false",
            "pull_request_target",
            "gitleaks",
            "ruff",
            "bandit",
            "semgrep",
            "dependency review",
            "dependabot",
            "production url",
            "skillspector",
            "readme",
        ):
            with self.subTest(control=needle):
                self.assertIn(needle, text)

    def test_sbom_reference_names_both_formats(self) -> None:
        text = read(self.ROOT / "references" / "sbom-and-supply-chain.md")
        for needle in ("CycloneDX 1.7", "SPDX 2.3", "--spec-version 1.7", "attest"):
            with self.subTest(topic=needle):
                self.assertIn(needle, text)


class WorkflowHardeningTest(unittest.TestCase):
    def test_required_workflows_exist(self) -> None:
        names = {path.name for path in workflow_files()}
        self.assertLessEqual({"ci.yml", "sbom.yml"}, names)

    def test_every_action_is_pinned_to_a_full_commit_sha(self) -> None:
        seen = 0
        for path in workflow_files():
            for ref in uses_refs(path):
                seen += 1
                with self.subTest(workflow=path.name, uses=ref):
                    self.assertRegex(ref, FULL_SHA_USE)
        self.assertGreaterEqual(seen, 4)

    def test_top_level_permissions_are_least_privilege(self) -> None:
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                lines = read(path).splitlines()
                top = [line for line in lines if re.match(r"^permissions:", line)]
                self.assertEqual(len(top), 1, "exactly one top-level permissions key")
                self.assertIn(
                    top[0].split(":", 1)[1].strip(), {"{}", "read-all"}
                )
                self.assertNotIn("write-all", read(path))

    def test_no_pull_request_target_trigger(self) -> None:
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                code = "\n".join(
                    line.split("#", 1)[0] for line in read(path).splitlines()
                )
                self.assertNotIn("pull_request_target", code)

    def test_checkout_never_persists_credentials(self) -> None:
        for path in workflow_files():
            text = read(path)
            with self.subTest(workflow=path.name):
                self.assertEqual(
                    text.count("actions/checkout@"),
                    text.count("persist-credentials: false"),
                )

    def test_ci_runs_tests_linter_and_secret_scan(self) -> None:
        text = read(WORKFLOWS / "ci.yml")
        self.assertIn("python3 -m unittest discover -s tests -v", text)
        self.assertIn("plugins/coding-cicd-hardening/scripts/check_workflows.py .", text)
        self.assertIn("gitleaks", text)
        self.assertIn("sha256sum", text)

    def test_sbom_workflow_emits_and_validates_both_formats(self) -> None:
        text = read(WORKFLOWS / "sbom.yml")
        self.assertIn("--spec-version 1.7", text)
        self.assertIn("SPDX-2.3", text)
        self.assertIn("actions/upload-artifact@", text)
        for trigger in ("push:", "pull_request:", "release:"):
            with self.subTest(trigger=trigger):
                self.assertIn(trigger, text)

    def test_ci_tool_requirements_are_hash_pinned(self) -> None:
        text = read(REPO / ".github" / "ci" / "requirements.txt")
        self.assertIn("--hash=sha256:", text)
        for path in workflow_files():
            for line in read(path).splitlines():
                if "pip install" in line:
                    with self.subTest(workflow=path.name, line=line.strip()):
                        self.assertIn("--require-hashes", line)

    def test_repo_passes_its_own_linter(self) -> None:
        spec = importlib.util.spec_from_file_location("check_workflows", LINTER)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        findings = module.lint_tree(REPO)
        self.assertEqual([finding.render() for finding in findings], [])


class RepositoryBaselineTest(unittest.TestCase):
    def test_dependabot_groups_pip_and_actions(self) -> None:
        text = read(REPO / ".github" / "dependabot.yml")
        self.assertIn("version: 2", text)
        self.assertIn('package-ecosystem: "pip"', text)
        self.assertIn('package-ecosystem: "github-actions"', text)
        self.assertEqual(text.count("groups:"), 2)

    def test_security_policy_reports_privately_and_flags_frozen_tree(self) -> None:
        text = read(REPO / "SECURITY.md")
        self.assertIn("security/advisories/new", text)
        self.assertIn("src/aetherops", text)

    def test_contributing_carries_the_pr_checklist(self) -> None:
        text = read(REPO / "CONTRIBUTING.md")
        for needle in (
            "- [ ]",
            "gitleaks protect --staged",
            "skillspector",
            "check_workflows.py",
            "python3 -m unittest discover -s tests -v",
            "README.md",
            "Current Marketplace Architecture",
        ):
            with self.subTest(item=needle):
                self.assertIn(needle, text)

    def test_readme_documents_the_architecture(self) -> None:
        text = read(README)
        self.assertIn("## Current Marketplace Architecture", text)
        section = text.split("## Current Marketplace Architecture", 1)[1].split("\n## ", 1)[0]
        self.assertIn("```mermaid", section)
        self.assertIn("Trust boundaries", section)
        self.assertIn("Living-doc rule", section)

    def test_new_plugins_carry_their_own_mit_license(self) -> None:
        for name in NEW_PLUGINS:
            with self.subTest(plugin=name):
                self.assertIn("MIT License", read(REPO / "plugins" / name / "LICENSE"))

    def test_readme_excludes_frozen_tree_from_the_license(self) -> None:
        section = read(README).split("## License", 1)[1]
        self.assertIn("src/aetherops", section)
        self.assertIn("no license is granted", section.lower())

    def test_plugins_ship_no_python_bytecode(self) -> None:
        # Bytecode is unreviewable and skill scanners block it. Loading the
        # plugin scripts from these tests must not leave any behind either.
        spec = importlib.util.spec_from_file_location("check_workflows_probe", LINTER)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        stray = sorted(
            path.relative_to(REPO).as_posix()
            for path in (REPO / "plugins").rglob("*")
            if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
        )
        self.assertEqual(stray, [])

    def test_gitignore_blocks_bytecode_and_debug_logs(self) -> None:
        lines = set(read(REPO / ".gitignore").split())
        self.assertLessEqual({"__pycache__/", "*.pyc", "firebase-debug.log", "sbom/"}, lines)


class HygieneTest(unittest.TestCase):
    def test_owned_files_exist(self) -> None:
        self.assertGreaterEqual(len(owned_text_files()), 20)

    def test_no_em_dash_in_owned_files(self) -> None:
        escaped = "\\u" + "2014"
        for path in owned_text_files():
            text = read(path)
            with self.subTest(file=path.relative_to(REPO).as_posix()):
                self.assertNotIn(EM_DASH, text)
                self.assertNotIn(escaped, text)

    def test_no_banned_word_in_owned_files(self) -> None:
        for path in owned_text_files():
            with self.subTest(file=path.relative_to(REPO).as_posix()):
                self.assertNotIn(BANNED_WORD, read(path).lower())

    def test_no_static_secret_literals_in_owned_files(self) -> None:
        for path in owned_text_files():
            text = read(path)
            for label, pattern in SECRET_PATTERNS.items():
                with self.subTest(file=path.relative_to(REPO).as_posix(), kind=label):
                    self.assertIsNone(pattern.search(text))

    def test_no_private_network_details_in_owned_files(self) -> None:
        private = re.compile(
            r"\b(100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+"
            r"|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+"
            r"|[a-z0-9-]+\.ts\.net|/Users/[a-z]+)\b"
        )
        for path in owned_text_files():
            with self.subTest(file=path.relative_to(REPO).as_posix()):
                self.assertIsNone(private.search(read(path)))


if __name__ == "__main__":
    unittest.main()
