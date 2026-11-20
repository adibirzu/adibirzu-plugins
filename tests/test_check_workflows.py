"""Behavior tests for plugins/coding-cicd-hardening/scripts/check_workflows.py.

Every case builds a throwaway tree in a temp directory and runs the linter
the way a user would: over a root path. No network, no repository state.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path

# Importing the plugin scripts must not write __pycache__ into a plugin.
sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parent.parent
LINTER = REPO / "plugins" / "coding-cicd-hardening" / "scripts" / "check_workflows.py"

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SHA_B = "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0"

GOOD_WORKFLOW = f"""\
name: ci
on:
  push:
    branches: [main]
  pull_request:
permissions: {{}}
jobs:
  test:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@{SHA_B} # v7.1.0
        with:
          python-version: "3.12"
      - name: Test
        env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
        run: |
          python3 -m unittest discover -s tests -v
          echo "$TITLE"
"""

# Interpolated into fixtures so this file holds no literal real-host default
# and passes the rule it tests.
REAL_HOST = "acme-prod.io"

GOOD_SKILL = """\
---
name: demo-skill
description: Shows a valid skill. Use when a test needs one.
license: MIT
---

# Demo
"""


def load_linter():
    spec = importlib.util.spec_from_file_location("check_workflows", LINTER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LinterCase(unittest.TestCase):
    def setUp(self) -> None:
        self.linter = load_linter()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def write(self, rel: str, content: str) -> Path:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        return path

    def workflow(self, content: str, name: str = "ci.yml") -> Path:
        return self.write(f".github/workflows/{name}", content)

    def rules(self) -> list[str]:
        return sorted({finding.rule for finding in self.linter.lint_tree(self.root)})

    def findings(self, rule: str) -> list:
        return [f for f in self.linter.lint_tree(self.root) if f.rule == rule]


class WorkflowRulesTest(LinterCase):
    def test_hardened_workflow_is_clean(self) -> None:
        self.workflow(GOOD_WORKFLOW)
        self.assertEqual(self.rules(), [])

    def test_tag_pinned_action_is_flagged_with_its_line(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace(f"actions/setup-python@{SHA_B}", "actions/setup-python@v5"))
        found = self.findings("unpinned-action")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].path, ".github/workflows/ci.yml")
        self.assertEqual(found[0].line, 16)
        self.assertIn("actions/setup-python@v5", found[0].message)

    def test_short_sha_and_branch_refs_are_flagged(self) -> None:
        for ref in (f"actions/checkout@{SHA[:7]}", "actions/checkout@main", "actions/checkout"):
            with self.subTest(ref=ref):
                self.workflow(GOOD_WORKFLOW.replace(f"actions/checkout@{SHA}", ref))
                self.assertIn("unpinned-action", self.rules())

    def test_local_actions_and_digest_pinned_images_are_allowed(self) -> None:
        extra = (
            "      - uses: ./.github/actions/local\n"
            "      - uses: docker://ghcr.io/example/tool@sha256:" + "a" * 64 + "\n"
        )
        self.workflow(GOOD_WORKFLOW + extra)
        self.assertEqual(self.rules(), [])

    def test_quoted_refs_are_read_without_their_quotes(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace(f"actions/setup-python@{SHA_B}", f'"actions/setup-python@{SHA_B}"'))
        self.assertEqual(self.rules(), [])
        self.workflow(GOOD_WORKFLOW.replace(f"actions/setup-python@{SHA_B}", "'actions/setup-python@v5'"))
        found = self.findings("unpinned-action")
        self.assertEqual(len(found), 1)
        self.assertIn("'actions/setup-python@v5' is not pinned", found[0].message)

    def test_tag_pinned_container_image_is_flagged(self) -> None:
        self.workflow(GOOD_WORKFLOW + "      - uses: docker://alpine:3.20\n")
        self.assertEqual(self.rules(), ["unpinned-action"])

    def test_reusable_workflow_refs_must_be_pinned(self) -> None:
        self.workflow(
            GOOD_WORKFLOW
            + "  reuse:\n    permissions:\n      contents: read\n"
            + "    uses: example/shared/.github/workflows/build.yml@v1\n"
        )
        self.assertEqual(self.rules(), ["unpinned-action"])

    def test_missing_top_level_permissions_is_flagged(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace("permissions: {}\n", ""))
        self.assertEqual(self.rules(), ["missing-top-level-permissions"])

    def test_read_all_and_read_only_mapping_are_accepted(self) -> None:
        for block in ("permissions: read-all\n", "permissions:\n  contents: read\n"):
            with self.subTest(block=block):
                self.workflow(GOOD_WORKFLOW.replace("permissions: {}\n", block))
                self.assertEqual(self.rules(), [])

    def test_write_scopes_at_top_level_are_flagged(self) -> None:
        for block in ("permissions: write-all\n", "permissions:\n  contents: write\n"):
            with self.subTest(block=block):
                self.workflow(GOOD_WORKFLOW.replace("permissions: {}\n", block))
                self.assertEqual(self.rules(), ["broad-permissions"])

    def test_job_level_write_all_is_flagged_but_scoped_write_is_not(self) -> None:
        scoped = GOOD_WORKFLOW.replace("      contents: read\n", "      contents: read\n      id-token: write\n")
        self.workflow(scoped)
        self.assertEqual(self.rules(), [])
        self.workflow(GOOD_WORKFLOW.replace("    permissions:\n      contents: read\n", "    permissions: write-all\n"))
        self.assertEqual(self.rules(), ["broad-permissions"])

    def test_pull_request_target_is_flagged_in_every_trigger_form(self) -> None:
        forms = (
            "on:\n  pull_request_target:\n",
            "on: [push, pull_request_target]\n",
            "on: pull_request_target\n",
        )
        for form in forms:
            with self.subTest(form=form):
                self.workflow(GOOD_WORKFLOW.replace("on:\n  push:\n    branches: [main]\n  pull_request:\n", form))
                self.assertEqual(self.rules(), ["pull-request-target"])

    def test_pull_request_target_in_a_comment_is_ignored(self) -> None:
        self.workflow("# never use pull_request_target here\n" + GOOD_WORKFLOW)
        self.assertEqual(self.rules(), [])

    def test_checkout_without_persist_credentials_false_is_flagged(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace("        with:\n          persist-credentials: false\n", "", 1))
        found = self.findings("checkout-persist-credentials")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].line, 13)

    def test_persist_credentials_on_a_later_step_does_not_count(self) -> None:
        text = GOOD_WORKFLOW.replace("        with:\n          persist-credentials: false\n", "", 1)
        text += "      - uses: example/other@" + SHA + "\n        with:\n          persist-credentials: false\n"
        self.workflow(text)
        self.assertEqual(self.rules(), ["checkout-persist-credentials"])

    def test_untrusted_context_inside_run_is_flagged(self) -> None:
        for expr in (
            "github.event.pull_request.title",
            "github.event.issue.body",
            "github.head_ref",
            "github.event.comment.body",
        ):
            with self.subTest(expr=expr):
                self.workflow(GOOD_WORKFLOW.replace('echo "$TITLE"', 'echo "${{ ' + expr + ' }}"'))
                self.assertEqual(self.rules(), ["script-injection"])

    def test_untrusted_context_in_single_line_run_is_flagged(self) -> None:
        self.workflow(GOOD_WORKFLOW + "      - run: echo ${{ github.event.pull_request.head.ref }}\n")
        self.assertEqual(self.rules(), ["script-injection"])

    def test_trusted_context_inside_run_is_allowed(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace('echo "$TITLE"', 'echo "${{ github.sha }} ${{ runner.os }}"'))
        self.assertEqual(self.rules(), [])

    def test_static_cloud_credentials_are_flagged(self) -> None:
        for line in (
            "          credentials_json: ${{ secrets.GCP_SA_KEY }}",
            "          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}",
            "          creds: ${{ secrets.AZURE_CREDENTIALS }}",
        ):
            with self.subTest(line=line.strip()):
                self.workflow(GOOD_WORKFLOW + f"      - uses: example/cloud-login@{SHA}\n        with:\n{line}\n")
                self.assertEqual(self.rules(), ["static-cloud-credential"])

    def test_every_workflow_file_is_checked(self) -> None:
        self.workflow(GOOD_WORKFLOW)
        self.workflow(GOOD_WORKFLOW.replace(f"@{SHA_B}", "@v5"), name="release.yaml")
        found = self.findings("unpinned-action")
        self.assertEqual([f.path for f in found], [".github/workflows/release.yaml"])

    def test_tree_without_workflows_has_no_workflow_findings(self) -> None:
        self.write("README.md", "# empty\n")
        self.assertEqual(self.rules(), [])


class SkillRulesTest(LinterCase):
    def skill(self, content: str, folder: str = "demo-skill") -> Path:
        return self.write(f"plugins/demo/skills/{folder}/SKILL.md", content)

    def test_valid_skill_is_clean(self) -> None:
        self.skill(GOOD_SKILL)
        self.assertEqual(self.rules(), [])

    def test_missing_frontmatter_is_flagged(self) -> None:
        self.skill("# Demo\n")
        self.assertEqual(self.rules(), ["skill-frontmatter"])

    def test_name_must_be_kebab_case(self) -> None:
        self.skill(GOOD_SKILL.replace("name: demo-skill", "name: Demo Skill"))
        found = self.findings("skill-frontmatter")
        self.assertEqual(len(found), 1)
        self.assertIn("Demo Skill", found[0].message)

    def test_name_must_match_directory(self) -> None:
        self.skill(GOOD_SKILL, folder="other-name")
        self.assertEqual(self.rules(), ["skill-frontmatter"])

    def test_description_is_required_and_bounded(self) -> None:
        self.skill(GOOD_SKILL.replace("description: Shows a valid skill. Use when a test needs one.\n", ""))
        self.assertEqual(self.rules(), ["skill-frontmatter"])
        self.skill(GOOD_SKILL.replace("Shows a valid skill.", "x" * 1100))
        self.assertEqual(self.rules(), ["skill-frontmatter"])

    def test_folded_description_is_read(self) -> None:
        self.skill("---\nname: demo-skill\ndescription: >\n  Shows a valid skill.\n  Use when a test needs one.\n---\n")
        self.assertEqual(self.rules(), [])

    def test_vendored_directories_are_skipped(self) -> None:
        self.write("node_modules/pkg/skills/bad/SKILL.md", "# no frontmatter\n")
        self.assertEqual(self.rules(), [])


class TestIsolationRulesTest(LinterCase):
    def test_env_default_pointing_at_a_real_host_is_flagged(self) -> None:
        cases = {
            "tests/test_api.py": f'BASE = os.environ.get("API_URL", "https://api.{REAL_HOST}/v1")\n',
            "tests/test_env.py": f'BASE = os.getenv("API_URL", "https://app.{REAL_HOST}")\n',
            "web/checkout.spec.ts": f'const base = process.env.BASE_URL || "https://shop.{REAL_HOST}";\n',
            "web/cart.test.js": f"const base = process.env.BASE_URL ?? 'https://shop.{REAL_HOST}';\n",
        }
        for rel, content in cases.items():
            with self.subTest(file=rel):
                path = self.write(rel, content)
                self.assertEqual(self.rules(), ["prod-url-default"])
                path.unlink()

    def test_local_and_reserved_hosts_are_allowed(self) -> None:
        self.write(
            "tests/test_api.py",
            """\
            A = os.environ.get("API_URL", "http://127.0.0.1:8000")
            B = os.getenv("API_URL", "http://localhost:3000/api")
            C = os.environ.get("API_URL", "https://service.example.com")
            D = os.environ.get("API_URL", "https://api.test")
            E = os.environ["API_URL"]
            """,
        )
        self.assertEqual(self.rules(), [])

    def test_non_test_files_are_not_checked(self) -> None:
        self.write("src/config.py", f'BASE = os.environ.get("API_URL", "https://api.{REAL_HOST}")\n')
        self.assertEqual(self.rules(), [])


class CommandLineTest(LinterCase):
    def run_cli(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.linter.main([*args])
        return code, out.getvalue()

    def test_clean_tree_exits_zero(self) -> None:
        self.workflow(GOOD_WORKFLOW)
        code, out = self.run_cli(str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("0 findings", out)

    def test_findings_exit_one_and_print_file_line_rule(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace(f"@{SHA_B}", "@v5"))
        code, out = self.run_cli(str(self.root))
        self.assertEqual(code, 1)
        self.assertIn(".github/workflows/ci.yml:16: unpinned-action", out)

    def test_json_output_is_machine_readable(self) -> None:
        self.workflow(GOOD_WORKFLOW.replace(f"@{SHA_B}", "@v5"))
        code, out = self.run_cli(str(self.root), "--format", "json")
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["findings"][0]["rule"], "unpinned-action")
        self.assertEqual(payload["findings"][0]["line"], 16)

    def test_missing_root_exits_two(self) -> None:
        code, _ = self.run_cli(str(self.root / "nope"))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
