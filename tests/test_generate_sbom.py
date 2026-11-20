"""Behavior tests for plugins/coding-cicd-hardening/scripts/generate_sbom.py.

The generator inventories a plugin marketplace: every listed plugin plus
every GitHub Action its workflows pin. It writes CycloneDX and SPDX JSON.
Schema validation against the official validators runs in CI (sbom.yml).
These tests cover shape, content and determinism with the standard library.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Importing the plugin scripts must not write __pycache__ into a plugin.
sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parent.parent
GENERATOR = REPO / "plugins" / "coding-cicd-hardening" / "scripts" / "generate_sbom.py"

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"

MARKETPLACE = {
    "name": "demo-market",
    "owner": {"name": "demo"},
    "plugins": [
        {
            "name": "remote-one",
            "description": "A remote plugin.",
            "version": "2.1.0",
            "source": {"source": "url", "url": "https://github.com/demo/remote-one.git"},
        },
        {
            "name": "local-one",
            "description": "A local plugin.",
            "version": "1.0.0",
            "source": "./plugins/local-one",
        },
    ],
}

WORKFLOW = f"""\
name: ci
on: [push]
permissions: {{}}
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@{SHA} # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/checkout@{SHA} # v7.0.1
        with:
          persist-credentials: false
      - uses: ./.github/actions/local
"""


def load_generator():
    spec = importlib.util.spec_from_file_location("generate_sbom", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GeneratorCase(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = load_generator()
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        self.out = Path(self._tmp.name) / "out"
        self.addCleanup(self._tmp.cleanup)
        self.write(".claude-plugin/marketplace.json", json.dumps(MARKETPLACE))
        self.write(
            "plugins/local-one/.claude-plugin/plugin.json",
            json.dumps({"name": "local-one", "version": "1.0.0", "license": "MIT"}),
        )
        self.write("plugins/local-one/skills/a/SKILL.md", "---\nname: a\ndescription: A.\n---\n")
        self.write(".github/workflows/ci.yml", WORKFLOW)
        env = mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1795132800"})
        env.start()
        self.addCleanup(env.stop)

    def write(self, rel: str, content: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def generate(self, *extra: str) -> tuple[dict, dict]:
        code = self.generator.main([str(self.root), "--output-dir", str(self.out), *extra])
        self.assertEqual(code, 0)
        cdx = json.loads((self.out / "marketplace.cdx.json").read_text(encoding="utf-8"))
        spdx = json.loads((self.out / "marketplace.spdx.json").read_text(encoding="utf-8"))
        return cdx, spdx


class CycloneDxTest(GeneratorCase):
    def test_document_header_is_cyclonedx_1_7(self) -> None:
        cdx, _ = self.generate("--spec-version", "1.7")
        self.assertEqual(cdx["bomFormat"], "CycloneDX")
        self.assertEqual(cdx["specVersion"], "1.7")
        self.assertEqual(cdx["$schema"], "http://cyclonedx.org/schema/bom-1.7.schema.json")
        self.assertRegex(cdx["serialNumber"], r"^urn:uuid:[0-9a-f-]{36}$")
        self.assertEqual(cdx["metadata"]["timestamp"], "2026-11-20T00:00:00Z")
        self.assertEqual(cdx["metadata"]["component"]["name"], "demo-market")

    def test_default_spec_version_is_1_7(self) -> None:
        cdx, _ = self.generate()
        self.assertEqual(cdx["specVersion"], "1.7")

    def test_plugins_and_pinned_actions_become_components(self) -> None:
        cdx, _ = self.generate()
        by_name = {c["name"]: c for c in cdx["components"]}
        self.assertEqual(sorted(by_name), ["actions/checkout", "local-one", "remote-one"])
        self.assertEqual(by_name["remote-one"]["version"], "2.1.0")
        self.assertEqual(by_name["remote-one"]["purl"], "pkg:github/demo/remote-one@2.1.0")
        self.assertEqual(by_name["actions/checkout"]["version"], SHA)
        self.assertEqual(by_name["actions/checkout"]["purl"], f"pkg:github/actions/checkout@{SHA}")
        self.assertEqual(by_name["local-one"]["licenses"], [{"license": {"id": "MIT"}}])
        refs = [c["bom-ref"] for c in cdx["components"]]
        self.assertEqual(len(refs), len(set(refs)))

    def test_remote_plugin_records_its_source_repository(self) -> None:
        cdx, _ = self.generate()
        remote = next(c for c in cdx["components"] if c["name"] == "remote-one")
        self.assertIn(
            {"type": "vcs", "url": "https://github.com/demo/remote-one.git"},
            remote["externalReferences"],
        )

    def test_local_plugin_tree_digest_tracks_content(self) -> None:
        def digest() -> str:
            cdx, _ = self.generate()
            local = next(c for c in cdx["components"] if c["name"] == "local-one")
            props = {p["name"]: p["value"] for p in local["properties"]}
            return props["marketplace:tree-sha256"]

        first = digest()
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, digest())
        self.write("plugins/local-one/skills/a/SKILL.md", "---\nname: a\ndescription: Changed.\n---\n")
        self.assertNotEqual(first, digest())

    def test_root_depends_on_every_component(self) -> None:
        cdx, _ = self.generate()
        root_ref = cdx["metadata"]["component"]["bom-ref"]
        deps = {d["ref"]: d["dependsOn"] for d in cdx["dependencies"]}
        self.assertEqual(sorted(deps[root_ref]), sorted(c["bom-ref"] for c in cdx["components"]))


class SourceShapesTest(GeneratorCase):
    """Every plugin source form Claude Code documents keeps its identity."""

    SHA_B = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
    DIGEST = "6bfa50e3d2e00c052b46abe51fff89346ac803e45771f76dcf6df1ab74cca5e1"

    def catalog(self, *plugins: dict) -> tuple[dict, dict]:
        self.write(".claude-plugin/marketplace.json", json.dumps({"name": "demo-market", "plugins": list(plugins)}))
        cdx, spdx = self.generate()
        return (
            {c["name"]: c for c in cdx["components"] if c["bom-ref"].startswith("plugin:")},
            {p["name"]: p for p in spdx["packages"]},
        )

    def test_github_source_uses_the_pinned_commit(self) -> None:
        source = {"source": "github", "repo": "Example/Plugins", "ref": "v2.0.0", "sha": self.SHA_B}
        cdx, spdx = self.catalog({"name": "demo", "version": "2.0.0", "source": source})
        self.assertEqual(cdx["demo"]["purl"], f"pkg:github/example/plugins@{self.SHA_B}")
        self.assertIn({"type": "vcs", "url": "https://github.com/Example/Plugins"}, cdx["demo"]["externalReferences"])
        self.assertEqual(spdx["demo"]["downloadLocation"], f"git+https://github.com/Example/Plugins@{self.SHA_B}")

    def test_github_source_without_a_commit_falls_back_to_ref_then_version(self) -> None:
        cdx, _ = self.catalog(
            {"name": "by-ref", "version": "1.0.0", "source": {"source": "github", "repo": "a/b", "ref": "main"}},
            {"name": "by-version", "version": "1.0.0", "source": {"source": "github", "repo": "a/c"}},
            {"name": "bare", "source": {"source": "github", "repo": "a/d"}},
        )
        self.assertEqual(cdx["by-ref"]["purl"], "pkg:github/a/b@main")
        self.assertEqual(cdx["by-version"]["purl"], "pkg:github/a/c@1.0.0")
        self.assertEqual(cdx["bare"]["purl"], "pkg:github/a/d")
        self.assertNotIn("version", cdx["bare"])

    def test_git_subdir_source_keeps_its_path(self) -> None:
        source = {"source": "git-subdir", "url": "your-org/monorepo", "path": "tools/formatter", "sha": self.SHA_B}
        cdx, spdx = self.catalog({"name": "formatter", "version": "1.2.0", "source": source})
        self.assertEqual(cdx["formatter"]["purl"], f"pkg:github/your-org/monorepo@{self.SHA_B}#tools/formatter")
        self.assertEqual(
            spdx["formatter"]["downloadLocation"],
            f"git+https://github.com/your-org/monorepo@{self.SHA_B}#tools/formatter",
        )

    def test_npm_source_becomes_an_npm_purl(self) -> None:
        source = {"source": "npm", "package": "@your-org/formatter", "version": "2.0.0"}
        cdx, _ = self.catalog({"name": "formatter", "source": source})
        self.assertEqual(cdx["formatter"]["purl"], "pkg:npm/%40your-org/formatter@2.0.0")

    def test_archive_source_records_url_and_checksum(self) -> None:
        source = {"source": "archive", "url": "https://artifacts.example.com/f-2.0.0.zip", "sha256": self.DIGEST}
        cdx, spdx = self.catalog({"name": "formatter", "version": "2.0.0", "source": source})
        self.assertEqual(cdx["formatter"]["hashes"], [{"alg": "SHA-256", "content": self.DIGEST}])
        self.assertIn(
            {"type": "distribution", "url": "https://artifacts.example.com/f-2.0.0.zip"},
            cdx["formatter"]["externalReferences"],
        )
        self.assertEqual(spdx["formatter"]["downloadLocation"], "https://artifacts.example.com/f-2.0.0.zip")
        self.assertEqual(spdx["formatter"]["checksums"], [{"algorithm": "SHA256", "checksumValue": self.DIGEST}])

    def test_unknown_source_forms_are_listed_without_invented_identity(self) -> None:
        cdx, spdx = self.catalog(
            {"name": "by-command", "source": {"source": "command", "command": "my-tool plugin-path"}},
            {"name": "ssh-git", "version": "1.0.0", "source": {"source": "url", "url": "git@example.com:a/b.git"}},
        )
        self.assertNotIn("purl", cdx["by-command"])
        self.assertEqual(spdx["by-command"]["downloadLocation"], "NOASSERTION")
        self.assertNotIn("externalReferences", cdx["ssh-git"])
        kinds = {p["name"]: p["value"] for p in cdx["by-command"]["properties"]}
        self.assertEqual(kinds["marketplace:source"], "command")

    def test_local_plugin_version_comes_from_its_own_manifest(self) -> None:
        cdx, spdx = self.catalog({"name": "local-one", "source": "./plugins/local-one"})
        self.assertEqual(cdx["local-one"]["version"], "1.0.0")
        self.assertEqual(cdx["local-one"]["purl"], "pkg:generic/local-one@1.0.0")
        self.assertEqual(spdx["local-one"]["versionInfo"], "1.0.0")

    def test_local_source_outside_the_repository_is_not_read(self) -> None:
        outside = self.root.parent / "elsewhere"
        outside.mkdir()
        (outside / "secret.txt").write_text("not ours", encoding="utf-8")
        cdx, _ = self.catalog({"name": "escape", "version": "1.0.0", "source": "../elsewhere"})
        names = {p["name"] for p in cdx["escape"]["properties"]}
        self.assertNotIn("marketplace:tree-sha256", names)
        self.assertIn("marketplace:source-outside-root", names)


class WorkflowInventoryTest(GeneratorCase):
    def components(self, workflow: str) -> tuple[list[dict], list[dict]]:
        self.write(".github/workflows/ci.yml", workflow)
        cdx, spdx = self.generate()
        return cdx["components"], spdx["packages"]

    def test_job_service_and_step_images_are_listed(self) -> None:
        digest = "sha256:" + "c" * 64
        workflow = WORKFLOW.replace(
            "    steps:\n",
            f"    container: node:24\n    services:\n      db:\n        image: ghcr.io/example/pg@{digest}\n    steps:\n",
        ) + "      - uses: docker://alpine:3.20\n"
        components, _ = self.components(workflow)
        images = {c["name"]: c for c in components if c["type"] == "container"}
        self.assertEqual(sorted(images), ["alpine", "ghcr.io/example/pg", "node"])
        self.assertEqual(images["node"]["version"], "24")
        self.assertEqual(images["alpine"]["version"], "3.20")
        self.assertEqual(images["ghcr.io/example/pg"]["version"], digest)

    def test_text_that_only_looks_like_an_action_is_not_listed(self) -> None:
        workflow = WORKFLOW + "      - name: |\n          uses: example/fake@v1\n        run: echo ok\n"
        components, _ = self.components(workflow)
        self.assertNotIn("example/fake", {c["name"] for c in components})

    def test_similar_action_names_get_distinct_identifiers(self) -> None:
        workflow = WORKFLOW + f"      - uses: example/tool/batch@{SHA}\n      - uses: example/tool-batch@{SHA}\n"
        components, packages = self.components(workflow)
        ids = [p["SPDXID"] for p in packages]
        self.assertEqual(len(ids), len(set(ids)))
        refs = [c["bom-ref"] for c in components]
        self.assertEqual(len(refs), len(set(refs)))


class SpdxTest(GeneratorCase):
    def test_document_header_is_spdx_2_3(self) -> None:
        _, spdx = self.generate()
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(spdx["dataLicense"], "CC0-1.0")
        self.assertEqual(spdx["SPDXID"], "SPDXRef-DOCUMENT")
        self.assertEqual(spdx["creationInfo"]["created"], "2026-11-20T00:00:00Z")
        self.assertTrue(spdx["documentNamespace"].startswith("https://"))

    def test_packages_mirror_the_cyclonedx_components(self) -> None:
        cdx, spdx = self.generate()
        packages = {p["name"]: p for p in spdx["packages"]}
        self.assertEqual(
            sorted(packages), sorted([c["name"] for c in cdx["components"]] + ["demo-market"])
        )
        remote = packages["remote-one"]
        self.assertEqual(remote["versionInfo"], "2.1.0")
        self.assertEqual(remote["downloadLocation"], "git+https://github.com/demo/remote-one.git")
        self.assertFalse(remote["filesAnalyzed"])
        self.assertEqual(packages["local-one"]["licenseDeclared"], "MIT")
        self.assertEqual(remote["licenseDeclared"], "NOASSERTION")
        for package in spdx["packages"]:
            self.assertRegex(package["SPDXID"], r"^SPDXRef-[A-Za-z0-9.-]+$")

    def test_document_describes_root_and_root_depends_on_packages(self) -> None:
        _, spdx = self.generate()
        kinds = [(r["spdxElementId"], r["relationshipType"]) for r in spdx["relationships"]]
        self.assertIn(("SPDXRef-DOCUMENT", "DESCRIBES"), kinds)
        depends = [r for r in spdx["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
        self.assertEqual(len(depends), len(spdx["packages"]) - 1)


class DeterminismAndCliTest(GeneratorCase):
    def test_same_input_gives_byte_identical_output(self) -> None:
        self.generate()
        first = [(self.out / n).read_bytes() for n in ("marketplace.cdx.json", "marketplace.spdx.json")]
        self.generate()
        second = [(self.out / n).read_bytes() for n in ("marketplace.cdx.json", "marketplace.spdx.json")]
        self.assertEqual(first, second)

    def test_unsupported_spec_version_is_rejected(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.generator.main([str(self.root), "--output-dir", str(self.out), "--spec-version", "1.2"])
        self.assertEqual(caught.exception.code, 2)

    def test_missing_marketplace_exits_two(self) -> None:
        (self.root / ".claude-plugin" / "marketplace.json").unlink()
        self.assertEqual(self.generator.main([str(self.root), "--output-dir", str(self.out)]), 2)

    def test_real_marketplace_inventory_matches_catalog(self) -> None:
        code = self.generator.main([str(REPO), "--output-dir", str(self.out)])
        self.assertEqual(code, 0)
        cdx = json.loads((self.out / "marketplace.cdx.json").read_text(encoding="utf-8"))
        catalog = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        names = {c["name"] for c in cdx["components"]}
        for plugin in catalog["plugins"]:
            self.assertIn(plugin["name"], names)
        self.assertIn("actions/checkout", names)


if __name__ == "__main__":
    unittest.main()
