#!/usr/bin/env python3
"""Scan every local plugin with SkillSpector and record the verdicts.

    python3 .github/ci/record_scan_status.py

Writes .github/skill-scan/status.json. Each entry is pinned to a digest of
the plugin directory, so the tests fail when a plugin changes and its scan
was not rerun. Run this after any change under plugins/, then copy the
verdicts into the "Plugin scan status" table in README.md.

Needs the `skillspector` command on PATH. It is not run in CI.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess  # nosec B404 - runs one fixed local command with no shell
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
STATUS = REPO / ".github" / "skill-scan" / "status.json"
GENERATOR = REPO / "plugins" / "coding-cicd-hardening" / "scripts" / "generate_sbom.py"


def load_generator():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("generate_sbom", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def scan(scanner: str, folder: Path, report: Path) -> dict:
    command = [scanner, "scan", str(folder), "--no-llm", "--recursive", "--format", "json", "--output", str(report)]
    subprocess.run(command, check=False, capture_output=True)  # noqa: S603  # nosec B603
    return json.loads(report.read_text(encoding="utf-8"))


def main() -> int:
    scanner = shutil.which("skillspector")
    if not scanner:
        print("error: skillspector is not on PATH", file=sys.stderr)
        return 2
    version = subprocess.run([scanner, "--version"], check=False, capture_output=True, text=True)  # noqa: S603  # nosec B603
    generator = load_generator()
    catalog = json.loads((REPO / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    plugins = {}
    with tempfile.TemporaryDirectory() as scratch:
        for entry in catalog["plugins"]:
            if not isinstance(entry["source"], str):
                continue
            folder = (REPO / entry["source"]).resolve()
            report = scan(scanner, folder, Path(scratch) / f"{entry['name']}.json")
            plugins[entry["name"]] = {
                "verdict": report["risk_assessment"]["recommendation"],
                "score": report["risk_assessment"]["score"],
                "findings": len(report["issues"]),
                "coverage": "complete" if report["analysis_completeness"]["is_complete"] else "partial",
                "tree_sha256": generator.tree_digest(folder),
            }
            print(f"{entry['name']}: {plugins[entry['name']]['verdict']}")
    status = {
        "scanner": "SkillSpector",
        "scanner_version": version.stdout.strip().split()[-1].lstrip("v"),
        "mode": "--no-llm --recursive, whole plugin bundle",
        "scanned": date.today().isoformat(),
        "plugins": plugins,
    }
    STATUS.parent.mkdir(parents=True, exist_ok=True)
    STATUS.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {STATUS.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
