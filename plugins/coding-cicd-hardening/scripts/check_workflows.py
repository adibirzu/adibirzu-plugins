#!/usr/bin/env python3
"""Lint GitHub Actions workflows, agent skills and test isolation.

Standard library only, so it runs in any CI job before dependencies install.

    python3 check_workflows.py [ROOT] [--format text|json]

Exit status: 0 clean, 1 findings, 2 usage error.

Rules
  unpinned-action                action, reusable workflow or image not pinned
                                 to a full commit SHA or sha256 digest
  missing-top-level-permissions  workflow has no top-level permissions key
  broad-permissions              write-all anywhere, or a write scope granted
                                 to every job from the top level
  pull-request-target            the trigger that runs with secrets on fork code
  checkout-persist-credentials   actions/checkout leaves the token in .git/config
  script-injection               attacker-controlled context expanded in run
  static-cloud-credential        long-lived cloud key where OIDC is available
  skill-frontmatter              SKILL.md breaks the Agent Skills frontmatter spec
  prod-url-default               a test falls back to a real host when its
                                 environment variable is unset

The workflow checks read YAML line by line. They cover the block style that
GitHub documents and that formatters emit. Flow-style steps on one line are
not understood, so keep workflows in block style.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
    "venv",
}
TEST_DIRS = {"tests", "test", "__tests__", "e2e"}
TEST_SUFFIXES = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

FULL_SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
IMAGE_DIGEST_REF = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
USES = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?uses:\s*(?P<ref>\S+)")
RUN = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?run:\s*(?P<value>.*)$")
TOP_PERMISSIONS = re.compile(r"^permissions:\s*(?P<value>.*)$")
ANY_WRITE_ALL = re.compile(r"^\s+permissions:\s*write-all\s*$")
PERSIST_FALSE = re.compile(r"^\s*persist-credentials:\s*['\"]?false['\"]?\s*$")
STATIC_CREDENTIAL = re.compile(
    r"^\s*(credentials_json|aws-access-key-id|aws-secret-access-key|creds|client-secret)\s*:"
)
UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{[^}]*\b("
    r"github\.head_ref"
    r"|github\.event\.[\w.\[\]*]*\b"
    r"(body|title|ref|label|message|name|email|default_branch|page_name)"
    r")\b[^}]*\}\}"
)
QUOTE_CHARS = frozenset({chr(34), chr(39)})  # double and single quote
SKILL_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
PY_ENV_DEFAULT = re.compile(
    r"(?:environ\.get|getenv)\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'](https?://[^\"']+)[\"']"
)
JS_ENV_DEFAULT = re.compile(
    r"process\.env(?:\.\w+|\[[\"']\w+[\"']\])\s*(?:\|\||\?\?)\s*[\"'`](https?://[^\"'`]+)[\"'`]"
)
SAFE_HOST = re.compile(
    r"^(localhost|127(\.\d+){3}|0\.0\.0\.0|\[::1\]|host\.docker\.internal"
    r"|([\w-]+\.)*(localhost|test|example|invalid|local)"
    r"|([\w-]+\.)*example\.(com|org|net))$"
)


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.rule} {self.message}"


def strip_comment(line: str) -> str:
    """Drop a YAML comment. A hash only starts one at line start or after space."""
    match = re.search(r"(^|\s)#", line)
    return line[: match.start()] if match else line


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def strip_quotes(value: str) -> str:
    """Remove one pair of matching quotes around a YAML scalar."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTE_CHARS:
        return value[1:-1]
    return value


def step_block(code: list[str], index: int, key_indent: int, has_dash: bool) -> list[str]:
    """Return the lines of the step that owns the key at ``index``."""
    start, dash_indent = index, key_indent
    if not has_dash:
        for back in range(index - 1, -1, -1):
            line = code[back]
            if line.strip().startswith("- ") and indent_of(line) < key_indent:
                start, dash_indent = back, indent_of(line)
                break
    end = len(code)
    for forward in range(index + 1, len(code)):
        line = code[forward]
        if line.strip() and indent_of(line) <= dash_indent:
            end = forward
            break
    return code[start:end]


def lint_workflow(text: str, path: str) -> list[Finding]:
    raw = text.splitlines()
    code = [strip_comment(line) for line in raw]
    findings: list[Finding] = []

    def add(rule: str, line: int, message: str) -> None:
        findings.append(Finding(path, line, rule, message))

    top = [(i, TOP_PERMISSIONS.match(line)) for i, line in enumerate(code)]
    top = [(i, match) for i, match in top if match]
    if not top:
        add(
            "missing-top-level-permissions",
            1,
            "add a top-level 'permissions: {}' and grant scopes per job",
        )
    for index, match in top:
        value = match.group("value").strip()
        granted = [value]
        for line in code[index + 1 :]:
            if line.strip() and indent_of(line) == 0:
                break
            granted.append(line.split(":", 1)[-1].strip())
        if any(re.search(r"\bwrite(-all)?\b", item) for item in granted):
            add(
                "broad-permissions",
                index + 1,
                "top-level permissions grant write to every job, scope them per job",
            )

    run_indent = None
    for index, line in enumerate(code):
        number = index + 1

        if run_indent is not None:
            if not line.strip() or indent_of(raw[index]) > run_indent:
                if UNTRUSTED_CONTEXT.search(raw[index]):
                    add(
                        "script-injection",
                        number,
                        "untrusted context expanded inside run, pass it through env",
                    )
                continue
            run_indent = None

        if ANY_WRITE_ALL.match(line):
            add("broad-permissions", number, "write-all grants every scope, list the ones needed")

        if "pull_request_target" in line:
            add(
                "pull-request-target",
                number,
                "pull_request_target runs fork code with repository secrets",
            )

        if STATIC_CREDENTIAL.match(line):
            add(
                "static-cloud-credential",
                number,
                "long-lived cloud credential, use OIDC workload identity federation",
            )

        uses = USES.match(line)
        if uses:
            ref = strip_quotes(uses.group("ref"))
            pinned = (
                ref.startswith("./")
                or FULL_SHA_REF.match(ref)
                or IMAGE_DIGEST_REF.match(ref)
            )
            if not pinned:
                add(
                    "unpinned-action",
                    number,
                    f"'{ref}' is not pinned to a 40-character commit SHA or sha256 digest",
                )
            if re.match(r"^actions/checkout(@|$)", ref):
                key_indent = len(uses.group("indent")) + len(uses.group("dash") or "")
                dash_indent = len(uses.group("indent"))
                block = step_block(
                    code,
                    index,
                    key_indent if not uses.group("dash") else dash_indent,
                    bool(uses.group("dash")),
                )
                if not any(PERSIST_FALSE.match(item) for item in block):
                    add(
                        "checkout-persist-credentials",
                        number,
                        "set 'persist-credentials: false' on actions/checkout",
                    )

        run = RUN.match(line)
        if run:
            value = run.group("value").strip()
            if value[:1] in {"|", ">"}:
                run_indent = len(run.group("indent")) + len(run.group("dash") or "")
            elif UNTRUSTED_CONTEXT.search(raw[index]):
                add(
                    "script-injection",
                    number,
                    "untrusted context expanded inside run, pass it through env",
                )

    return findings


def parse_frontmatter(text: str) -> dict[str, str] | None:
    """Read top-level scalar keys from YAML frontmatter. None when absent."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    fields: dict[str, str] = {}
    key = None
    for line in lines[1:]:
        if line.strip() == "---":
            return fields
        match = re.match(r"^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip()
            fields[key] = "" if re.fullmatch(r"[>|][+-]?", value) else strip_quotes(value)
        elif key and line.startswith((" ", "\t")):
            fields[key] = (fields[key] + " " + line.strip()).strip()
    return None


def lint_skill(text: str, path: str) -> list[Finding]:
    fields = parse_frontmatter(text)
    if fields is None:
        return [Finding(path, 1, "skill-frontmatter", "missing '---' delimited YAML frontmatter")]
    problems = []
    name = fields.get("name", "")
    folder = Path(path).parent.name
    if not SKILL_NAME.match(name) or len(name) > 64:
        problems.append(f"name '{name}' must be lowercase letters, digits and hyphens, 64 max")
    elif name != folder:
        problems.append(f"name '{name}' must match its directory '{folder}'")
    description = fields.get("description", "")
    if not description:
        problems.append("description is required")
    elif len(description) > 1024:
        problems.append(f"description is {len(description)} characters, 1024 max")
    return [Finding(path, 1, "skill-frontmatter", problem) for problem in problems]


def is_test_file(relative: Path) -> bool:
    if relative.suffix not in TEST_SUFFIXES:
        return False
    name = relative.name
    if name.startswith("test_") or name == "conftest.py" or name.endswith("_test.py"):
        return True
    if re.search(r"\.(test|spec)\.[cm]?[jt]sx?$", name):
        return True
    return bool(TEST_DIRS.intersection(relative.parts[:-1]))


def lint_test_file(text: str, path: str) -> list[Finding]:
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern in (PY_ENV_DEFAULT, JS_ENV_DEFAULT):
            for match in pattern.finditer(line):
                host = re.sub(r"^https?://", "", match.group(1)).split("/")[0]
                host = host.rsplit("@", 1)[-1]
                if not host.startswith("["):
                    host = host.split(":")[0]
                if re.search(r"[{}$<>%]", host) or SAFE_HOST.match(host.lower()):
                    continue
                findings.append(
                    Finding(
                        path,
                        number,
                        "prod-url-default",
                        f"test defaults to '{host}' when its variable is unset, "
                        "default to a local or reserved host and require an opt-in",
                    )
                )
    return findings


def lint_tree(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = Path(current) / name
            relative = path.relative_to(root)
            posix = relative.as_posix()
            in_workflows = relative.parts[:2] == (".github", "workflows")
            if in_workflows and len(relative.parts) == 3 and path.suffix in {".yml", ".yaml"}:
                check = lint_workflow
            elif name == "SKILL.md":
                check = lint_skill
            elif is_test_file(relative):
                check = lint_test_file
            else:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            findings.extend(check(text, posix))
    return sorted(findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lint GitHub Actions workflows, agent skills and test isolation."
    )
    parser.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    findings = lint_tree(root)
    if args.format == "json":
        print(json.dumps({"count": len(findings), "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        for finding in findings:
            print(finding.render())
        print(f"{len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
