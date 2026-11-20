#!/usr/bin/env python3
"""Lint GitHub Actions workflows, agent skills and test isolation.

Standard library only, so it runs in any CI job before dependencies install.

    python3 check_workflows.py [ROOT] [--format text|json]

Exit status: 0 clean, 1 findings, 2 usage error.

Rules
  unpinned-action                action or reusable workflow not pinned to a
                                 full 40-character commit SHA
  unpinned-image                 job, service or step container image not
                                 pinned to a sha256 digest
  missing-top-level-permissions  workflow has no top-level permissions key
  broad-permissions              write-all anywhere, or a write scope granted
                                 to every job from the top level
  pull-request-target            the trigger that runs with secrets on fork code
  checkout-persist-credentials   actions/checkout leaves the token in .git/config
  script-injection               attacker-controlled context expanded in a
                                 run step or a github-script input
  static-cloud-credential        long-lived cloud key where OIDC is available
  unparsed-construct             YAML this reader cannot follow, so the checks
                                 above could not be applied to it
  skill-frontmatter              SKILL.md breaks the Agent Skills frontmatter spec
  prod-url-default               a test falls back to a real host when its
                                 environment variable is unset

Workflows are read with a small block-style YAML reader that tracks the key
path of every value, so each rule looks only where GitHub looks: triggers
under `on`, actions under a step's `uses`, inputs under that step's `with`.
It reads quoted keys, block scalars and one-line flow collections. It does
not read anchors, aliases, tags, merge keys or flow collections that span
lines. Those are reported as unparsed-construct instead of passing silently.
"""

from __future__ import annotations

import argparse
import ast
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

QUOTE_CHARS = frozenset({chr(34), chr(39)})  # double and single quote
FULL_SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
KEY_LINE = re.compile(
    r"^(?P<key>\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'|[^\s\"'\[\]{}#&*!|>%@`,?-][^:#]*?|-[^\s:][^:#]*?)"
    r"\s*:(?:\s+(?P<value>.*))?$"
)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
BRACKET_ACCESS = re.compile(r"\[[\"']([^\"'\]]+)[\"']\]")
UNTRUSTED_CONTEXT = re.compile(
    r"(?<![\w.])(github\.head_ref"
    r"|github\.event[\w.*]*?[._](body|title|ref|label|message|name|email|default_branch|page_name))"
    r"(?![\w])"
)
CREDENTIAL_ENV = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "ARM_CLIENT_SECRET",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_CREDENTIALS",
}
# Inputs that carry a long-lived key on any action, then inputs that only
# mean that on one specific login action.
CREDENTIAL_INPUTS = {"credentials_json", "aws-access-key-id", "aws-secret-access-key"}
CREDENTIAL_INPUTS_BY_ACTION = {"azure/login": {"creds"}}
SKILL_NAME = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
JS_ENV_DEFAULT = re.compile(
    r"process\.env(?:\.\w+|\[[\"']\w+[\"']\])\s*(?:\|\||\?\?)\s*[\"'`](https?://[^\"'`]+)[\"'`]"
)
PY_ENV_DEFAULT = re.compile(
    r"(?:environ\.get|getenv)\(\s*[\"'][^\"']+[\"']\s*,\s*[\"'](https?://[^\"']+)[\"']"
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


@dataclass(frozen=True)
class Node:
    """One value in a workflow, addressed by its key path.

    Sequence items appear in the path as "[0]", "[1]" and so on. ``value`` is
    the decoded scalar, or None when the value is a nested collection.
    ``lines`` holds the physical lines of a scalar with their line numbers.
    """

    path: tuple[str, ...]
    value: str | None
    line: int
    lines: tuple[tuple[int, str], ...] = ()


@dataclass
class Frame:
    indent: int
    path: tuple[str, ...]
    is_open: bool = True
    is_item: bool = False
    count: int = 0


def strip_comment(text: str) -> str:
    """Drop a YAML comment, leaving hashes inside quotes alone."""
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in QUOTE_CHARS:
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    return text


def strip_quotes(value: str) -> str:
    """Remove one pair of matching quotes around a YAML scalar."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTE_CHARS:
        return value[1:-1]
    return value


def flow_depth(text: str) -> int:
    """Count brackets left open by a line, ignoring quoted text."""
    depth, quote = 0, ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
        elif char in QUOTE_CHARS:
            quote = char
        elif char in "{[":
            depth += 1
        elif char in "}]":
            depth -= 1
    return depth


def parse_flow(text: str):
    """Parse a one-line flow collection into dicts, lists and strings."""
    position = 0

    def skip_space() -> None:
        nonlocal position
        while position < len(text) and text[position].isspace():
            position += 1

    def scalar(stops: str) -> str:
        nonlocal position
        skip_space()
        start = position
        if position < len(text) and text[position] in QUOTE_CHARS:
            quote = text[position]
            position += 1
            while position < len(text) and text[position] != quote:
                position += 1
            if position >= len(text):
                raise ValueError("unterminated quoted scalar")
            position += 1
            return text[start + 1 : position - 1]
        while position < len(text) and text[position] not in stops:
            if text[position] in "{[":
                raise ValueError("unexpected collection inside a scalar")
            position += 1
        return text[start:position].strip()

    def value(stops: str):
        skip_space()
        if position >= len(text):
            raise ValueError("unexpected end of flow collection")
        if text[position] == "{":
            return mapping()
        if text[position] == "[":
            return sequence()
        return scalar(stops)

    def mapping() -> dict:
        nonlocal position
        position += 1
        result: dict = {}
        while True:
            skip_space()
            if position >= len(text):
                raise ValueError("flow mapping is not closed on this line")
            if text[position] == "}":
                position += 1
                return result
            key = scalar(":,}")
            skip_space()
            if position < len(text) and text[position] == ":":
                position += 1
                result[key] = value(",}")
            else:
                result[key] = ""
            skip_space()
            if position < len(text) and text[position] == ",":
                position += 1

    def sequence() -> list:
        nonlocal position
        position += 1
        result: list = []
        while True:
            skip_space()
            if position >= len(text):
                raise ValueError("flow sequence is not closed on this line")
            if text[position] == "]":
                position += 1
                return result
            result.append(value(",]"))
            skip_space()
            if position < len(text) and text[position] == ",":
                position += 1

    parsed = value("")
    skip_space()
    if position != len(text):
        raise ValueError("trailing text after flow collection")
    return parsed


def parse_workflow(text: str) -> tuple[list[Node], list[tuple[int, str]]]:
    """Read block-style YAML into path-addressed nodes.

    Returns the nodes and a list of (line, reason) for constructs it could
    not follow.
    """
    nodes: list[Node] = []
    problems: list[tuple[int, str]] = []
    stack = [Frame(indent=-1, path=())]
    lines = text.splitlines()
    last_scalar: tuple[int, int] | None = None  # (index in nodes, key indent)
    index = 0

    def flatten(data, path: tuple[str, ...], number: int) -> None:
        if isinstance(data, dict):
            nodes.append(Node(path, None, number))
            for key, item in data.items():
                flatten(item, path + (key,), number)
        elif isinstance(data, list):
            nodes.append(Node(path, None, number))
            for position, item in enumerate(data):
                flatten(item, path + (f"[{position}]",), number)
        else:
            nodes.append(Node(path, str(data), number, ((number, str(data)),)))

    def emit(path: tuple[str, ...], value: str, number: int, key_indent: int) -> None:
        nonlocal index, last_scalar
        last_scalar = None
        if value[0] in "|>":
            block = []
            while index < len(lines):
                line = lines[index]
                if line.strip() and len(line) - len(line.lstrip(" ")) <= key_indent:
                    break
                block.append((index + 1, line))
                index += 1
            body = "\n".join(item for _, item in block)
            nodes.append(Node(path, body, number, tuple(block)))
        elif value[0] in "&*!":
            problems.append((number, "anchors, aliases and tags are not followed"))
            nodes.append(Node(path, None, number))
        elif value[0] in "{[":
            depth = flow_depth(value)
            if depth > 0:
                # Spans lines. Skip to where it closes and report it once.
                while depth > 0 and index < len(lines):
                    depth += flow_depth(strip_comment(lines[index]))
                    index += 1
                problems.append((number, "flow collection spans several lines"))
                nodes.append(Node(path, None, number))
                return
            try:
                flatten(parse_flow(value), path, number)
            except ValueError as error:
                problems.append((number, f"flow collection not read: {error}"))
                nodes.append(Node(path, None, number))
        else:
            nodes.append(Node(path, strip_quotes(value), number, ((number, value),)))
            last_scalar = (len(nodes) - 1, key_indent)

    while index < len(lines):
        raw = lines[index]
        number = index + 1
        index += 1
        if not raw.strip():
            continue
        lead = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in lead:
            problems.append((number, "tab indentation is not valid YAML"))
            continue
        indent = len(lead)
        body = strip_comment(raw[indent:]).rstrip()
        if not body or (indent == 0 and body in {"---", "..."}):
            continue

        dashed = False
        while body == "-" or body.startswith("- "):
            dashed = True
            while len(stack) > 1 and (
                stack[-1].indent > indent
                or (stack[-1].indent == indent and (stack[-1].is_item or not stack[-1].is_open))
            ):
                stack.pop()
            parent = stack[-1]
            item_path = parent.path + (f"[{parent.count}]",)
            parent.count += 1
            stack.append(Frame(indent=indent, path=item_path, is_item=True))
            rest = body[1:]
            indent += 1 + len(rest) - len(rest.lstrip())
            body = rest.lstrip()
        if not body:
            nodes.append(Node(stack[-1].path, None, number))
            continue

        if body.startswith("? ") or body.startswith("<<"):
            problems.append((number, "complex keys and merge keys are not followed"))
            continue

        match = KEY_LINE.match(body)
        if not match:
            top = stack[-1]
            if dashed:
                emit(top.path, body, number, indent)
            elif body[0] in "{[" and top.is_open and not top.is_item and indent > top.indent:
                # A flow collection written on the line after its key.
                top.is_open = False
                emit(top.path, body, number, top.indent)
            elif last_scalar and indent > last_scalar[1]:
                previous = nodes[last_scalar[0]]
                nodes[last_scalar[0]] = Node(
                    previous.path,
                    f"{previous.value} {body}",
                    previous.line,
                    previous.lines + ((number, body),),
                )
            else:
                problems.append((number, "line is not a key, a list item or a scalar continuation"))
            continue

        key = strip_quotes(match.group("key"))
        value = (match.group("value") or "").strip()
        while len(stack) > 1 and stack[-1].indent >= indent:
            stack.pop()
        path = stack[-1].path + (key,)
        if value:
            stack.append(Frame(indent=indent, path=path, is_open=False))
            emit(path, value, number, indent)
        else:
            stack.append(Frame(indent=indent, path=path))
            nodes.append(Node(path, None, number))
            last_scalar = None

    return nodes, problems


def is_step_key(path: tuple[str, ...], key: str) -> bool:
    return len(path) == 5 and path[0] == "jobs" and path[2] == "steps" and path[4] == key


def is_action_ref(path: tuple[str, ...]) -> bool:
    """True for a step's `uses` and for a job that calls a reusable workflow."""
    return is_step_key(path, "uses") or (len(path) == 3 and path[0] == "jobs" and path[2] == "uses")


def is_image_ref(path: tuple[str, ...]) -> bool:
    """True for a job container and for a service image."""
    if len(path) < 3 or path[0] != "jobs":
        return False
    return (
        path[2:] == ("container",)
        or path[2:] == ("container", "image")
        or (len(path) == 5 and path[2] == "services" and path[4] == "image")
    )


def injected_lines(node: Node) -> list[int]:
    """Line numbers where an untrusted context is expanded inside a scalar."""
    text = "\n".join(item for _, item in node.lines)
    hits = []
    for match in EXPRESSION.finditer(text):
        # Drop whitespace and escape characters, then read ['key'] as .key
        compact = "".join(match.group(1).split()).replace(chr(92), "")
        expression = BRACKET_ACCESS.sub(r".\1", compact)
        if UNTRUSTED_CONTEXT.search(expression):
            offset = text.count("\n", 0, match.start())
            hits.append(node.lines[offset][0] if node.lines else node.line)
    return hits


def lint_workflow(text: str, path: str) -> list[Finding]:
    nodes, problems = parse_workflow(text)
    findings: list[Finding] = []

    def add(rule: str, line: int, message: str) -> None:
        findings.append(Finding(path, line, rule, message))

    for line, reason in problems:
        add("unparsed-construct", line, f"{reason}, so this part was not checked")

    if not any(node.path == ("permissions",) for node in nodes):
        add(
            "missing-top-level-permissions",
            1,
            "add a top-level 'permissions: {}' and grant scopes per job",
        )

    step_action: dict[tuple[str, ...], str] = {}
    step_inputs: dict[tuple[str, ...], dict[str, str]] = {}
    for node in nodes:
        if is_step_key(node.path, "uses") and node.value:
            step_action[node.path[:4]] = node.value
        if len(node.path) == 6 and node.path[0] == "jobs" and node.path[4] == "with":
            step_inputs.setdefault(node.path[:4], {})[node.path[5]] = node.value or ""

    for node in nodes:
        where, value = node.path, node.value

        if where == ("permissions",) and value == "write-all":
            add("broad-permissions", node.line, "write-all grants every scope to every job")
        elif len(where) == 2 and where[0] == "permissions" and value == "write":
            add(
                "broad-permissions",
                node.line,
                f"top-level '{where[1]}: write' reaches every job, grant it on the job that needs it",
            )
        elif len(where) == 3 and where[0] == "jobs" and where[2] == "permissions" and value == "write-all":
            add("broad-permissions", node.line, "write-all grants every scope, list the ones needed")

        if where[:1] == ("on",) and (
            (len(where) == 2 and where[1] == "pull_request_target")
            or (len(where) <= 2 and value == "pull_request_target")
        ):
            add(
                "pull-request-target",
                node.line,
                "pull_request_target runs fork code with repository secrets",
            )

        if is_action_ref(where) and value:
            if value.startswith("docker://"):
                if not IMAGE_DIGEST.search(value):
                    add("unpinned-image", node.line, f"'{value}' is not pinned to a sha256 digest")
            elif not value.startswith("./") and not FULL_SHA_REF.match(value):
                add(
                    "unpinned-action",
                    node.line,
                    f"'{value}' is not pinned to a 40-character commit SHA",
                )
            if re.match(r"^actions/checkout(@|$)", value, re.I):
                persisted = step_inputs.get(where[:4], {}).get("persist-credentials", "")
                if persisted.lower() != "false":
                    add(
                        "checkout-persist-credentials",
                        node.line,
                        "set 'persist-credentials: false' under this step's 'with'",
                    )

        if is_image_ref(where) and value and "${{" not in value and not IMAGE_DIGEST.search(value):
            add("unpinned-image", node.line, f"'{value}' is not pinned to a sha256 digest")

        is_sink = is_step_key(where, "run") or (
            len(where) == 6 and where[0] == "jobs" and where[4:] == ("with", "script")
        )
        if is_sink and value:
            for line in injected_lines(node):
                add(
                    "script-injection",
                    line,
                    "untrusted context expanded inside a script, pass it through env",
                )

        if len(where) >= 2 and where[-2] == "env" and where[-1] in CREDENTIAL_ENV and value:
            add(
                "static-cloud-credential",
                node.line,
                f"{where[-1]} is a long-lived cloud key, use OIDC workload identity federation",
            )
        if len(where) == 6 and where[0] == "jobs" and where[4] == "with" and value:
            action = step_action.get(where[:4], "").split("@")[0].lower()
            scoped = CREDENTIAL_INPUTS_BY_ACTION.get(action, set())
            if where[5] in CREDENTIAL_INPUTS or where[5] in scoped:
                add(
                    "static-cloud-credential",
                    node.line,
                    f"'{where[5]}' passes a long-lived cloud credential, use OIDC workload identity federation",
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


def real_host(url: str) -> str | None:
    """Return the host when a URL names a real service, else None."""
    host = re.sub(r"^https?://", "", url).split("/")[0].rsplit("@", 1)[-1]
    if not host.startswith("["):
        host = host.split(":")[0]
    if re.search(r"[{}$<>%]", host) or SAFE_HOST.match(host.lower()):
        return None
    return host


def python_env_defaults(text: str) -> list[tuple[int, str]]:
    """Find (line, url) for environment lookups that fall back to a URL."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [
            (text.count("\n", 0, match.start(1)) + 1, match.group(1))
            for match in PY_ENV_DEFAULT.finditer(text)
        ]

    def is_lookup(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        name = ast.unparse(node.func)
        return name == "getenv" or name.endswith((".getenv", "environ.get"))

    def urls(node: ast.AST | None) -> list[tuple[int, str]]:
        is_text = isinstance(node, ast.Constant) and isinstance(node.value, str)
        if is_text and node.value.startswith(("http://", "https://")):
            return [(node.lineno, node.value)]
        return []

    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if is_lookup(node):
            default = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "default":
                    default = keyword.value
            found.extend(urls(default))
        elif (
            isinstance(node, ast.BoolOp)
            and isinstance(node.op, ast.Or)
            and any(is_lookup(value) for value in node.values[:-1])
        ):
            for value in node.values[1:]:
                found.extend(urls(value))
    return found


def lint_test_file(text: str, path: str) -> list[Finding]:
    if path.endswith(".py"):
        candidates = python_env_defaults(text)
    else:
        candidates = [
            (text.count("\n", 0, match.start(1)) + 1, match.group(1))
            for match in JS_ENV_DEFAULT.finditer(text)
        ]
    findings = []
    for line, url in candidates:
        host = real_host(url)
        if host:
            findings.append(
                Finding(
                    path,
                    line,
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
