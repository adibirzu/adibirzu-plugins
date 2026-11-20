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

DOUBLE_QUOTE, SINGLE_QUOTE, BACKSLASH = chr(34), chr(39), chr(92)
QUOTE_CHARS = frozenset({DOUBLE_QUOTE, SINGLE_QUOTE})
BYTE_ORDER_MARK = chr(0xFEFF)
SIMPLE_ESCAPES = {
    "0": chr(0),
    "t": chr(9),
    "n": chr(10),
    "r": chr(13),
    "e": chr(27),
    " ": " ",
    "/": "/",
    DOUBLE_QUOTE: DOUBLE_QUOTE,
    BACKSLASH: BACKSLASH,
}
HEX_ESCAPES = {"x": 2, "u": 4, "U": 8}
# Inside a flow collection a quote opens a quoted scalar only after one of these.
FLOW_SCALAR_STARTS = frozenset({"", ":", ",", "{", "["})
FULL_SHA_REF = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
KEY_LINE = re.compile(
    r"^(?P<key>\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*'|[^\s\"'\[\]{}#&*!|>%@`,?-][^:#]*?|-[^\s:][^:#]*?)"
    r"\s*:(?:\s+(?P<value>.*))?$"
)
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
BRACKET_ACCESS = re.compile(r"\[[\"']([^\"'\]]+)[\"']\]")
INDEX_ACCESS = re.compile(r"\[(\d+|\*)\]")
STRING_LITERAL = re.compile(r"'[^']*'")
MATRIX_VALUE = re.compile(r"^\$\{\{\s*matrix\.([\w-]+)\s*\}\}$")
UNTRUSTED_CONTEXT = re.compile(
    r"(?<![\w.])(github\.head_ref"
    r"|github\.event[\w.*]*?[._]"
    r"(body|title|ref|label|message|name|email|default_branch|head_branch|page_name))"
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
    has_children: bool = False


def quoted_end(text: str) -> int:
    """Index just past the closing quote of a scalar that starts text, or -1."""
    quote, index = text[0], 1
    while index < len(text):
        char = text[index]
        if quote == DOUBLE_QUOTE and char == BACKSLASH:
            index += 2
            continue
        if char == quote:
            if quote == SINGLE_QUOTE and text[index + 1 : index + 2] == SINGLE_QUOTE:
                index += 2
                continue
            return index + 1
        index += 1
    return -1


def strip_value_comment(value: str) -> str:
    """Drop a trailing comment from one value, by the rules of its scalar style."""
    if not value:
        return value
    if value[0] in QUOTE_CHARS:
        # A quoted scalar: only text after its closing quote can be a comment.
        end = quoted_end(value)
        if end < 0:
            return value
        tail = re.search(r"(^|\s)#", value[end:])
        return value[: end + tail.start()] if tail else value
    if value[0] in "{[":
        # A flow collection: quotes delimit scalars inside it.
        quote, previous, index = "", "", 0
        while index < len(value):
            char = value[index]
            if quote:
                if quote == DOUBLE_QUOTE and char == BACKSLASH:
                    index += 2
                    continue
                if char == quote:
                    if quote == SINGLE_QUOTE and value[index + 1 : index + 2] == SINGLE_QUOTE:
                        index += 2
                        continue
                    quote = ""
            elif char in QUOTE_CHARS and previous in FLOW_SCALAR_STARTS:
                quote = char
            elif char == "#" and (index == 0 or value[index - 1].isspace()):
                return value[:index]
            if not char.isspace():
                previous = char
            index += 1
        return value
    # A plain scalar: quotes and brackets are ordinary text, so the first
    # hash after whitespace starts the comment.
    match = re.search(r"(^|\s)#", value)
    return value[: match.start()] if match else value


def strip_comment(text: str) -> str:
    """Drop a YAML comment from one line with its indentation removed.

    The line is split into list dashes, an optional key and a value, because
    whether a quote character is a delimiter depends on where it stands.
    """
    prefix = len(text) - len(re.sub(r"^(-\s+)+", "", text))
    rest = text[prefix:]
    if rest.startswith("#"):
        return text[:prefix]
    match = KEY_LINE.match(rest)
    if match and match.group("value") is not None:
        head, value = rest[: match.start("value")], match.group("value")
    elif match:
        head, value = rest, ""
    else:
        head, value = "", rest
    return text[:prefix] + head + strip_value_comment(value)


def strip_quotes(value: str) -> str:
    """Remove one pair of matching quotes around a scalar, without decoding."""
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in QUOTE_CHARS:
        return value[1:-1]
    return value


def decode_scalar(text: str) -> str:
    """Decode a one-line YAML scalar the way a YAML parser would.

    Raises ValueError for a quoted scalar that does not close on its line or
    uses an escape this reader does not know.
    """
    text = text.strip()
    if not text or text[0] not in QUOTE_CHARS:
        return text
    quote = text[0]
    if len(text) < 2 or text[-1] != quote:
        raise ValueError("quoted scalar does not close on its line")
    inner = text[1:-1]
    if quote == SINGLE_QUOTE:
        return inner.replace(SINGLE_QUOTE * 2, SINGLE_QUOTE)
    decoded, index = [], 0
    while index < len(inner):
        char = inner[index]
        if char != BACKSLASH:
            decoded.append(char)
            index += 1
            continue
        code = inner[index + 1 : index + 2]
        if code in SIMPLE_ESCAPES:
            decoded.append(SIMPLE_ESCAPES[code])
            index += 2
        elif code in HEX_ESCAPES:
            digits = inner[index + 2 : index + 2 + HEX_ESCAPES[code]]
            if len(digits) != HEX_ESCAPES[code] or not all(d in "0123456789abcdefABCDEF" for d in digits):
                raise ValueError("escape sequence is not valid")
            decoded.append(chr(int(digits, 16)))
            index += 2 + len(digits)
        else:
            raise ValueError("escape sequence is not supported")
    return "".join(decoded)


def decode_block(header: str, block: list[tuple[int, str]], indent: int) -> str:
    """Decode a block scalar body: strip its indentation, then keep or fold lines."""
    stripped = [line[indent:] if line.strip() else "" for _, line in block]
    if header[0] == "|":
        return "\n".join(stripped).strip("\n")
    folded, pending = [], []
    for line in stripped:
        if line:
            pending.append(line)
        else:
            if pending:
                folded.append(" ".join(pending))
                pending = []
            folded.append("")
    if pending:
        folded.append(" ".join(pending))
    return "\n".join(folded).strip("\n")


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
        if position >= len(text):
            raise ValueError("unexpected end of flow collection")
        if text[position] in QUOTE_CHARS:
            end = quoted_end(text[start:])
            if end < 0:
                raise ValueError("unterminated quoted scalar")
            position = start + end
            return decode_scalar(text[start:position])
        while position < len(text) and text[position] not in stops:
            if text[position] in "{[":
                raise ValueError("unexpected collection inside a scalar")
            position += 1
        plain = text[start:position].strip()
        if plain[:1] in {"&", "*", "!", "?"} or plain == "<<":
            raise ValueError("anchors, aliases, tags, explicit keys and merge keys are not followed")
        return plain

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
            separator("}")

    def separator(closing: str) -> None:
        """After an entry there must be a comma or the end of the collection."""
        nonlocal position
        skip_space()
        if position < len(text) and text[position] == ",":
            position += 1
        elif position >= len(text) or text[position] != closing:
            raise ValueError("entries are not separated by a comma")

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
            separator("]")

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
    lines = text.lstrip(BYTE_ORDER_MARK).splitlines()
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
            if any(char not in "+-0123456789" for char in value[1:]):
                problems.append((number, "block scalar header is not understood"))
            explicit = next((int(char) for char in value[1:] if char.isdigit()), 0)
            content_indent = key_indent + explicit if explicit else None
            block = []
            while index < len(lines):
                line = lines[index]
                if line.strip():
                    depth = len(line) - len(line.lstrip(" "))
                    if content_indent is None:
                        if depth <= key_indent:
                            break
                        content_indent = depth
                    if depth < content_indent:
                        break
                block.append((index + 1, line))
                index += 1
            while block and not block[-1][1].strip():
                block.pop()
            body = decode_block(value, block, content_indent or 0)
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
            try:
                decoded = decode_scalar(value)
            except ValueError as error:
                problems.append((number, f"scalar not read: {error}"))
                nodes.append(Node(path, None, number))
                return
            nodes.append(Node(path, decoded, number, ((number, decoded),)))
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
            parent.has_children = True
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
            elif top.is_open and not top.is_item and not top.has_children and indent > top.indent:
                # A scalar or flow collection written on the line after its key.
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

        try:
            key = decode_scalar(match.group("key"))
        except ValueError as error:
            problems.append((number, f"key not read: {error}"))
            continue
        value = (match.group("value") or "").strip()
        while len(stack) > 1 and stack[-1].indent >= indent:
            stack.pop()
        stack[-1].has_children = True
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


def is_env_key(path: tuple[str, ...]) -> bool:
    """True for a variable in an env block GitHub actually exports."""
    if len(path) < 2 or path[-2] != "env":
        return False
    owner = path[:-2]
    return (
        owner == ()
        or (len(owner) == 2 and owner[0] == "jobs")
        or (len(owner) == 4 and owner[0] == "jobs" and owner[2] in {"steps", "services"})
        or (len(owner) == 3 and owner[0] == "jobs" and owner[2] == "container")
    )


def image_references(nodes: list[Node]) -> tuple[list[tuple[str, int]], list[tuple[int, str]]]:
    """Every container image a workflow names.

    Returns (image, line) pairs and (line, reason) for references that are
    expressions this reader could not resolve. An image taken from a matrix
    axis resolves to the literal values of that axis.
    """
    images: list[tuple[str, int]] = []
    unresolved: list[tuple[int, str]] = []
    for node in nodes:
        value = node.value
        if not value:
            continue
        if is_action_ref(node.path):
            if value.startswith("docker://"):
                images.append((value, node.line))
            continue
        if not is_image_ref(node.path):
            continue
        if "${{" not in value:
            images.append((value, node.line))
            continue
        axis = MATRIX_VALUE.match(value)
        matrix = node.path[:2] + ("strategy", "matrix")
        # A matrix, an axis or an include list that is itself an expression
        # can add values this reader never sees.
        computed = any(
            other.value
            and "${{" in other.value
            and (other.path == matrix or (axis and other.path in {matrix + (axis.group(1),), matrix + ("include",)}))
            for other in nodes
        )
        literals = [
            (other.value, other.line)
            for other in nodes
            if axis
            and other.value
            and (
                other.path[:-1] == matrix + (axis.group(1),)
                or (other.path[:-2] == matrix + ("include",) and other.path[-1] == axis.group(1))
            )
        ]
        if literals and not computed and all("${{" not in image for image, _ in literals):
            images.extend(literals)
        else:
            unresolved.append((node.line, f"image '{value}' is an expression that could not be resolved"))
    return images, unresolved


def expressions(text: str) -> list[tuple[int, str]]:
    """Find (offset, body) for each GitHub expression in a scalar.

    The closing braces are looked for outside single-quoted strings, the way
    the runner reads them, so a string that contains braces does not end
    the expression early.
    """
    found, cursor = [], 0
    while True:
        start = text.find("${{", cursor)
        if start < 0:
            return found
        index, quoted = start + 3, False
        while index < len(text):
            char = text[index]
            if char == SINGLE_QUOTE:
                quoted = not quoted
            elif not quoted and text.startswith("}}", index):
                break
            index += 1
        found.append((start, text[start + 3 : index]))
        cursor = index + 2


def injected_lines(node: Node) -> list[int]:
    """Line numbers where an untrusted context is expanded inside a scalar."""
    text = "\n".join(item for _, item in node.lines)
    hits = []
    for start, body in expressions(text):
        # GitHub reads names without regard to case, and a['b'], a.b and a[0]
        # are all property access. A quoted string is data, not a reference.
        compact = "".join(body.split()).replace(BACKSLASH, "").lower()
        compact = INDEX_ACCESS.sub(r".\1", BRACKET_ACCESS.sub(r".\1", compact))
        if UNTRUSTED_CONTEXT.search(STRING_LITERAL.sub("''", compact)):
            offset = text.count("\n", 0, start)
            hits.append(node.lines[offset][0] if node.lines else node.line)
    return hits


def lint_workflow(text: str, path: str) -> list[Finding]:
    nodes, problems = parse_workflow(text)
    findings: list[Finding] = []

    def add(rule: str, line: int, message: str) -> None:
        findings.append(Finding(path, line, rule, message))

    images, unresolved = image_references(nodes)
    for line, reason in problems + unresolved:
        add("unparsed-construct", line, f"{reason}, so this part was not checked")
    for image, line in images:
        if not IMAGE_DIGEST.search(image):
            add("unpinned-image", line, f"'{image}' is not pinned to a sha256 digest")

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
            # The runner matches action input names without regard to case.
            step_inputs.setdefault(node.path[:4], {})[node.path[5].lower()] = node.value or ""

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
                pass  # checked with the other images below
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

        is_input = len(where) == 6 and where[0] == "jobs" and where[4] == "with"
        input_name = where[5].lower() if is_input else ""
        is_sink = is_step_key(where, "run") or input_name == "script"
        if is_sink and value:
            for line in injected_lines(node):
                add(
                    "script-injection",
                    line,
                    "untrusted context expanded inside a script, pass it through env",
                )

        if is_env_key(where) and where[-1] in CREDENTIAL_ENV and value:
            add(
                "static-cloud-credential",
                node.line,
                f"{where[-1]} is a long-lived cloud key, use OIDC workload identity federation",
            )
        if is_input and value:
            action = step_action.get(where[:4], "").split("@")[0].lower()
            scoped = CREDENTIAL_INPUTS_BY_ACTION.get(action, set())
            if input_name in CREDENTIAL_INPUTS or input_name in scoped:
                add(
                    "static-cloud-credential",
                    node.line,
                    f"'{where[5]}' passes a long-lived cloud credential, use OIDC workload identity federation",
                )
        if where and where[-1] == "env" and is_env_key(where + ("x",)) and value and "${{" in value:
            add(
                "unparsed-construct",
                node.line,
                "env is built from an expression, so its variable names were not checked",
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
    """Find (line, url) for os environment lookups that fall back to a URL."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [
            (text.count("\n", 0, match.start(1)) + 1, match.group(1))
            for match in PY_ENV_DEFAULT.finditer(text)
        ]

    # Resolve what the file imported, so `env(...)` from `from os import
    # getenv as env` counts and `Config().getenv(...)` does not.
    # The bare name `os` counts even without a visible import.
    modules, getters, environs = {"os"}, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == "os")
        elif isinstance(node, ast.ImportFrom) and node.module == "os" and node.level == 0:
            for alias in node.names:
                if alias.name == "getenv":
                    getters.add(alias.asname or alias.name)
                elif alias.name == "environ":
                    environs.add(alias.asname or alias.name)

    def is_os(node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id in modules

    def is_environ(node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in environs
        return isinstance(node, ast.Attribute) and node.attr == "environ" and is_os(node.value)

    def is_lookup(node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Name):
            return func.id in getters
        if not isinstance(func, ast.Attribute):
            return False
        return (func.attr == "getenv" and is_os(func.value)) or (func.attr == "get" and is_environ(func.value))

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
