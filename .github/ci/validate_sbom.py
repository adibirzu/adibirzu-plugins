#!/usr/bin/env python3
"""Validate generated SBOMs with the official CycloneDX and SPDX libraries.

    python3 validate_sbom.py marketplace.cdx.json marketplace.spdx.json

Needs the hash-pinned tools in .github/ci/requirements.txt. Exit status is 0
when both documents validate and 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

CYCLONEDX_VERSIONS = {"1.6": SchemaVersion.V1_6, "1.7": SchemaVersion.V1_7}
SPDX_VERSION = "SPDX-2.3"


def validate_cyclonedx(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    spec = json.loads(text).get("specVersion")
    if spec not in CYCLONEDX_VERSIONS:
        return [f"unsupported CycloneDX specVersion {spec!r}"]
    error = JsonStrictValidator(CYCLONEDX_VERSIONS[spec]).validate_str(text)
    return [str(error).splitlines()[0]] if error else []


def validate_spdx(path: Path) -> list[str]:
    document = parse_file(str(path))
    if document.creation_info.spdx_version != SPDX_VERSION:
        return [f"expected {SPDX_VERSION}, found {document.creation_info.spdx_version}"]
    return [m.validation_message for m in validate_full_spdx_document(document, SPDX_VERSION)]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    failed = False
    for label, check, name in (
        ("CycloneDX", validate_cyclonedx, argv[0]),
        ("SPDX", validate_spdx, argv[1]),
    ):
        problems = check(Path(name))
        failed = failed or bool(problems)
        print(f"{label}: {name}: {'INVALID' if problems else 'valid'}")
        for problem in problems:
            print(f"  {problem}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
