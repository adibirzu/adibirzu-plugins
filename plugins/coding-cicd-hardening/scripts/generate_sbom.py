#!/usr/bin/env python3
"""Write CycloneDX and SPDX SBOMs for a plugin marketplace repository.

Standard library only. The inventory is what a consumer of the marketplace
actually pulls in or trusts:

  * every plugin listed in .claude-plugin/marketplace.json, local or remote
  * every GitHub Action and container image the workflows reference

    python3 generate_sbom.py [ROOT] --spec-version 1.7 --output-dir sbom

Outputs <output-dir>/marketplace.cdx.json (CycloneDX) and
<output-dir>/marketplace.spdx.json (SPDX 2.3). Output is reproducible: the
same tree and the same SOURCE_DATE_EPOCH give byte-identical files.

Exit status: 0 written, 2 usage error or missing marketplace manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "generate_sbom.py"
TOOL_VERSION = "1.0.0"
SPEC_VERSIONS = ("1.6", "1.7")
SKIP_NAMES = {"__pycache__", ".DS_Store", "node_modules", ".git"}
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)")
GITHUB_REPO = re.compile(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
# SPDX identifiers this tool will assert. Anything else is recorded by name in
# CycloneDX and as NOASSERTION in SPDX, so the output always validates.
KNOWN_LICENSES = {
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "GPL-2.0-only",
    "GPL-3.0-only",
    "ISC",
    "LGPL-3.0-only",
    "MIT",
    "MPL-2.0",
    "Unlicense",
}


@dataclass(frozen=True)
class Component:
    kind: str  # "plugin" | "action" | "image"
    name: str
    version: str
    description: str = ""
    license: str = ""
    purl: str = ""
    vcs_url: str = ""
    tree_sha256: str = ""

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.name}@{self.version}"


def tree_digest(root: Path) -> str:
    """Hash every file path and content under root, in sorted order."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root)
        if SKIP_NAMES.intersection(relative.parts) or path.suffix == ".pyc":
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return digest.hexdigest()


def plugin_component(root: Path, entry: dict) -> Component:
    name, version = entry["name"], str(entry.get("version", ""))
    description = entry.get("description", "")
    source = entry.get("source")
    if isinstance(source, str):
        folder = (root / source).resolve()
        manifest = folder / ".claude-plugin" / "plugin.json"
        declared = ""
        if manifest.is_file():
            declared = json.loads(manifest.read_text(encoding="utf-8")).get("license", "")
        return Component(
            kind="plugin",
            name=name,
            version=version,
            description=description,
            license=declared,
            purl=f"pkg:generic/{name}@{version}",
            tree_sha256=tree_digest(folder) if folder.is_dir() else "",
        )
    url = (source or {}).get("url", "")
    match = GITHUB_REPO.match(url)
    purl = f"pkg:github/{match.group(1)}/{match.group(2)}@{version}" if match else ""
    return Component(
        kind="plugin", name=name, version=version, description=description, purl=purl, vcs_url=url
    )


def workflow_components(root: Path) -> list[Component]:
    folder = root / ".github" / "workflows"
    found: dict[tuple[str, str], Component] = {}
    if not folder.is_dir():
        return []
    for path in sorted(p for p in folder.iterdir() if p.suffix in {".yml", ".yaml"}):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = USES.match(line)
            if not match:
                continue
            ref = match.group(1).strip("\"'")
            if ref.startswith("./") or "@" not in ref:
                continue
            name, version = ref.rsplit("@", 1)
            if name.startswith("docker://"):
                component = Component(kind="image", name=name[len("docker://") :], version=version)
            else:
                owner_repo = "/".join(name.split("/")[:2])
                subpath = "/".join(name.split("/")[2:])
                component = Component(
                    kind="action",
                    name=name,
                    version=version,
                    purl=f"pkg:github/{owner_repo}@{version}" + (f"#{subpath}" if subpath else ""),
                    vcs_url=f"https://github.com/{owner_repo}",
                )
            found[(component.kind + name, version)] = component
    return [found[key] for key in sorted(found)]


def build_inventory(root: Path) -> tuple[str, list[Component]]:
    data = json.loads((root / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    plugins = [plugin_component(root, entry) for entry in data.get("plugins", [])]
    return data.get("name", root.name), plugins + workflow_components(root)


def timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = (
        datetime.fromtimestamp(int(epoch), tz=timezone.utc) if epoch else datetime.now(timezone.utc)
    )
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def content_uuid(name: str, components: list[Component]) -> str:
    seed = json.dumps([name] + [repr(c) for c in components], sort_keys=True)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def cyclonedx(name: str, components: list[Component], spec_version: str, created: str) -> dict:
    root_ref = f"marketplace:{name}"
    items = []
    for component in components:
        item: dict = {
            "type": "container" if component.kind == "image" else "application",
            "bom-ref": component.ref,
            "name": component.name,
            "version": component.version,
        }
        if component.description:
            item["description"] = component.description
        if component.license:
            key = "id" if component.license in KNOWN_LICENSES else "name"
            item["licenses"] = [{"license": {key: component.license}}]
        if component.purl:
            item["purl"] = component.purl
        if component.vcs_url:
            item["externalReferences"] = [{"type": "vcs", "url": component.vcs_url}]
        properties = [{"name": "marketplace:kind", "value": component.kind}]
        if component.tree_sha256:
            properties.append({"name": "marketplace:tree-sha256", "value": component.tree_sha256})
        item["properties"] = properties
        items.append(item)
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{content_uuid(name, components)}",
        "version": 1,
        "metadata": {
            "timestamp": created,
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}
                ]
            },
            "component": {"type": "application", "bom-ref": root_ref, "name": name},
        },
        "components": items,
        "dependencies": [{"ref": root_ref, "dependsOn": [c.ref for c in components]}],
    }


def spdx_id(component: Component) -> str:
    label = f"{component.kind}-{component.name}"
    if component.kind != "plugin":
        label += f"-{component.version[:12]}"
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]+", "-", label).strip("-")


def spdx(name: str, components: list[Component], created: str) -> dict:
    root_id = "SPDXRef-Marketplace"
    packages: list[dict] = [
        {
            "SPDXID": root_id,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for component in components:
        if component.kind == "action":
            location = f"git+{component.vcs_url}@{component.version}"
        elif component.vcs_url:
            location = f"git+{component.vcs_url}"
        else:
            location = "NOASSERTION"
        package: dict = {
            "SPDXID": spdx_id(component),
            "name": component.name,
            "versionInfo": component.version,
            "downloadLocation": location,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": (
                component.license if component.license in KNOWN_LICENSES else "NOASSERTION"
            ),
            "copyrightText": "NOASSERTION",
        }
        if component.kind == "plugin":
            package["primaryPackagePurpose"] = "APPLICATION"
        if component.description:
            package["description"] = component.description
        if component.tree_sha256:
            package["comment"] = f"tree-sha256: {component.tree_sha256}"
        if component.purl:
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component.purl,
                }
            ]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package["SPDXID"],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-sbom",
        "documentNamespace": f"https://spdx.org/spdxdocs/{name}-{content_uuid(name, components)}",
        "creationInfo": {"created": created, "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"]},
        "packages": packages,
        "relationships": relationships,
    }


def write_json(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write CycloneDX and SPDX 2.3 SBOMs for a plugin marketplace."
    )
    parser.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument("--spec-version", choices=SPEC_VERSIONS, default="1.7")
    parser.add_argument("--output-dir", default="sbom")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not (root / ".claude-plugin" / "marketplace.json").is_file():
        print(f"error: no .claude-plugin/marketplace.json under {root}", file=sys.stderr)
        return 2

    name, components = build_inventory(root)
    created = timestamp()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "marketplace.cdx.json", cyclonedx(name, components, args.spec_version, created))
    write_json(output / "marketplace.spdx.json", spdx(name, components, created))
    print(
        f"wrote {len(components)} components to {output}/marketplace.cdx.json "
        f"(CycloneDX {args.spec_version}) and {output}/marketplace.spdx.json (SPDX-2.3)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
