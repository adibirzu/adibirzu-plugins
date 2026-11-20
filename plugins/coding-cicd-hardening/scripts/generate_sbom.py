#!/usr/bin/env python3
"""Write CycloneDX and SPDX SBOMs for a plugin marketplace repository.

Standard library only. The inventory is what a consumer of the marketplace
actually pulls in or trusts:

  * every plugin listed in .claude-plugin/marketplace.json, in any source
    form Claude Code documents: relative path, github, url, git-subdir, npm,
    archive and command
  * every GitHub Action, reusable workflow and container image that the
    workflows reference, read with the same reader check_workflows.py uses

    python3 generate_sbom.py [ROOT] --spec-version 1.7 --output-dir sbom

Outputs <output-dir>/marketplace.cdx.json (CycloneDX) and
<output-dir>/marketplace.spdx.json (SPDX 2.3). Output is reproducible: the
same tree and the same SOURCE_DATE_EPOCH give byte-identical files.

Nothing is asserted that was not read. A source with no public identity gets
no package URL, and a license that was not declared is NOASSERTION.

A workflow construct the reader cannot follow would leave the inventory
incomplete, so generation stops unless --allow-incomplete is given, in which
case both documents are marked incomplete.

Exit status: 0 written, 1 inventory incomplete, 2 usage error, missing
marketplace manifest or duplicate catalog entries.
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
from urllib.parse import quote

# The workflow reader lives next to this file. Importing it must not leave
# bytecode inside the plugin directory.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_workflows  # noqa: E402

TOOL_NAME = "generate_sbom.py"
TOOL_VERSION = "1.2.0"
SPEC_VERSIONS = ("1.6", "1.7")
SKIP_NAMES = {"__pycache__", ".DS_Store", "node_modules", ".git"}
GITHUB_REPO = re.compile(r"^(?:https?://|ssh://git@)github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
GITHUB_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+$")
SCP_STYLE = re.compile(r"^git@([^:/]+):(.+)$")
GIT_TRANSPORTS = ("https://", "http://", "ssh://", "git://")
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
    version: str = ""
    description: str = ""
    license: str = ""
    purl: str = ""
    vcs_url: str = ""
    download: str = ""
    distribution_url: str = ""
    sha256: str = ""
    tree_sha256: str = ""
    source: str = ""
    revision: str = ""
    outside_root: bool = False

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.name}@{self.version}"


def tree_digest(root: Path, exclude: Path | None = None) -> str:
    """Hash every file path and content under root, in sorted order.

    ``exclude`` is a directory to leave out, so a plugin at the repository
    root does not hash the SBOMs this tool writes into it.
    """
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root)
        if SKIP_NAMES.intersection(relative.parts) or path.suffix == ".pyc":
            continue
        if exclude is not None and (path == exclude or exclude in path.parents):
            continue
        digest.update(relative.as_posix().encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii") + b"\n")
    return digest.hexdigest()


def git_identity(url: str, revision: str, subpath: str) -> dict:
    """Package URL, repository URL and download location for a git source.

    The package URL carries the revision that is fetched: the commit or ref
    the source names. A source that names neither tracks the default branch,
    so its package URL has no version at all. The catalog version is a label
    and never stands in for a revision.
    """
    if GITHUB_SHORTHAND.match(url):
        url = f"https://github.com/{url}"
    scp = SCP_STYLE.match(url)
    if scp:
        url = f"ssh://git@{scp.group(1)}/{scp.group(2)}"
    if not url.startswith(GIT_TRANSPORTS):
        return {}
    suffix = f"#{quote(subpath, safe='/')}" if subpath else ""
    identity = {
        "revision": revision or "default-branch",
        "download": f"git+{url}" + (f"@{quote(revision, safe='')}" if revision else "") + suffix,
    }
    if url.startswith(("https://", "http://")):
        identity["vcs_url"] = url
    match = GITHUB_REPO.match(url)
    if match:
        identity["purl"] = (
            f"pkg:github/{match.group(1).lower()}/{match.group(2).lower()}"
            + (f"@{quote(revision, safe='')}" if revision else "")
            + suffix
        )
    return identity


def npm_identity(package: str, version: str, registry: str) -> dict:
    """Package URL for an npm source. A version inside the package name wins."""
    if package.startswith(("https://", "http://")):
        return {"distribution_url": package, "download": package}
    name = package
    if "@" in package[1:]:
        name, _, embedded = package.rpartition("@")
        version = embedded or version
    purl = f"pkg:npm/{quote(name, safe='/')}" + (f"@{quote(version, safe='')}" if version else "")
    if registry:
        purl += f"?repository_url={quote(registry, safe='')}"
    return {"purl": purl}


def local_plugin(root: Path, entry: dict, source: str, plugin_root: str, exclude: Path | None) -> Component:
    name = entry["name"]
    # A source that is not a relative path is a bare name under pluginRoot.
    is_path = source in {".", ".."} or source.startswith(("./", "../"))
    folder = (root / source if is_path else root / plugin_root / source).resolve()
    if root != folder and root not in folder.parents:
        # Never read outside the repository on the say-so of a manifest.
        version = str(entry.get("version", ""))
        return Component(kind="plugin", name=name, version=version, source="local", outside_root=True)
    manifest = folder / ".claude-plugin" / "plugin.json"
    declared: dict = {}
    if manifest.is_file():
        declared = json.loads(manifest.read_text(encoding="utf-8"))
    # At install time the plugin manifest wins over the catalog entry.
    version = str(declared.get("version") or entry.get("version", ""))
    return Component(
        kind="plugin",
        name=name,
        version=version,
        description=entry.get("description", ""),
        license=declared.get("license", ""),
        purl=f"pkg:generic/{quote(name, safe='')}" + (f"@{quote(version, safe='')}" if version else ""),
        tree_sha256=tree_digest(folder, exclude) if folder.is_dir() else "",
        source="local",
    )


def plugin_component(root: Path, entry: dict, plugin_root: str = "", exclude: Path | None = None) -> Component:
    source = entry.get("source")
    if isinstance(source, str):
        return local_plugin(root, entry, source, plugin_root, exclude)
    source = source if isinstance(source, dict) else {}
    form = str(source.get("source", "unknown"))
    revision = str(source.get("sha") or source.get("ref") or "")
    identity: dict = {}
    if form == "github":
        identity = git_identity(str(source.get("repo", "")), revision, "")
    elif form == "url":
        identity = git_identity(str(source.get("url", "")), revision, "")
    elif form == "git-subdir":
        subpath = str(source.get("path", "")).strip("/")
        identity = git_identity(str(source.get("url", "")), revision, subpath)
    elif form == "npm":
        identity = npm_identity(
            str(source.get("package", "")), str(source.get("version", "")), str(source.get("registry", ""))
        )
    elif form == "archive":
        url = str(source.get("url", ""))
        identity = {"distribution_url": url, "download": url, "sha256": str(source.get("sha256", "")).lower()}
    return Component(
        kind="plugin",
        name=entry["name"],
        version=str(entry.get("version", "")),
        description=entry.get("description", ""),
        source=form,
        **identity,
    )


def image_component(reference: str) -> Component:
    reference = reference[len("docker://") :] if reference.startswith("docker://") else reference
    name, version = reference, ""
    if "@" in reference:
        name, version = reference.split("@", 1)
        name = name.rsplit(":", 1)[0] if ":" in name.rsplit("/", 1)[-1] else name
    elif ":" in reference.rsplit("/", 1)[-1]:
        name, version = reference.rsplit(":", 1)
    first = name.split("/", 1)[0]
    registry = first if "/" in name and ("." in first or ":" in first or first == "localhost") else ""
    path = name[len(registry) + 1 :] if registry else name
    purl = f"pkg:docker/{quote(path, safe='/')}" + (f"@{quote(version, safe='')}" if version else "")
    if registry:
        purl += f"?repository_url={quote(registry, safe='.-')}"
    return Component(kind="image", name=name, version=version, purl=purl, source="workflow")


def action_component(reference: str) -> Component:
    name, _, version = reference.partition("@")
    owner_repo = "/".join(name.split("/")[:2])
    subpath = "/".join(name.split("/")[2:])
    identity = git_identity(f"https://github.com/{owner_repo}", version, subpath)
    identity.pop("revision", None)
    return Component(kind="action", name=name, version=version, source="workflow", **identity)


def workflow_components(root: Path) -> tuple[list[Component], list[str]]:
    """Actions and images the workflows reference, plus what could not be read."""
    folder = root / ".github" / "workflows"
    if not folder.is_dir():
        return [], []
    found: dict[str, Component] = {}
    unread: list[str] = []
    for path in sorted(p for p in folder.iterdir() if p.suffix in {".yml", ".yaml"}):
        nodes, problems = check_workflows.parse_workflow(path.read_text(encoding="utf-8"))
        images, unresolved = check_workflows.image_references(nodes)
        relative = path.relative_to(root).as_posix()
        unread.extend(f"{relative}:{line}: {reason}" for line, reason in problems + unresolved)
        components = [image_component(image) for image, _ in images]
        for node in nodes:
            value = node.value
            if value and check_workflows.is_action_ref(node.path) and not value.startswith(("./", "docker://")):
                components.append(action_component(value))
        for component in components:
            found[component.ref] = component
    return [found[key] for key in sorted(found)], sorted(unread)


def build_inventory(root: Path, exclude: Path | None = None) -> tuple[str, list[Component], list[str]]:
    data = json.loads((root / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    plugin_root = str((data.get("metadata") or {}).get("pluginRoot", ""))
    plugins = [plugin_component(root, entry, plugin_root, exclude) for entry in data.get("plugins", [])]
    actions, unread = workflow_components(root)
    return data.get("name", root.name), plugins + actions, unread


def timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    moment = datetime.fromtimestamp(int(epoch), tz=timezone.utc) if epoch else datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def content_uuid(name: str, components: list[Component], created: str) -> str:
    """A stable identity for one document: its content, build time and tool."""
    seed = json.dumps([name, created, TOOL_VERSION] + [repr(c) for c in components], sort_keys=True)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def cyclonedx(
    name: str, components: list[Component], spec_version: str, created: str, incomplete: bool = False
) -> dict:
    root_ref = f"marketplace:{name}"
    items = []
    for component in components:
        item: dict = {
            "type": "container" if component.kind == "image" else "application",
            "bom-ref": component.ref,
            "name": component.name,
        }
        if component.version:
            item["version"] = component.version
        if component.description:
            item["description"] = component.description
        if component.sha256:
            item["hashes"] = [{"alg": "SHA-256", "content": component.sha256}]
        if component.license:
            key = "id" if component.license in KNOWN_LICENSES else "name"
            item["licenses"] = [{"license": {key: component.license}}]
        if component.purl:
            item["purl"] = component.purl
        references = []
        if component.vcs_url:
            references.append({"type": "vcs", "url": component.vcs_url})
        if component.distribution_url:
            references.append({"type": "distribution", "url": component.distribution_url})
        if references:
            item["externalReferences"] = references
        properties = [{"name": "marketplace:kind", "value": component.kind}]
        if component.source:
            properties.append({"name": "marketplace:source", "value": component.source})
        if component.revision:
            properties.append({"name": "marketplace:revision", "value": component.revision})
        if component.tree_sha256:
            properties.append({"name": "marketplace:tree-sha256", "value": component.tree_sha256})
        if component.outside_root:
            properties.append({"name": "marketplace:source-outside-root", "value": "true"})
        item["properties"] = properties
        items.append(item)
    metadata: dict = {
        "timestamp": created,
        "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
        "component": {"type": "application", "bom-ref": root_ref, "name": name},
    }
    if incomplete:
        metadata["properties"] = [{"name": "marketplace:inventory-incomplete", "value": "true"}]
    return {
        "$schema": f"http://cyclonedx.org/schema/bom-{spec_version}.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{content_uuid(name, components, created)}",
        "version": 1,
        "metadata": metadata,
        "components": items,
        "dependencies": [{"ref": root_ref, "dependsOn": [c.ref for c in components]}],
    }


def spdx_id(component: Component) -> str:
    """A readable identifier with a hash suffix, so similar names never collide."""
    label = re.sub(r"[^A-Za-z0-9.]+", "-", f"{component.kind}-{component.name}").strip("-")
    suffix = hashlib.sha256(component.ref.encode("utf-8")).hexdigest()[:10]
    return f"SPDXRef-{label}-{suffix}"


def spdx(name: str, components: list[Component], created: str, incomplete: bool = False) -> dict:
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
        package: dict = {"SPDXID": spdx_id(component), "name": component.name}
        if component.version:
            package["versionInfo"] = component.version
        package.update(
            {
                "downloadLocation": component.download or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": component.license if component.license in KNOWN_LICENSES else "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        if component.kind == "plugin":
            package["primaryPackagePurpose"] = "APPLICATION"
        elif component.kind == "image":
            package["primaryPackagePurpose"] = "CONTAINER"
        if component.description:
            package["description"] = component.description
        if component.sha256:
            package["checksums"] = [{"algorithm": "SHA256", "checksumValue": component.sha256}]
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
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-sbom",
        "documentNamespace": (
            f"https://spdx.org/spdxdocs/{quote(name, safe='')}-{content_uuid(name, components, created)}"
        ),
        "creationInfo": {"created": created, "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"]},
        "packages": packages,
        "relationships": relationships,
    }
    if incomplete:
        document["comment"] = "Inventory incomplete: parts of the workflows could not be read."
    return document


def write_json(path: Path, document: dict) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write CycloneDX and SPDX 2.3 SBOMs for a plugin marketplace.")
    parser.add_argument("root", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument("--spec-version", choices=SPEC_VERSIONS, default="1.7")
    parser.add_argument("--output-dir", default="sbom")
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="write the SBOMs even when part of a workflow could not be read, and mark them incomplete",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not (root / ".claude-plugin" / "marketplace.json").is_file():
        print(f"error: no .claude-plugin/marketplace.json under {root}", file=sys.stderr)
        return 2

    output = Path(args.output_dir)
    name, components, unread = build_inventory(root, exclude=output.resolve())

    references = [component.ref for component in components]
    duplicates = sorted({ref for ref in references if references.count(ref) > 1})
    if duplicates:
        print(f"error: the catalog lists the same name and version twice: {', '.join(duplicates)}", file=sys.stderr)
        return 2
    if unread:
        for line in unread:
            print(line, file=sys.stderr)
        if not args.allow_incomplete:
            print(
                "error: the inventory would be incomplete. Rewrite those constructs in plain block YAML, "
                "or pass --allow-incomplete to write SBOMs that are marked incomplete.",
                file=sys.stderr,
            )
            return 1

    created = timestamp()
    incomplete = bool(unread)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "marketplace.cdx.json", cyclonedx(name, components, args.spec_version, created, incomplete))
    write_json(output / "marketplace.spdx.json", spdx(name, components, created, incomplete))
    print(
        f"wrote {len(components)} components to {output}/marketplace.cdx.json "
        f"(CycloneDX {args.spec_version}) and {output}/marketplace.spdx.json (SPDX-2.3)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
