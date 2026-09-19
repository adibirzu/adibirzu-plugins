"""Pinned toolchain manifest. Binaries resolve from this file, not ambient PATH."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from aetherops.config import ROOT

DEFAULT_MANIFEST = ROOT / "configs" / "toolchain.yaml"


class ToolSpec(BaseModel):
    """One declared scanner/CLI. Version is compared at verify() time."""

    name: str = ""
    binary: str
    version: str
    version_args: list[str] = Field(default_factory=lambda: ["--version"])
    base_args: list[str] = Field(default_factory=list)
    non_interactive_args: list[str] = Field(default_factory=list)
    timeout_s: int = 600
    normalizer: str = "generic"
    networked: bool = False
    notes: str = ""


class ToolchainManifest(BaseModel):
    manifest_version: str = "1.0.0"
    tools: dict[str, ToolSpec] = Field(default_factory=dict)

    def get(self, name: str) -> ToolSpec:
        spec = self.tools.get(name)
        if spec is None:
            raise KeyError(f"Tool {name!r} is not declared in the toolchain manifest.")
        return spec


def load_manifest(path: Path | None = None) -> ToolchainManifest:
    dest = path or DEFAULT_MANIFEST
    raw = yaml.safe_load(dest.read_text(encoding="utf-8")) or {}
    tools_raw: dict[str, Any] = dict(raw.get("tools") or {})
    tools: dict[str, ToolSpec] = {}
    for name, item in tools_raw.items():
        payload = dict(item or {})
        payload["name"] = name
        tools[name] = ToolSpec.model_validate(payload)
    return ToolchainManifest(
        manifest_version=str(raw.get("manifest_version") or "1.0.0"),
        tools=tools,
    )
