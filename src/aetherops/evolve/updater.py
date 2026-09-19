from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from aetherops.airlock.classifier import classify, sanitize_capability
from aetherops.config import ROOT
from aetherops.harness.observation import err
from aetherops.types import Observation

# Capability sources only. Never include engagement/vault paths.
# Exact HTTPS URLs. Adding a URL is a reviewed PR. No wildcards, no HF models.
DEFAULT_CAPABILITY_URLS = (
    "https://raw.githubusercontent.com/NVIDIA/garak/main/README.md",
    "https://raw.githubusercontent.com/microsoft/PyRIT/main/README.md",
    "https://raw.githubusercontent.com/schematizeme/skill-pentest/main/SKILL.md",
)

_WILDCARD_CHARS = ("*", "?", "[", "]", "{", "}")
_BLOCKED_ROOTS = (
    "/vault/",
    "/engagements/",
    "/reports/",
    "vault/",
    "engagements/",
    "reports/",
)
_HF_HOSTS = frozenset({"huggingface.co", "hf.co", "www.huggingface.co"})
_MODEL_MARKERS = (
    "/resolve/",
    ".gguf",
    ".safetensors",
    ".bin",
    "/models/",
)


class EvolveDenied(ValueError):
    """URL is not an exact allowlisted capability GET."""


def is_exact_capability_url(url: str) -> tuple[bool, str]:
    """Accept only exact https file URLs. No wildcards, no model hosts."""
    if not url or not isinstance(url, str):
        return False, "empty"
    stripped = url.strip()
    lowered = stripped.lower()
    if any(ch in stripped for ch in _WILDCARD_CHARS):
        return False, "wildcard"
    if any(block in lowered for block in _BLOCKED_ROOTS):
        return False, "engagement-path"
    parsed = urlparse(stripped)
    if parsed.scheme != "https":
        return False, "not-https"
    if parsed.username or parsed.password:
        return False, "userinfo"
    host = (parsed.hostname or "").lower()
    if not host:
        return False, "no-host"
    if host in _HF_HOSTS or host.endswith((".huggingface.co", ".hf.co")):
        return False, "model-host"
    path = parsed.path or ""
    if not path or path == "/":
        return False, "bare-domain"
    if any(marker in lowered for marker in _MODEL_MARKERS):
        return False, "model-download"
    if parsed.query or parsed.fragment:
        return False, "query-or-fragment"
    return True, "ok"


def load_capability_urls(*files: Path | None) -> list[str]:
    """Load exact capability URLs from airlock yaml files, then builtins."""
    urls: list[str] = []
    for path in files:
        if path is None or not path.exists():
            continue
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        urls.extend(str(u) for u in (raw.get("capability_urls") or []) if u)
    if not urls:
        urls.extend(DEFAULT_CAPABILITY_URLS)
    return urls


def validate_capability_urls(urls: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    accepted: list[str] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for url in urls:
        ok, reason = is_exact_capability_url(url)
        if not ok:
            rejected.append({"url": url, "reason": reason})
            continue
        if url in seen:
            continue
        seen.add(url)
        accepted.append(url)
    return accepted, rejected


def fetch_capability(url: str, timeout: float = 20.0) -> str:
    """GET an already-validated exact URL. Never follows redirects."""
    ok, reason = is_exact_capability_url(url)
    if not ok:
        raise EvolveDenied(reason)
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.get(url)
    if resp.status_code != 200:
        raise EvolveDenied(f"HTTP {resp.status_code}")
    return resp.text


def evolve(
    cache_dir: Path,
    allowlist_file: Path | None,
    airgap: bool,
    allow_network: bool,
    airlock_file: Path | None = None,
) -> Observation:
    if airgap or not allow_network:
        return err(
            "Evolve blocked: air-gap is on (or --allow-network missing).",
            stop_condition="Operate from local skills/. Enable evolve only on a non-engagement host.",
        )
    lock = airlock_file if airlock_file is not None else ROOT / "configs" / "airlock.yaml"
    urls = load_capability_urls(lock, allowlist_file)
    urls, rejected = validate_capability_urls(urls)
    cache_dir.mkdir(parents=True, exist_ok=True)
    saved: list[str] = []
    for url in urls:
        try:
            text = fetch_capability(url)
        except (EvolveDenied, httpx.HTTPError, OSError, ValueError, TypeError) as exc:
            rejected.append({"url": url, "reason": str(exc)})
            continue
        kind = classify(text, path=url)
        if kind != "capability":
            rejected.append({"url": url, "reason": f"classified as {kind}; not cached"})
            continue
        cleaned = sanitize_capability(text)
        dest = cache_dir / (url.split("/")[-1] or "capability.md")
        dest.write_text(cleaned, encoding="utf-8")
        saved.append(str(dest))
    if saved:
        index = cache_dir / "INDEX.md"
        lines = [
            "# Evolve capability index",
            "",
            "Allowlisted capability docs only. Never includes vault/, engagements/, or reports/.",
            "",
        ]
        for path in saved:
            lines.append(f"- `{path}`")
        index.write_text("\n".join(lines) + "\n", encoding="utf-8")
        saved.append(str(index))
    status = "success" if saved else "warning"
    return Observation(
        status=status,
        summary=f"Cached {len(saved)} capability docs; rejected {len(rejected)}",
        artifacts=saved,
        data={"rejected": rejected},
        next_actions=["Review .evolve-cache before promoting into skills/"],
    )
