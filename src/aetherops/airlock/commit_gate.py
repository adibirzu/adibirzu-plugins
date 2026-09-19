"""Client-identifier sanitizer for commit paths and report render.

Seeds are synthetic (RFC 5737 / example domains). Real engagement names,
including any private client codename, must never be added to this file.
"""

from __future__ import annotations

from pathlib import Path

from aetherops.airlock.classifier import CANARY_MARKERS

# Planted tokens used only in tests and this denylist. Not real clients.
SEED_CLIENT_IDENTIFIERS: tuple[str, ...] = (
    "SEEDCLIENT",
    "CLIENT-SEED-ACME",
    "seed-client.example",
    "198.51.100.77",
    "SEED-ENGAGEMENT-ID",
    "AcmeSeedCorp",
)


class ClientIdentifierFound(ValueError):
    """A planted or forbidden client identifier was found."""

    def __init__(self, hits: list[str], path: str | None = None) -> None:
        self.hits = hits
        self.path = path
        loc = f" in {path}" if path else ""
        super().__init__(f"client identifier(s){loc}: {', '.join(hits)}")


def _hits_in(text: str) -> list[str]:
    blob = text or ""
    lowered = blob.lower()
    hits: list[str] = []
    for token in SEED_CLIENT_IDENTIFIERS:
        if token.lower() in lowered:
            hits.append(token)
    for token in CANARY_MARKERS:
        if token.lower() in lowered:
            hits.append(token)
    return hits


def scan_text(text: str, *, path: str | None = None) -> None:
    hits = _hits_in(text)
    if hits:
        raise ClientIdentifierFound(hits, path)


_SELF_NAMES = frozenset(
    {
        "commit_gate.py",
        "sanitize_gate.py",
        "test_cp10_sanitizer_gate.py",
    }
)


def scan_paths(paths: list[Path]) -> None:
    """Fail closed if any given file contains a seed client identifier.

    The denylist module and its unit test necessarily mention the seeds;
    they are skipped so the hook can still scan the rest of a commit.
    """
    for path in paths:
        if not path.is_file() or path.name in _SELF_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        scan_text(text, path=str(path))


def assert_report_clean(markdown: str) -> str:
    """Hook for report render: refuse to emit a report that carries seed ids."""
    scan_text(markdown, path="report")
    return markdown
