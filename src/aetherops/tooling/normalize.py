"""Byte-stable output normalizers for declared tools."""

from __future__ import annotations

import json
import re
from collections.abc import Callable

_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_NMAP_AT = re.compile(r"\bat\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?\s+\S+")
_ELAPSED = re.compile(r"scanned in\s+[0-9.]+ seconds", re.IGNORECASE)
_LATENCY = re.compile(r"\([0-9.]+s latency\)")
_PID = re.compile(r"\bpid\s*=\s*\d+\b", re.IGNORECASE)
_WS = re.compile(r"[ \t]+$")


def _eol(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def generic(text: str) -> str:
    """Strip clocks, PIDs, trailing whitespace; pin newlines."""
    cleaned = _eol(text or "")
    cleaned = _TIMESTAMP.sub("<ts>", cleaned)
    cleaned = _PID.sub("pid=<id>", cleaned)
    lines = [_WS.sub("", line) for line in cleaned.split("\n")]
    return "\n".join(lines).strip() + ("\n" if lines else "")


def nmap(text: str) -> str:
    cleaned = generic(text)
    cleaned = _NMAP_AT.sub("at <ts>", cleaned)
    cleaned = _ELAPSED.sub("scanned in <t> seconds", cleaned)
    cleaned = _LATENCY.sub("(<t> latency)", cleaned)
    return cleaned


def nuclei(text: str) -> str:
    lines = [line for line in generic(text).split("\n") if line != ""]
    return "\n".join(sorted(lines)) + ("\n" if lines else "")


def json_sorted(text: str) -> str:
    blob = (text or "").strip()
    if not blob:
        return "\n"
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return generic(text)
    dumped = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return dumped + "\n"


NORMALIZERS: dict[str, Callable[[str], str]] = {
    "generic": generic,
    "nmap": nmap,
    "nuclei": nuclei,
    "json_sorted": json_sorted,
}


def normalize(kind: str, text: str) -> str:
    fn = NORMALIZERS.get(kind or "generic", generic)
    return fn(text)
