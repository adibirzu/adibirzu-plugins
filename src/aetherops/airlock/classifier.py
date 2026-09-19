from __future__ import annotations

import re

from aetherops.types import Classification

# Distinctive planted tokens. Capability docs never contain these; evolve
# must classify them as engagement and refuse to cache.
CANARY_MARKERS = (
    "aetherops-canary",
    "canarytoken",
    "corpus-canary",
    "vault-canary",
)

# Always engagement, even when capability words are also present.
HARD_ENGAGEMENT_MARKERS = (
    "engagement_id",
    "credential",
    "password",
    "secret",
    "cookie",
    "vault/",
) + CANARY_MARKERS

ENGAGEMENT_MARKERS = HARD_ENGAGEMENT_MARKERS + (
    "scope_cidrs",
    "scope_hosts",
    "authorized_by",
    "finding",
    "session",
    "10.",
    "192.168.",
    "172.16.",
)
CAPABILITY_MARKERS = (
    "skill",
    "methodology",
    "mitre",
    "owasp",
    "ptes",
    "nist",
    "raise",
    "adapter",
    "modelfile",
    "knowledge pack",
)

RFC1918_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")\b"
)
_CANARY_RE = re.compile(r"(?i)(?:aetherops-canary|canarytoken|corpus-canary|vault-canary)[-A-Z0-9]*")


def _normalized_path(path: str) -> str:
    return path.replace("\\", "/").lower()


def classify(text: str, path: str = "") -> Classification:
    norm_path = _normalized_path(path)
    blob = f"{norm_path}\n{text}".lower()
    if norm_path.startswith("vault/") or "/vault/" in norm_path:
        return "engagement"
    if any(marker in blob for marker in HARD_ENGAGEMENT_MARKERS):
        return "engagement"
    if RFC1918_RE.search(blob):
        return "engagement"
    if any(marker in blob for marker in CAPABILITY_MARKERS):
        return "capability"
    if any(marker in blob for marker in ENGAGEMENT_MARKERS):
        return "engagement"
    return "unknown"


_IPV4 = r"(?:\d{1,3}\.){3}\d{1,3}"
_IPV4_CIDR = _IPV4 + r"/(?:3[0-2]|[12]?\d)"
# Compressed and full IPv6, optional zone id, optional brackets.
_HEX4 = r"[0-9a-fA-F]{1,4}"
_IPV6 = (
    r"(?:(?:" + _HEX4 + r":){7}" + _HEX4
    + r"|(?:" + _HEX4 + r":){1,7}:"
    + r"|:(?::" + _HEX4 + r"){1,7}"
    + r"|(?:" + _HEX4 + r":){1,6}:" + _HEX4
    + r"|(?:" + _HEX4 + r":){1,5}(?::" + _HEX4 + r"){1,2}"
    + r"|(?:" + _HEX4 + r":){1,4}(?::" + _HEX4 + r"){1,3}"
    + r"|(?:" + _HEX4 + r":){1,3}(?::" + _HEX4 + r"){1,4}"
    + r"|(?:" + _HEX4 + r":){1,2}(?::" + _HEX4 + r"){1,5}"
    + r"|" + _HEX4 + r":(?::" + _HEX4 + r"){1,6}"
    + r"|::(?:ffff(?::0{1,4}){0,1}:){0,1}" + _IPV4
    + r"|::" + _HEX4
    + r"|::)"
    + r"(?:%[0-9A-Za-z._-]+)?"
)
_IPV6_BRACKETS = r"\[" + _IPV6 + r"\]"
_IPV6_CIDR = r"(?:" + _IPV6_BRACKETS + r"|" + _IPV6 + r")/(?:12[0-8]|1[01]\d|[1-9]?\d)"
_SECRET = (
    r"(?i)(password|secret|token|cookie|authorization|api[_-]?key|bearer|private[_-]?key)"
    r"\s*[:=]\s*\S+"
)
# Lab-ish two-label hosts, plus any FQDN with three or more labels.
_HOST = (
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}"
    r"(?:[A-Za-z]{2,24})\b"
    r"|\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)"
    r"(?:local|internal|lan|corp|lab|home|invalid|example|test)\b"
)


def sanitize_capability(text: str) -> str:
    """Strip IPv4/IPv6/CIDR, secret-shaped tokens, and canaries before any fetch cache or lesson write."""
    cleaned = re.sub(_IPV4_CIDR, "[redacted-cidr]", text)
    cleaned = re.sub(_IPV6_CIDR, "[redacted-cidr]", cleaned)
    cleaned = re.sub(_IPV6_BRACKETS, "[redacted-ip]", cleaned)
    cleaned = re.sub(_IPV6, "[redacted-ip]", cleaned)
    cleaned = re.sub(rf"\b{_IPV4}\b", "[redacted-ip]", cleaned)
    cleaned = re.sub(_SECRET, r"\1=[redacted]", cleaned)
    cleaned = _CANARY_RE.sub("[redacted-canary]", cleaned)
    return cleaned


def sanitize_lesson(text: str) -> str:
    """Capability-lesson sanitizer: identifiers first, then lab/FQDN hostnames."""
    cleaned = sanitize_capability(text)
    return re.sub(_HOST, "[redacted-host]", cleaned)


class OutboundRefused(ValueError):
    """Text still contains identifiers that must not leave the box."""


_ENGAGEMENT_ID_RE = re.compile(r"(?i)engagement_id\s*[:=]\s*\S+")
# Outbound-only: a bare two-label apex (acmecorp.com) is not caught by _HOST,
# which only covers 3+-label FQDNs and lab TLDs. Restricted to a curated set of
# public TLDs so common file names (run.sh, main.py, config.yaml) are untouched.
# Applied ONLY in sanitize_outbound — never in classify() or capability lessons.
_APEX_TLDS = (
    "com|net|org|io|co|ai|dev|app|cloud|online|site|tech|xyz|biz|info"
    "|eu|ro|us|uk|de|fr|nl|es|it|pl|ru|cn|jp|gov|edu"
)
_APEX_HOST_RE = re.compile(
    r"(?i)\b[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.(?:" + _APEX_TLDS + r")\b"
)
_UNREDACTED_SECRET_RE = re.compile(
    r"(?i)(password|secret|token|cookie|authorization|api[_-]?key|bearer|private[_-]?key)"
    r"\s*[:=]\s*(?!\[redacted\])\S+"
)


def scrub_outbound(text: str) -> str:
    """Redact IPs/CIDRs, secrets, hosts, apex domains, engagement_id, canaries.

    Never raises — safe to apply field-by-field to nested structures (e.g. a
    training-corpus tool_trace) before serialization. sanitize_outbound layers
    the fail-closed refusal checks on top of this.
    """
    cleaned = sanitize_lesson(text or "")
    cleaned = _ENGAGEMENT_ID_RE.sub("engagement_id=[redacted]", cleaned)
    cleaned = _APEX_HOST_RE.sub("[redacted-host]", cleaned)
    return cleaned


def sanitize_outbound(text: str) -> str:
    """Sanitize then refuse if IPs, canaries, or unredacted secrets remain.

    Used before any connected-LLM POST and before training-corpus writes.
    Does not use classify() — the word "finding" is capability language.
    """
    raw = text or ""
    if _CANARY_RE.search(raw):
        raise OutboundRefused("outbound text contains a canary")
    cleaned = scrub_outbound(raw)
    if RFC1918_RE.search(cleaned) or re.search(rf"\b{_IPV4}\b", cleaned):
        raise OutboundRefused("outbound text still contains an IP or RFC1918 address")
    if _UNREDACTED_SECRET_RE.search(cleaned):
        raise OutboundRefused("outbound text still contains an unredacted secret")
    return cleaned
