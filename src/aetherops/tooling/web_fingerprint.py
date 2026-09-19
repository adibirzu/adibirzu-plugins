"""Web header fingerprint + security-header audit via curl.

Field-proven checks: HSTS presence/strength, frame/click defenses,
CSP family (CSP, COOP/COEP/CORP), referrer/permissions policy, and
RFC 9116 security.txt discovery. Binary path resolves via
``AETHEROPS_TOOL_CURL`` then PATH.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlparse

from aetherops.tooling.dns_recon import resolve_tool

_HSTS_MAXAGE_RE = re.compile(r"max-age=(\d+)", re.IGNORECASE)

# header-name-lower -> (required?, description)
_CHECKS = {
    "strict-transport-security": "HSTS",
    "x-frame-options": "clickjacking defense",
    "x-content-type-options": "MIME sniffing defense",
    "referrer-policy": "referrer control",
    "permissions-policy": "browser feature control",
    "content-security-policy": "injection defense (CSP)",
    "cross-origin-opener-policy": "cross-origin isolation (COOP)",
    "cross-origin-embedder-policy": "cross-origin isolation (COEP)",
    "cross-origin-resource-policy": "cross-origin isolation (CORP)",
}


@dataclass(frozen=True)
class HeaderAudit:
    url: str
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    missing: tuple[str, ...] = ()
    hsts_max_age: int | None = None
    hsts_weak: bool = False          # present but max-age < 31536000
    server_tech: tuple[str, ...] = ()
    security_txt_ok: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "missing": list(self.missing),
            "hsts_max_age": self.hsts_max_age,
            "hsts_weak": self.hsts_weak,
            "server_tech": list(self.server_tech),
            "security_txt_ok": self.security_txt_ok,
        }


def _curl_headers(curl_bin: str, url: str, timeout: int, insecure: bool) -> tuple[int | None, dict[str, str]]:
    argv = [curl_bin, "-sSI", "--max-time", str(timeout)]
    if insecure:
        argv.append("-k")
    argv.append(url)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5, check=False)
    except subprocess.TimeoutExpired:
        return None, {}
    out = proc.stdout or ""
    status = None
    headers: dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"^HTTP/\S+\s+(\d{3})", line)
        if m:
            status = int(m.group(1))
            continue
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return status, headers


def _fetch_body(curl_bin: str, url: str, timeout: int, insecure: bool) -> str:
    argv = [curl_bin, "-sS", "--max-time", str(timeout)]
    if insecure:
        argv.append("-k")
    argv.append(url)
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5, check=False).stdout or ""
    except subprocess.TimeoutExpired:
        return ""


def _looks_like_404(body: str) -> bool:
    low = body[:2000].lower()
    return "<!doctype html" in low and ("404" in low or "not found" in low)


def audit_headers(
    url: str,
    *,
    timeout: int = 15,
    curl_bin: str | None = None,
    check_security_txt: bool = True,
) -> HeaderAudit:
    """Fetch *url* headers with curl and run the audit battery."""
    bin_ = curl_bin or resolve_tool("curl", "AETHEROPS_TOOL_CURL")
    if not bin_:
        raise FileNotFoundError("curl not found (set AETHEROPS_TOOL_CURL)")

    parsed = urlparse(url)
    expired_peer = parsed.hostname != "cyber-sec.ro"  # intros have expired certs
    status, headers = _curl_headers(bin_, url, timeout, insecure=expired_peer)

    hsts = headers.get("strict-transport-security", "")
    hsts_max_age = None
    if hsts:
        m = _HSTS_MAXAGE_RE.search(hsts)
        if m:
            hsts_max_age = int(m.group(1))

    missing = tuple(name for name in _CHECKS if name not in headers)

    tech: list[str] = []
    server = headers.get("server", "")
    if server:
        tech.append(server)

    txt_ok = False
    if check_security_txt:
        base = f"{parsed.scheme}://{parsed.netloc}"
        body = _fetch_body(bin_, f"{base}/.well-known/security.txt", timeout, insecure=expired_peer)
        txt_ok = "contact:" in body.lower() and not _looks_like_404(body)

    return HeaderAudit(
        url=url,
        status=status,
        headers=headers,
        missing=missing,
        hsts_max_age=hsts_max_age,
        hsts_weak=bool(hsts_max_age and hsts_max_age < 31_536_000),
        server_tech=tuple(tech),
        security_txt_ok=txt_ok,
    )
