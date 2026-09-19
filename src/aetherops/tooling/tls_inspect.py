"""TLS posture inspection via sslscan + openssl cert dates.

Strategies proven in the field: protocol-battery parsing (flag legacy
TLS 1.0/1.1), Heartbleed line, and cert expiry math. Binary paths resolve
via ``AETHEROPS_TOOL_SSLSCAN`` / ``AETHEROPS_TOOL_OPENSSL`` then PATH.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime

from aetherops.tooling.dns_recon import resolve_tool

_PROTOCOL_RE = re.compile(r"^(SSLv[23]|TLSv1\.[0-3])\s+(enabled|disabled)", re.MULTILINE)
_HEARTBLEED_RE = re.compile(r"(TLSv1\.[0-3]|SSLv3)\s+(?:not\s+)?vulnerable to heartbleed", re.IGNORECASE)
_CERT_DATE_RE = re.compile(r"notAfter=(.+)")


@dataclass(frozen=True)
class TlsReport:
    host: str
    protocols_enabled: tuple[str, ...]
    legacy_enabled: bool          # TLS 1.0/1.1 or SSLv2/v3 accepted
    heartbleed: bool
    cert_not_after: datetime | None
    cert_expired: bool
    days_left: int | None
    raw_summary: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "protocols_enabled": list(self.protocols_enabled),
            "legacy_enabled": self.legacy_enabled,
            "heartbleed": self.heartbleed,
            "cert_not_after": self.cert_not_after.isoformat() if self.cert_not_after else None,
            "cert_expired": self.cert_expired,
            "days_left": self.days_left,
        }


_LEGACY = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


def _parse_sslscan(text: str) -> tuple[tuple[str, ...], bool]:
    enabled: list[str] = []
    heartbleed = False
    for m in _PROTOCOL_RE.finditer(text):
        if m.group(2) == "enabled":
            enabled.append(m.group(1))
    # "X not vulnerable to heartbleed" lines still match the find-all above;
    # detect the negative form explicitly.
    for line in text.splitlines():
        low = line.strip().lower()
        if "heartbleed" in low:
            if "not vulnerable" in low:
                continue
            heartbleed = True
    return tuple(sorted(set(enabled))), heartbleed


def _cert_not_after(host: str, port: int, openssl_bin: str, timeout: int) -> datetime | None:
    try:
        s_client = subprocess.run(
            [openssl_bin, "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        x509 = subprocess.run(
            [openssl_bin, "x509", "-noout", "-enddate"],
            input=s_client.stdout,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    m = _CERT_DATE_RE.search(x509.stdout or "")
    if not m:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %e %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(m.group(1).strip(), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def inspect_tls(
    host: str,
    *,
    port: int = 443,
    timeout: int = 60,
    sslscan_bin: str | None = None,
    openssl_bin: str | None = None,
) -> TlsReport:
    """Run sslscan + cert-date probe against *host* and normalize."""
    scan_bin = sslscan_bin or resolve_tool("sslscan", "AETHEROPS_TOOL_SSLSCAN")
    ossl_bin = openssl_bin or resolve_tool("openssl", "AETHEROPS_TOOL_OPENSSL")
    if not scan_bin:
        raise FileNotFoundError("sslscan not found (set AETHEROPS_TOOL_SSLSCAN)")

    try:
        proc = subprocess.run(
            [scan_bin, "--no-colour", f"{host}:{port}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        text = proc.stdout or ""
    except subprocess.TimeoutExpired:
        text = ""

    enabled, heartbleed = _parse_sslscan(text)
    legacy = bool(_LEGACY.intersection(enabled))

    not_after = None
    if ossl_bin:
        not_after = _cert_not_after(host, port, ossl_bin, min(timeout, 20))

    days_left = None
    expired = False
    if not_after is not None:
        delta = not_after - datetime.now(UTC)
        days_left = delta.days
        expired = delta.total_seconds() <= 0

    return TlsReport(
        host=host,
        protocols_enabled=enabled,
        legacy_enabled=legacy,
        heartbleed=heartbleed,
        cert_not_after=not_after,
        cert_expired=expired,
        days_left=days_left,
        raw_summary=text[:400],
    )
