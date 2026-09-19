"""DNS reconnaissance wrapper used by black-box engagements.

Runs ``dig`` against a fixed record-type battery and returns normalized
records. The dig binary resolves via ``AETHEROPS_TOOL_DIG`` then PATH.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from shutil import which

DEFAULT_DKIM_SELECTORS = ("default", "zoho", "google", "selector1", "selector2")


@dataclass(frozen=True)
class DnsRecords:
    """Normalized DNS record battery for one domain."""

    domain: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    txt: tuple[str, ...] = ()
    caa: tuple[str, ...] = ()
    soa: tuple[str, ...] = ()
    dmarc: tuple[str, ...] = ()
    dkim: dict[str, str] = field(default_factory=dict)

    @property
    def has_dmarc(self) -> bool:
        return any(rec.startswith("v=DMARC1") for rec in self.dmarc)

    @property
    def spf_record(self) -> str | None:
        for rec in self.txt:
            if rec.startswith("v=spf1"):
                return rec
        return None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "a": list(self.a),
            "aaaa": list(self.aaaa),
            "ns": list(self.ns),
            "mx": list(self.mx),
            "txt": list(self.txt),
            "caa": list(self.caa),
            "soa": list(self.soa),
            "dmarc": list(self.dmarc),
            "dkim": dict(self.dkim),
            "has_dmarc": self.has_dmarc,
            "spf_record": self.spf_record,
        }


def resolve_tool(name: str, env_key: str) -> str | None:
    """Resolve a binary via its AETHEROPS_TOOL_* env var, then PATH."""
    env_path = os.environ.get(env_key)
    if env_path and Path(env_path).exists():
        return env_path
    return which(name)


def _dig(dig_bin: str, query: str, resolver: str, timeout: int) -> tuple[str, ...]:
    try:
        proc = subprocess.run(
            [dig_bin, "+short", query, f"@{resolver}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ()
    lines = [ln.strip().rstrip(".") for ln in (proc.stdout or "").splitlines()]
    return tuple(sorted({ln for ln in lines if ln}))


def run_dns_recon(
    domain: str,
    *,
    resolver: str = "1.1.1.1",
    dkim_selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS,
    timeout: int = 10,
    dig_bin: str | None = None,
) -> DnsRecords:
    """Collect the standard record battery for *domain*."""
    bin_ = dig_bin or resolve_tool("dig", "AETHEROPS_TOOL_DIG")
    if not bin_:
        raise FileNotFoundError("dig not found (set AETHEROPS_TOOL_DIG)")

    def q(name: str) -> tuple[str, ...]:
        return _dig(bin_, f"{name}", resolver, timeout)

    dmarc = _dig(bin_, f"_dmarc.{domain} TXT", resolver, timeout)

    dkim: dict[str, str] = {}
    for sel in dkim_selectors:
        recs = _dig(bin_, f"{sel}._domainkey.{domain} TXT", resolver, timeout)
        if recs:
            dkim[sel] = " ".join(recs)[:200]

    return DnsRecords(
        domain=domain,
        a=q(f"{domain} A"),
        aaaa=q(f"{domain} AAAA"),
        ns=q(f"{domain} NS"),
        mx=q(f"{domain} MX"),
        txt=q(f"{domain} TXT"),
        caa=q(f"{domain} CAA"),
        soa=q(f"{domain} SOA"),
        dmarc=dmarc,
        dkim=dkim,
    )
