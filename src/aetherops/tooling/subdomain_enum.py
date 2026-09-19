"""Passive subdomain enumeration orchestration.

Chains subfinder + assetfinder (discovery) and dnsx (resolution), the
exact pipeline proven in the field. Every binary resolves via
``AETHEROPS_TOOL_<NAME>`` then PATH; missing tools are skipped with a
recorded note rather than failing the whole run.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from aetherops.tooling.dns_recon import resolve_tool


@dataclass(frozen=True)
class SubdomainResult:
    domain: str
    discovered: tuple[str, ...] = ()
    resolved: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tools_used: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "discovered": list(self.discovered),
            "resolved": {k: list(v) for k, v in self.resolved.items()},
            "tools_used": list(self.tools_used),
            "notes": list(self.notes),
        }


def _run_lines(argv: list[str], timeout: int) -> set[str]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return set()
    return {ln.strip().lower() for ln in (proc.stdout or "").splitlines() if ln.strip()}


def enumerate_subdomains(
    domain: str,
    *,
    resolver: str = "1.1.1.1",
    timeout: int = 120,
    passive_only: bool = True,
) -> SubdomainResult:
    """Discover and resolve *domain*'s subdomains using available tools."""
    found: set[str] = {domain}
    used: list[str] = []
    notes: list[str] = []

    subfinder = resolve_tool("subfinder", "AETHEROPS_TOOL_SUBFINDER")
    if subfinder:
        found |= _run_lines([subfinder, "-d", domain, "-all", "-silent"], timeout)
        used.append("subfinder")
    else:
        notes.append("subfinder unavailable")

    assetfinder = resolve_tool("assetfinder", "AETHEROPS_TOOL_ASSETFINDER")
    if assetfinder:
        found |= _run_lines([assetfinder, "--subs-only", domain], timeout)
        used.append("assetfinder")
    else:
        notes.append("assetfinder unavailable")

    candidates = sorted(
        f for f in found
        if f == domain or f.endswith(f".{domain}")
    )

    resolved: dict[str, tuple[str, ...]] = {}
    dnsx = resolve_tool("dnsx", "AETHEROPS_TOOL_DNSX")
    if dnsx and candidates:
        argv = [dnsx, "-silent", "-a", "-resp", "-r", resolver]
        proc = subprocess.run(
            argv,
            input="\n".join(candidates),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            if "] [A" not in line:
                continue
            head = line.split(" ", 1)[0]
            ips = [tok.strip() for tok in line.split("]")[-1].split() if tok.count(".") >= 3]
            if ips:
                resolved[head.lower()] = tuple(sorted(set(ips)))
        used.append("dnsx")
    elif not dnsx:
        notes.append("dnsx unavailable - resolution skipped")
    elif not passive_only:
        pass

    live = {c for c in candidates if c in resolved}
    return SubdomainResult(
        domain=domain,
        discovered=tuple(live or candidates),
        resolved=resolved,
        tools_used=tuple(used),
        notes=tuple(notes),
    )
