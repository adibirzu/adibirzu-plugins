"""Deterministic pentest tool wrappers with scope enforcement and evidence ledger.

Usage::

    from aetherops.tooling import DeterministicTool, ScopeGuard, EvidenceLedger

    guard = ScopeGuard(engagement)
    guard.assert_in_scope("10.0.0.1")  # raises ScopeViolation if denied

    tool = DeterministicTool.for_binary("nmap")
    result = tool.run("10.0.0.1", extra=["-sV", "-T4"])

    ledger = EvidenceLedger("/path/to/ledger.jsonl")
    ledger.record(result)

A second surface ships alongside the field-proven recon helpers: the
manifest-pinned ``DeterministicToolRunner`` (CP-10). Every external
scanner invocation goes through it, resolving binaries from
``configs/toolchain.yaml``, freezing argv/env, forcing non-interactive
flags, applying timeouts, normalizing output, and logging full argv +
cwd + input-hash into the run-evidence ledger.
"""

from aetherops.tooling.deterministic import (
    DeterministicTool,
    ToolResult,
    ToolRunError,
)
from aetherops.tooling.dns_recon import DnsRecords, run_dns_recon
from aetherops.tooling.evidence import EvidenceLedger, EvidenceRecord
from aetherops.tooling.manifest import ToolchainManifest, ToolSpec, load_manifest
from aetherops.tooling.scope_guard import ScopeGuard, ScopeViolation
from aetherops.tooling.subdomain_enum import SubdomainResult, enumerate_subdomains
from aetherops.tooling.tls_inspect import TlsReport, inspect_tls
from aetherops.tooling.web_fingerprint import HeaderAudit, audit_headers
from aetherops.tooling.wrapper import (
    DeterministicToolRunner,
    ScopeRefused,
    ToolchainDrift,
    ToolNotDeclared,
    invocation_log,
)
from aetherops.tooling.wrapper import (
    ToolResult as ManifestToolResult,
)

__all__ = [
    "DeterministicTool",
    "DeterministicToolRunner",
    "DnsRecords",
    "EvidenceLedger",
    "EvidenceRecord",
    "HeaderAudit",
    "ManifestToolResult",
    "ScopeGuard",
    "ScopeRefused",
    "ScopeViolation",
    "SubdomainResult",
    "TlsReport",
    "ToolNotDeclared",
    "ToolResult",
    "ToolRunError",
    "ToolSpec",
    "ToolchainDrift",
    "ToolchainManifest",
    "audit_headers",
    "enumerate_subdomains",
    "inspect_tls",
    "invocation_log",
    "load_manifest",
    "run_dns_recon",
]