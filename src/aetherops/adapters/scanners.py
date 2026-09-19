"""Live allowlisted scanner wrappers and output normalizers.

Implements real execution and normalization for allowlisted assessment tools:
- nmap_scan: port & service discovery (T1046)
- nuclei_scan: vulnerability detection with local templates only (T1595.002)
- trivy_scan: container/IaC/fs vulnerability & misconfig scanner (T1195.001)
- checkov_iac_scan: static IaC & K8s policy compliance (T1580)
- prowler_scan: CIS/cloud configuration assessment (T1580/T1526, airgap-stopped for public cloud)
- nessus: host-only lab scanner (T1595.002, requires nessuscli + signed engagement)

Air-gap safety:
- Never fetches CVE advisories or NVD feeds over internet on an engagement host.
- Never downloads or updates Nuclei templates when airgap is true.
- Never downloads Trivy vulnerability DB when airgap is true.
- Prowler public cloud access is blocked when airgap is true.
- All observations land in vault/ as structured JSON with raw excerpt + normalized fields.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from typing import Any

import httpx

from aetherops.adapters.hexstrike_contract import hexstrike_route_for
from aetherops.airlock.egress import EgressDenied, EgressSession
from aetherops.airlock.vault import store
from aetherops.harness.observation import err, ok, warn
from aetherops.types import Engagement, Observation

ALLOWLISTED_SCANNER_VERBS = frozenset(
    {
        "nmap_scan",
        "nuclei_scan",
        "trivy_scan",
        "checkov_iac_scan",
        "prowler_scan",
        "nessus_scan",
        "nessus",
    }
)

VERB_TECHNIQUES: dict[str, str] = {
    "nmap_scan": "T1046",
    "nuclei_scan": "T1595.002",
    "trivy_scan": "T1195.001",
    "checkov_iac_scan": "T1580",
    "prowler_scan": "T1580",
    "nessus_scan": "T1595.002",
    "nessus": "T1595.002",
}


def parse_nmap_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[int], list[dict[str, Any]]]:
    """Parse nmap output into raw excerpt, port list, and normalized services."""
    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or raw.get("output") or json.dumps(raw))[:2000]
        ports = [int(p) for p in raw.get("ports", []) if str(p).isdigit()]
        services = list(raw.get("services", []))
        if not ports and services:
            ports = [int(s["port"]) for s in services if "port" in s and str(s["port"]).isdigit()]
        return raw_excerpt, sorted(set(ports)), services

    text = str(raw)
    raw_excerpt = text[:2000]
    ports: list[int] = []
    services: list[dict[str, Any]] = []

    # Match lines like: 22/tcp open ssh OpenSSH 8.9p1
    pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        port_num = int(match.group(1))
        protocol = match.group(2).lower()
        state = match.group(3).lower()
        service_name = match.group(4)
        version_info = (match.group(5) or "").strip()

        if "open" in state:
            ports.append(port_num)

        services.append(
            {
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": version_info,
            }
        )

    return raw_excerpt, sorted(set(ports)), services


def parse_nuclei_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Parse nuclei output into raw excerpt and normalized findings."""
    if isinstance(raw, list):
        raw_excerpt = json.dumps(raw)[:2000]
        return raw_excerpt, [dict(item) for item in raw if isinstance(item, dict)]

    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or json.dumps(raw))[:2000]
        findings = list(raw.get("findings", []))
        return raw_excerpt, findings

    text = str(raw)
    raw_excerpt = text[:2000]
    findings: list[dict[str, Any]] = []

    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
                info = obj.get("info") or {}
                cls_info = info.get("classification") or {}
                cve_id = cls_info.get("cve-id")
                if isinstance(cve_id, list) and cve_id:
                    cve_str = str(cve_id[0])
                else:
                    cve_str = str(cve_id) if cve_id else None

                findings.append(
                    {
                        "template_id": obj.get("template-id") or obj.get("templateID") or "unknown",
                        "name": info.get("name") or obj.get("template-id") or "unknown",
                        "severity": (info.get("severity") or "info").lower(),
                        "matched_at": obj.get("matched-at") or obj.get("matched") or obj.get("host") or "",
                        "cve": cve_str,
                        "type": obj.get("type") or "http",
                    }
                )
                continue
            except (json.JSONDecodeError, TypeError):
                pass

        # Text line format: [template-id] [type] [severity] url
        match = re.match(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", line)
        if match:
            findings.append(
                {
                    "template_id": match.group(1),
                    "name": match.group(1),
                    "type": match.group(2),
                    "severity": match.group(3).lower(),
                    "matched_at": match.group(4),
                    "cve": None,
                }
            )

    return raw_excerpt, findings


def parse_trivy_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Parse trivy output into raw excerpt and normalized vulnerabilities."""
    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or json.dumps(raw))[:2000]
        if "vulnerabilities" in raw:
            return raw_excerpt, list(raw["vulnerabilities"])
        vulns: list[dict[str, Any]] = []
        for res in raw.get("Results", []):
            for v in res.get("Vulnerabilities", []):
                vulns.append(
                    {
                        "vulnerability_id": v.get("VulnerabilityID", "unknown"),
                        "package": v.get("PkgName", "unknown"),
                        "installed_version": v.get("InstalledVersion", ""),
                        "fixed_version": v.get("FixedVersion", ""),
                        "severity": (v.get("Severity") or "unknown").upper(),
                        "title": v.get("Title", ""),
                    }
                )
        return raw_excerpt, vulns

    text = str(raw)
    raw_excerpt = text[:2000]
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return parse_trivy_output(data)
    except (json.JSONDecodeError, TypeError):
        pass

    vulns = []
    # Text line pattern for CVE
    pattern = re.compile(
        r"(CVE-\d{4}-\d+)\s+([A-Z]+)\s+(\S+)\s+(\S+)(?:\s+->\s+(\S+))?\s*(.*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        vulns.append(
            {
                "vulnerability_id": match.group(1),
                "severity": match.group(2),
                "package": match.group(3),
                "installed_version": match.group(4),
                "fixed_version": match.group(5) or "",
                "title": (match.group(6) or "").strip(),
            }
        )

    return raw_excerpt, vulns


def parse_checkov_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Parse checkov output into raw excerpt and normalized checks."""
    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or json.dumps(raw))[:2000]
        if "failed_checks" in raw or "checks" in raw:
            return raw_excerpt, list(raw.get("failed_checks") or raw.get("checks") or [])
        checks: list[dict[str, Any]] = []
        res = raw.get("results") or {}
        for check in res.get("failed_checks", []):
            checks.append(
                {
                    "check_id": check.get("check_id", "unknown"),
                    "check_name": check.get("check_name", ""),
                    "resource": check.get("resource", ""),
                    "file_path": check.get("file_path", ""),
                    "severity": (check.get("severity") or "MEDIUM").upper(),
                    "status": "FAILED",
                }
            )
        return raw_excerpt, checks

    text = str(raw)
    raw_excerpt = text[:2000]
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return parse_checkov_output(data)
    except (json.JSONDecodeError, TypeError):
        pass

    checks = []
    pattern = re.compile(
        r"Check:\s+(CKV_\S+):\s+\"([^\"]+)\".*?FAILED for resource:\s+(\S+)",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        checks.append(
            {
                "check_id": match.group(1),
                "check_name": match.group(2),
                "resource": match.group(3),
                "status": "FAILED",
                "severity": "MEDIUM",
            }
        )

    return raw_excerpt, checks


def parse_prowler_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Parse prowler output into raw excerpt and normalized findings."""
    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or json.dumps(raw))[:2000]
        return raw_excerpt, list(raw.get("findings", []))
    if isinstance(raw, list):
        raw_excerpt = json.dumps(raw)[:2000]
        return raw_excerpt, [dict(item) for item in raw if isinstance(item, dict)]

    text = str(raw)
    raw_excerpt = text[:2000]
    findings = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            findings.append(
                {
                    "check_id": obj.get("CheckID") or obj.get("check_id") or "unknown",
                    "service": obj.get("ServiceName") or obj.get("service") or "",
                    "status": (obj.get("Status") or obj.get("status") or "FAIL").upper(),
                    "severity": (obj.get("Severity") or obj.get("severity") or "medium").lower(),
                    "resource_id": obj.get("ResourceID") or obj.get("resource_id") or "",
                }
            )
        except (json.JSONDecodeError, TypeError):
            pass
    return raw_excerpt, findings


def parse_nessus_output(
    raw: str | dict[str, Any] | list[Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Parse nessus output into raw excerpt and normalized findings."""
    if isinstance(raw, dict):
        raw_excerpt = str(raw.get("raw_excerpt") or json.dumps(raw))[:2000]
        return raw_excerpt, list(raw.get("findings", []))

    text = str(raw)
    raw_excerpt = text[:2000]
    findings = []
    for line in text.strip().splitlines():
        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) >= 3:
            findings.append(
                {
                    "host": parts[0],
                    "plugin_name": parts[1],
                    "severity": parts[2].lower(),
                    "cve": parts[3] if len(parts) > 3 else None,
                }
            )
    return raw_excerpt, findings


def execute_live_scanner(
    *,
    adapter: str = "hexstrike",
    verb: str,
    target: str | None,
    engagement: Engagement,
    vault_dir: Path,
    airgap: bool = True,
    arguments: dict[str, Any] | None = None,
    runner: Callable[[str, str, dict[str, Any] | None], Any] | None = None,
    http_client: httpx.Client | None = None,
    hexstrike_url: str = "http://127.0.0.1:8888",
) -> Observation:
    """Execute one allowlisted live scanner behind the gate and store observation in vault."""
    action = (verb or "").strip().lower()
    resolved_adapter = adapter.lower() if adapter else ("nessus" if action in {"nessus", "nessus_scan"} else "hexstrike")

    if resolved_adapter == "nessus":
        cli_present = which("nessuscli") is not None
        if not cli_present and runner is None:
            return err(
                "STOP live-unwired: Nessus live scan is not implemented.",
                root_cause_hint="nessuscli is not present on this host.",
                stop_condition="STOP live-unwired. Lab CLI nessuscli is not present on this host.",
                data={"scope_refused": True, "executed": False, "adapter": "nessus", "verb": action},
            )

    if action not in ALLOWLISTED_SCANNER_VERBS and resolved_adapter != "nessus":
        return err(
            f"Denied: {action} is not an allowlisted scanner verb.",
            stop_condition="Use nmap_scan/nuclei_scan/trivy_scan/checkov_iac_scan/prowler_scan only.",
            data={"scope_refused": True, "verb": action, "executed": False},
        )

    if not target:
        return err(
            f"SCOPE DENIED: {action} requires an explicit in-scope target.",
            stop_condition="SCOPE DENIED. Do not retry without an in-scope target.",
            data={"scope_refused": True, "verb": action, "executed": False},
        )

    # Air-gap checks per scanner
    if action == "prowler_scan" and airgap:
        return err(
            "SCOPE DENIED: Prowler cloud scan blocked by air-gap.",
            root_cause_hint="Prowler requires public cloud API egress which is blocked under airgap: true.",
            stop_condition="STOP airgap-cloud-refused. Cloud APIs are blocked in air-gap mode.",
            data={"scope_refused": True, "airgap": True, "verb": action, "target": target, "executed": False},
        )

    if action == "nuclei_scan" and airgap:
        args = arguments or {}
        if any(k in args for k in ("update", "update_templates", "download", "download_templates")) or any(
            isinstance(v, str) and ("update" in v or "download" in v) for v in args.values()
        ):
            return err(
                "Air-gap mode: internet-required action refused (nuclei template update blocked).",
                root_cause_hint="Nuclei template update from internet is forbidden under air-gap.",
                stop_condition="Do not update templates from internet on an engagement host.",
                data={"scope_refused": True, "airgap": True, "verb": action, "target": target, "executed": False},
            )

    if action == "trivy_scan" and airgap:
        args = arguments or {}
        if any(k in args for k in ("download_db", "update", "download")) or any(
            isinstance(v, str) and ("download-db" in v or "update" in v) for v in args.values()
        ):
            return err(
                "Air-gap mode: internet-required action refused (trivy DB update blocked).",
                root_cause_hint="Trivy DB update from internet is forbidden under air-gap.",
                stop_condition="Do not download vulnerability DB from internet on an engagement host.",
                data={"scope_refused": True, "airgap": True, "verb": action, "target": target, "executed": False},
            )

    if adapter == "nessus":
        cli_present = which("nessuscli") is not None
        if not cli_present and runner is None:
            return err(
                "STOP live-unwired: Nessus live scan is not implemented.",
                root_cause_hint="nessuscli is not present on this host.",
                stop_condition="STOP live-unwired. Lab CLI nessuscli is not present on this host.",
                data={"scope_refused": True, "executed": False, "adapter": "nessus", "verb": action},
            )

    # Run the scanner
    raw_output: Any = ""
    evidence_ids: list[str] = []
    if runner is not None:
        try:
            raw_output = runner(action, target, arguments)
        except (RuntimeError, ValueError, TypeError, OSError) as exc:
            return err(
                f"Live scanner {action} execution failed: {exc}",
                root_cause_hint=str(exc),
                stop_condition="Verify scanner runner configuration.",
                data={"executed": False, "verb": action, "target": target},
            )
    else:
        # Try HexStrike HTTP API if configured and reachable.
        # Verb ≠ Flask route: nmap_scan posts /api/tools/nmap (PRD-E).
        base_url = hexstrike_url.rstrip("/")
        route = hexstrike_route_for(action)
        ran_http = False

        if route and (http_client is not None or _check_port_open(base_url)):
            url = base_url + route
            try:
                payload = {"target": target, "arguments": arguments or {}}
                with EgressSession(timeout=10.0, client=http_client) as client:
                    resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    raw_output = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
                    ran_http = True
            except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError):
                ran_http = False

        if not ran_http:
            local = _run_declared_cli(
                action=action,
                target=target,
                engagement=engagement,
                vault_dir=vault_dir,
                adapter=resolved_adapter,
            )
            if local is None:
                cli_name = "nmap" if action == "nmap_scan" else action.split("_")[0]
                return warn(
                    f"Live scanner {action} is not installed locally and HexStrike server is unreachable.",
                    root_cause_hint=f"Neither declared toolchain binary nor HexStrike API at {base_url} is available.",
                    retry=f"Start HexStrike or pin {cli_name} in configs/toolchain.yaml.",
                    stop_condition="Do not invent scanner results when the tool is missing.",
                    data={"executed": False, "verb": action, "target": target},
                )
            if isinstance(local, Observation):
                return local
            raw_output, evidence_ids = local

    # Normalize output based on verb
    ports: list[int] = []
    services: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    technique = VERB_TECHNIQUES.get(action, "unknown")
    raw_excerpt = ""

    if action == "nmap_scan":
        raw_excerpt, ports, services = parse_nmap_output(raw_output)
        desc = f"{len(ports)} open port(s) discovered"
    elif action == "nuclei_scan":
        raw_excerpt, findings = parse_nuclei_output(raw_output)
        desc = f"{len(findings)} vulnerability finding(s)"
    elif action == "trivy_scan":
        raw_excerpt, findings = parse_trivy_output(raw_output)
        desc = f"{len(findings)} supply-chain finding(s)"
    elif action == "checkov_iac_scan":
        raw_excerpt, findings = parse_checkov_output(raw_output)
        desc = f"{len(findings)} IaC misconfiguration(s)"
    elif action == "prowler_scan":
        raw_excerpt, findings = parse_prowler_output(raw_output)
        desc = f"{len(findings)} cloud posture finding(s)"
    elif adapter == "nessus":
        raw_excerpt, findings = parse_nessus_output(raw_output)
        desc = f"{len(findings)} Nessus finding(s)"
    else:
        raw_excerpt = str(raw_output)[:2000]
        desc = "Scan completed"

    # Store observation in vault
    slug = target.replace("/", "_").replace(":", "_").replace(".", "_")
    summary_text = f"{action} on {target}: {desc}."
    payload = {
        "kind": "finding",
        "evidence_status": "potential",
        "status": "Potential",
        "asset": target,
        "target": target,
        "observation": summary_text,
        "engagement_id": engagement.engagement_id,
        "adapter": adapter,
        "verb": action,
        "timestamp": datetime.now(UTC).isoformat(),
        "technique": technique,
        "raw_excerpt": raw_excerpt,
        "ports": ports,
        "services": services,
        "findings": findings,
        "executed": True,
        "airgap": airgap,
        "evidence_ids": evidence_ids,
    }
    vault_path = store(vault_dir, f"observation-{action}-{slug}", payload)

    return ok(
        summary_text + " (Potential finding saved to vault).",
        artifacts=[str(vault_path)],
        data={
            "kind": "finding",
            "evidence_status": "potential",
            "status": "Potential",
            "asset": target,
            "target": target,
            "observation": summary_text,
            "engagement_id": engagement.engagement_id,
            "adapter": adapter,
            "verb": action,
            "technique": technique,
            "raw_excerpt": raw_excerpt,
            "ports": ports,
            "services": services,
            "findings": findings,
            "executed": True,
            "vault_path": str(vault_path),
            "evidence_ids": evidence_ids,
        },
        next_actions=[
            "Pair red finding with purple-feedback before report",
            "Keep findings in vault/",
        ],
    )


_VERB_TO_DECLARED: dict[str, tuple[str, list[str]]] = {
    "nmap_scan": ("nmap", ["-sV", "-Pn"]),
    "nuclei_scan": ("nuclei", ["-target", "{target}", "-offline", "-no-update-templates"]),
    "trivy_scan": ("trivy", ["fs", "--offline-scan", "--format", "json", "{target}"]),
    "checkov_iac_scan": ("checkov", ["-d", "{target}"]),
    "prowler_scan": ("prowler", ["--compliance", "cis"]),
    "nessus_scan": ("nessus", ["scan", "{target}"]),
    "nessus": ("nessus", ["scan", "{target}"]),
}


def _run_declared_cli(
    *,
    action: str,
    target: str,
    engagement: Engagement,
    vault_dir: Path,
    adapter: str,
) -> tuple[str, list[str]] | Observation | None:
    """Run the local CLI through the deterministic wrapper. No ambient PATH exec."""
    from aetherops.evidence.run_ledger import RunLedger
    from aetherops.tooling.wrapper import DeterministicToolRunner, ScopeRefused, ToolchainDrift

    mapping = _VERB_TO_DECLARED.get(action)
    if mapping is None and adapter == "nessus":
        mapping = _VERB_TO_DECLARED["nessus"]
    if mapping is None:
        return None
    tool_name, extra_template = mapping
    extra = [target if part == "{target}" else part for part in extra_template]
    if tool_name == "nmap":
        extra = extra + [target]
    try:
        runner = DeterministicToolRunner(engagement=engagement, workdir=vault_dir)
        result = runner.run(tool_name, extra, target=target, cwd=vault_dir)
    except ScopeRefused as exc:
        return err(
            f"SCOPE DENIED: {exc.reason}",
            stop_condition="SCOPE DENIED. Do not retry out-of-scope targets.",
            data={"scope_refused": True, "target": exc.target, "executed": False, "verb": action},
        )
    except (ToolchainDrift, KeyError, TimeoutError, OSError):
        return None
    ledger = RunLedger(vault_dir / "run-ledger.jsonl", artifacts_dir=vault_dir / "tool-artifacts")
    record = ledger.append_result(result)
    return result.normalized, [record.evidence_id]


def _check_port_open(url: str) -> bool:
    try:
        with EgressSession(timeout=1.0) as client:
            resp = client.get(url + "/health")
            return resp.status_code == 200
    except (EgressDenied, httpx.HTTPError, OSError, ValueError, TypeError):
        return False
