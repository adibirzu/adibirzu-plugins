from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Any

import yaml

from aetherops.airlock.egress import EgressDenied
from aetherops.config import ROOT, Settings
from aetherops.harness.observation import err, ok, warn
from aetherops.mcp.router import McpRouter
from aetherops.scope.gate import authorize, load_engagement_or_deny
from aetherops.scope.verbs import DENY_SUBSTRINGS, EXPLOITATION_TOOL_NAMES
from aetherops.types import Observation


@dataclass(frozen=True)
class AdapterSpec:
    name: str
    kind: str
    side: str
    airgap_ok: bool
    internet_required: bool
    notes: str
    repo: str = ""
    command: str | None = None
    package: str | None = None
    allow: tuple[str, ...] = ()


def load_catalog(path: Path) -> tuple[list[str], list[AdapterSpec]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    deny = list(raw.get("deny_patterns", []))
    specs = []
    for name, item in (raw.get("adapters") or {}).items():
        specs.append(
            AdapterSpec(
                name=name,
                kind=item.get("kind", "local_cli"),
                side=item.get("side", "purple"),
                airgap_ok=bool(item.get("airgap_ok", True)),
                internet_required=bool(item.get("internet_required", False)),
                notes=item.get("notes", ""),
                repo=item.get("repo", ""),
                command=item.get("command"),
                package=item.get("package"),
                allow=tuple(item.get("allow") or ()),
            )
        )
    return deny, specs


class AdapterRegistry:
    def __init__(
        self,
        settings: Settings,
        router: McpRouter | None = None,
        scanner_runner: Callable[[str, str, dict[str, Any] | None], Any] | None = None,
    ):
        self.settings = settings
        self.deny, self.specs = load_catalog(settings.adapters_file)
        self.by_name = {s.name: s for s in self.specs}
        self.router = router or McpRouter(settings)
        self.scanner_runner = scanner_runner or getattr(self.router, "scanner_runner", None)

    def inventory(self) -> Observation:
        rows = []
        for spec in self.specs:
            present = self._present(spec)
            rows.append(
                {
                    "name": spec.name,
                    "side": spec.side,
                    "kind": spec.kind,
                    "present": present,
                    "airgap_ok": spec.airgap_ok,
                    "notes": spec.notes,
                }
            )
        return ok(
            f"{len(rows)} adapters registered (wrappers only, no exploit generation)",
            data={"adapters": rows},
            next_actions=["Run aetherops doctor", "Load an engagement file before live use"],
        )

    def _present(self, spec: AdapterSpec) -> bool:
        if spec.name == "hexstrike":
            if not (self.settings.hexstrike_path and Path(self.settings.hexstrike_path).exists()):
                return False
            return self.router.is_server_present("hexstrike-lab", timeout=1.0)
        if spec.name == "mcp":
            return bool(self.settings.mcp_file and Path(self.settings.mcp_file).exists())
        if spec.name == "tempest":
            from aetherops.adapters.tempest import adjacent_tree_present

            return adjacent_tree_present(self.settings.tempest_path)
        if spec.name == "lab_target":
            from aetherops.adapters.lab_target import adjacent_tree_present

            return adjacent_tree_present(self.settings.dvllm_path)
        if spec.name == "redamon":
            return bool(self.settings.redamon_path and Path(self.settings.redamon_path).exists())
        if spec.name == "strix":
            return which("strix") is not None
        if spec.command:
            return which(spec.command) is not None
        if spec.package:
            try:
                __import__(spec.package)
                return True
            except (AttributeError, ImportError):
                return False
        if spec.name in {
            "offsec",
            "completeness",
            "remote_exec",
            "exploit_dev",
            "plan",
            "pack",
            "estate",
            "library",
            "whw",
            "prompt_hacking",
            "ha_catalog",
            "landscape",
        }:
            return True
        return spec.kind in {"knowledge", "local_cli", "mcp_catalog", "local_pipeline"}

    def run(
        self,
        name: str,
        verb: str = "inventory",
        target: str | None = None,
        live: bool = False,
        arguments: dict[str, Any] | None = None,
    ) -> Observation:
        engagement, load_err = load_engagement_or_deny(self.settings.engagement_file)

        def _audit(obs: Observation, allowed: bool) -> Observation:
            if engagement is not None:
                self.router.audit(
                    engagement,
                    tool=f"{name}.{verb}",
                    verb=verb,
                    target=target,
                    live=live,
                    arguments=arguments,
                    allowed=allowed,
                    status=obs.status,
                    summary=obs.summary,
                    root_cause_hint=obs.root_cause_hint,
                    stop_condition=obs.stop_condition,
                )
            return obs

        spec = self.by_name.get(name)
        if spec is None:
            return _audit(
                err(
                    f"Unknown adapter: {name}",
                    retry="Use aetherops adapters to list names.",
                    stop_condition="SCOPE DENIED. Do not invent adapter names.",
                ),
                allowed=False,
            )
        lowered = f"{name}.{verb}".lower()
        catalogued = name == "exploit_dev" or lowered in EXPLOITATION_TOOL_NAMES
        if not catalogued and any(tok in lowered for tok in DENY_SUBSTRINGS + tuple(self.deny)):
            return _audit(
                err(
                    "Denied: exploit/payload/exfil verbs are not available.",
                    stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
                ),
                allowed=False,
            )
        # The landscape is a checked-in catalog.  Its read-only verbs neither
        # address a target nor execute a tool, so an ROE cannot add protection
        # here.  Keep its local inventory usable before an engagement is
        # configured, while retaining the normal gate for every live or
        # target-bearing adapter path.
        if name == "landscape" and not live and target is None:
            from aetherops.adapters.landscape import run_landscape_adapter

            return _audit(run_landscape_adapter(verb, arguments=arguments), allowed=True)
        if load_err or engagement is None:
            return load_err or err(
                "SCOPE DENIED: engagement file unreadable.",
                stop_condition="SCOPE DENIED. Do not retry without a readable signed engagement.",
            )
        blocked = authorize(
            tool=f"{name}.{verb}",
            verb=verb,
            target=target,
            engagement=engagement,
            airgap=self.settings.airgap,
            internet_required=spec.internet_required,
            live=live,
            arguments=arguments,
        )
        if blocked:
            if spec.name == "strix":
                data = dict(blocked.data or {})
                data["executed"] = False
                data["scope_refused"] = True
                blocked = blocked.model_copy(update={"data": data})
            return _audit(blocked, allowed=False)
        if spec.name == "hexstrike" and verb == "health":
            return _audit(self._hexstrike_health(), allowed=True)
        if spec.name == "hexstrike" and verb == "inventory":
            return _audit(self._hexstrike_inventory(spec.allow), allowed=True)
        if spec.name == "strix":
            from aetherops.adapters.strix import strix_inventory, strix_scan_plan

            if verb in {"health", "inventory"}:
                return _audit(
                    strix_inventory(mcp_config=self.settings.strix_mcp_file), allowed=True
                )
            if verb == "plan":
                if not (target or "").strip():
                    return _audit(
                        err(
                            "Strix plan requires an explicit in-scope target.",
                            data={"executed": False},
                            stop_condition="Do not construct a targetless autonomous scan.",
                        ),
                        allowed=False,
                    )
                return _audit(
                    strix_scan_plan(target=target, mcp_config=self.settings.strix_mcp_file),
                    allowed=True,
                )
            return _audit(
                err(
                    "Strix supports inventory and plan only; scan execution stays operator-gated.",
                    data={"executed": False},
                    stop_condition="Do not use AetherOps to launch autonomous Strix scans.",
                ),
                allowed=False,
            )
        if spec.name == "mcp":
            from aetherops.adapters.mcp import inventory_mcp, plan_mcp_call

            if verb in {"inventory", "health"}:
                return _audit(inventory_mcp(self.settings.mcp_file), allowed=True)
            if not live:
                return _audit(
                    plan_mcp_call(
                        verb=verb,
                        engagement=engagement,
                        target=target,
                        live=live,
                        airgap=self.settings.airgap,
                        arguments=arguments,
                        catalog_path=self.settings.mcp_file,
                    ),
                    allowed=True,
                )
            from aetherops.adapters.scanners import execute_live_scanner

            obs = execute_live_scanner(
                adapter=spec.name,
                verb=verb,
                target=target,
                engagement=engagement,
                vault_dir=self.settings.vault_dir,
                airgap=self.settings.airgap,
                arguments=arguments,
                runner=self.scanner_runner or getattr(self.router, "scanner_runner", None),
                http_client=getattr(self.router, "_http_client", None),
                hexstrike_url=self.settings.get_hexstrike_url(),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "pack":
            from aetherops.packs.runner import run_pack

            return _audit(
                run_pack(
                    verb,
                    engagement=engagement,
                    target=target,
                    live=live,
                    airgap=self.settings.airgap,
                ),
                allowed=True,
            )
        if spec.name == "estate":
            from aetherops.adapters.estate import run_estate_adapter

            obs = run_estate_adapter(
                verb=verb,
                target=target,
                live=live,
                engagement=engagement,
                arguments=arguments,
                router=self.router,
                eval_runner=getattr(self, "eval_runner", None),
                settings=self.settings,
                vault_dir=self.settings.vault_dir,
                reports_dir=self.settings.reports_dir,
                engagement_file=self.settings.engagement_file,
                workspace=ROOT,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "plan":
            from aetherops.adapters.plan import run_plan_adapter

            obs = run_plan_adapter(
                verb=verb,
                engagement=engagement,
                inventory=self.inventory().data,
                vault_dir=self.settings.vault_dir,
                arguments=arguments,
                adapters_file=self.settings.adapters_file,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "offsec":
            from aetherops.adapters.offsec import run_offsec_adapter

            obs = run_offsec_adapter(
                verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
                runner=getattr(self, "offsec_runner", None),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "remote_exec":
            from aetherops.adapters.remote_exec import run_remote_exec

            extra = None
            if arguments:
                raw = arguments.get("argv") or arguments.get("extra")
                if isinstance(raw, list):
                    extra = [str(x) for x in raw]
            binary = verb if verb not in {"inventory", "health"} else str((arguments or {}).get("binary") or "nmap")
            obs = run_remote_exec(
                engagement=engagement,
                binary=binary,
                extra=extra,
                live=live,
                transport=getattr(self, "remote_transport", None),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "completeness":
            from aetherops.airlock.vault import index_vault
            from aetherops.scope.completeness import check_completeness

            obs = check_completeness(
                engagement,
                index_vault(self.settings.vault_dir),
                self.inventory().data,
            )
            return _audit(obs, allowed=True)
        if spec.name == "whw":
            from aetherops.adapters.whw import run_whw_adapter

            obs = run_whw_adapter(
                verb,
                engagement=engagement,
                vault_dir=self.settings.vault_dir,
                arguments=arguments,
                live=live,
                target=target,
                llm_chat=getattr(self, "llm_chat", None),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "exploit_dev":
            from aetherops.adapters.exploit_dev import run_exploit_dev_adapter

            obs = run_exploit_dev_adapter(
                verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
                vault_dir=self.settings.vault_dir,
                llm_chat=getattr(self, "llm_chat", None),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "library":
            from aetherops.adapters.cyber_library import run_library_adapter

            obs = run_library_adapter(
                verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "prompt_hacking":
            from aetherops.adapters.prompt_hacking import run_prompt_hacking_adapter

            obs = run_prompt_hacking_adapter(
                verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "ha_catalog":
            from aetherops.adapters.hackagent_catalog import run_ha_catalog_adapter

            obs = run_ha_catalog_adapter(
                verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "tempest":
            from aetherops.adapters.tempest import run_tempest_adapter

            obs = run_tempest_adapter(
                verb=verb,
                engagement=engagement,
                target=target,
                live=live,
                airgap=self.settings.airgap,
                arguments=arguments,
                tempest_path=self.settings.tempest_path,
                allowlist=spec.allow or None,
                deny_patterns=self.deny,
                router=self.router,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name == "lab_target":
            from aetherops.adapters.lab_target import run_lab_target_adapter

            obs = run_lab_target_adapter(
                verb=verb,
                engagement=engagement,
                target=target,
                live=live,
                arguments=arguments,
                dvllm_path=self.settings.dvllm_path,
                probe_runner=getattr(self, "eval_runner", None),
                vault_dir=self.settings.vault_dir,
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.name in {"hexstrike", "mcp"} and verb in {
            "amass_scan",
            "subfinder_scan",
            "gobuster_scan",
            "nikto_scan",
        }:
            from aetherops.adapters.mcp import plan_mcp_call

            return _audit(
                plan_mcp_call(
                    verb=verb,
                    engagement=engagement,
                    target=target,
                    live=live,
                    airgap=self.settings.airgap,
                    arguments=arguments,
                    catalog_path=self.settings.mcp_file,
                ),
                allowed=True,
            )
        if (spec.name in {"hexstrike", "mcp"} and verb in {
            "nmap_scan",
            "nuclei_scan",
            "trivy_scan",
            "checkov_iac_scan",
            "prowler_scan",
        }) or (spec.name == "nessus" and verb not in {"health", "inventory"}):
            if not live:
                from aetherops.adapters.mcp import plan_mcp_call

                return _audit(
                    plan_mcp_call(
                        verb=verb,
                        engagement=engagement,
                        target=target,
                        live=live,
                        airgap=self.settings.airgap,
                        arguments=arguments,
                        catalog_path=self.settings.mcp_file,
                        nessus=spec.name == "nessus",
                    ),
                    allowed=True,
                )
            from aetherops.adapters.scanners import execute_live_scanner

            obs = execute_live_scanner(
                adapter=spec.name,
                verb=verb,
                target=target,
                engagement=engagement,
                vault_dir=self.settings.vault_dir,
                airgap=self.settings.airgap,
                arguments=arguments,
                runner=self.scanner_runner or getattr(self.router, "scanner_runner", None),
                http_client=getattr(self.router, "_http_client", None),
                hexstrike_url=self.settings.get_hexstrike_url(),
            )
            is_allowed = obs.status != "error" or not (obs.data or {}).get("scope_refused", False)
            return _audit(obs, allowed=is_allowed)
        if spec.kind == "knowledge":
            return _audit(
                ok(
                    f"{name} is a local knowledge pack, not a live attack tool",
                    next_actions=["Load the matching skill from skills/"],
                ),
                allowed=True,
            )
        if not live:
            return _audit(
                ok(
                    f"{name} ready as a local wrapper ({spec.kind}). Live run requires allow_live_tools.",
                    data={"verb": verb, "present": self._present(spec), "allow": list(spec.allow)},
                    next_actions=["Keep air-gap on", "Point only at authorized scope"],
                ),
                allowed=True,
            )
        return _audit(
            warn(
                f"{name}.{verb} live path is a thin wrapper around an already-installed tool; not implemented as a generator.",
                retry="Install the upstream CLI locally, then re-run with --live after ROE.",
                stop_condition="Do not invent payloads if the upstream tool is missing.",
            ),
            allowed=True,
        )

    def _hexstrike_http_client(self):
        return getattr(self.router, "_http_client", None)

    def _probe_hexstrike_identity(self):
        from aetherops.adapters.hexforge import probe_hexstrike_identity

        return probe_hexstrike_identity(
            self.settings.get_hexstrike_url(),
            timeout=3.0,
            client=self._hexstrike_http_client(),
        )

    def _hexstrike_health(self) -> Observation:
        from aetherops.adapters.hexforge import denied_non_loopback, observation_from_probe

        try:
            identity = self._probe_hexstrike_identity()
        except EgressDenied as exc:
            return denied_non_loopback(self.settings.get_hexstrike_url(), exc)
        return observation_from_probe(identity, local_path=self.settings.hexstrike_path)

    def _hexstrike_inventory(self, allow: tuple[str, ...]) -> Observation:
        from aetherops.adapters.hexforge import HEXFORGE_ENGINE, denied_non_loopback

        try:
            identity = self._probe_hexstrike_identity()
        except EgressDenied as exc:
            return denied_non_loopback(self.settings.get_hexstrike_url(), exc)
        obs = self.router.inventory_hexstrike(allow, deny_patterns=self.deny)
        data = {**obs.data, **identity.as_data()}
        summary = obs.summary
        if identity.engine == HEXFORGE_ENGINE:
            summary = f"HexForge {identity.version}: {obs.summary}"
        return obs.model_copy(update={"data": data, "summary": summary})
