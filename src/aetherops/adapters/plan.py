"""Readonly plan.next adapter. Orchestration only; never dispatches a scan."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aetherops.adapters.base import load_catalog
from aetherops.config import Settings
from aetherops.harness.observation import err, ok
from aetherops.plan.stages import IN_TREE_ADAPTERS, STAGES, next_stage
from aetherops.scope.verbs import extra_arg_keys
from aetherops.types import Engagement, Observation


def catalog_inventory(
    adapters_file: Path | None = None,
    *,
    presence: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Local catalog rows with allow lists. No network."""
    path = adapters_file or Settings().adapters_file
    _deny, specs = load_catalog(path)
    rows: list[dict[str, Any]] = []
    for spec in specs:
        if presence is not None and spec.name in presence:
            present = bool(presence[spec.name])
        else:
            present = spec.name in IN_TREE_ADAPTERS or spec.kind in {
                "knowledge",
                "local_pipeline",
                "mcp_catalog",
            }
        rows.append(
            {
                "name": spec.name,
                "side": spec.side,
                "kind": spec.kind,
                "present": present,
                "airgap_ok": spec.airgap_ok,
                "internet_required": spec.internet_required,
                "allow": list(spec.allow),
                "notes": spec.notes,
            }
        )
    return {"adapters": rows, "path": str(path), "executed": False}


def merge_inventory(
    runtime: dict[str, Any] | None,
    catalog: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Overlay runtime presence onto catalog allow lists."""
    base = catalog or catalog_inventory()
    by_name = {str(row["name"]): dict(row) for row in base.get("adapters") or []}
    for row in (runtime or {}).get("adapters") or []:
        if not isinstance(row, dict) or not row.get("name"):
            continue
        name = str(row["name"])
        current = by_name.get(name, {"name": name, "allow": []})
        if "present" in row:
            current["present"] = bool(row["present"])
        if row.get("allow"):
            current["allow"] = list(row["allow"])
        by_name[name] = current
    return {"adapters": list(by_name.values()), "executed": False}


def run_plan_adapter(
    verb: str = "next",
    *,
    engagement: Engagement,
    inventory: dict[str, Any] | None = None,
    vault_index: dict[str, Any] | None = None,
    vault_dir: Path | None = None,
    arguments: dict[str, Any] | None = None,
    adapters_file: Path | None = None,
) -> Observation:
    """Readonly planner. `next` is the only computing verb."""
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments. Advertised keys only.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )

    action = (verb or "next").strip().lower()
    catalog = catalog_inventory(adapters_file)
    merged = merge_inventory(inventory, catalog)

    if action in {"inventory", "health"}:
        stages = [
            {
                "id": stage.id,
                "name": stage.name,
                "adapter": stage.adapter,
                "verb": stage.verb,
                "live": stage.live,
            }
            for stage in STAGES
        ]
        return ok(
            "Deterministic assessment-stage planner (readonly).",
            data={
                "adapter": "plan",
                "verb": action,
                "stages": stages,
                "executed": False,
                "readonly": True,
            },
            next_actions=["Call plan.next against a loaded engagement"],
        )

    if action != "next":
        return err(
            "SCOPE DENIED: plan adapter is readonly (next/inventory/health).",
            stop_condition="Use plan.next only. Do not invent planner verbs.",
            data={"scope_refused": True, "executed": False, "verb": action},
        )

    index = vault_index
    if index is None and vault_dir is not None:
        from aetherops.airlock.vault import index_vault

        index = index_vault(vault_dir)
    if index is None:
        index = {}

    return next_stage(engagement, merged, index)
