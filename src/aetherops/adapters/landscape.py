"""Landscape catalog adapter — inventory / gap / map. No packets."""

from __future__ import annotations

from typing import Any

from aetherops.harness.observation import err, ok
from aetherops.landscape.catalog import category_gap, load_catalog, missing_capabilities
from aetherops.scope.verbs import extra_arg_keys
from aetherops.types import Observation

LANDSCAPE_VERBS = frozenset({"inventory", "health", "gap", "map", "show"})


def run_landscape_adapter(
    verb: str = "inventory",
    *,
    arguments: dict[str, Any] | None = None,
) -> Observation:
    """Readonly catalog/gap verbs. Never executes a scanner or exploit."""
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )

    action = (verb or "inventory").strip().lower()
    if action not in LANDSCAPE_VERBS:
        return err(
            f"Unknown landscape verb: {verb}",
            stop_condition="Use landscape inventory, gap, map, or show.",
            data={"scope_refused": True, "executed": False},
        )

    catalog = load_catalog()
    provenance = dict(catalog.get("provenance") or {})
    counts = dict(catalog.get("counts") or {})
    tools = list(catalog.get("tools") or [])
    gaps = missing_capabilities()
    cats = category_gap(catalog)

    if action in {"inventory", "health"}:
        return ok(
            f"StationX landscape catalog: {counts.get('tools', len(tools))} tools "
            f"across {counts.get('categories', len(cats))} categories "
            f"(captured {provenance.get('captured', 'unknown')}).",
            data={
                "provenance": provenance,
                "counts": counts,
                "categories": cats,
                "shipped_gaps": gaps["shipped"],
                "needs_decision": [row["id"] for row in gaps["needs_decision"]],
                "executed": False,
            },
            next_actions=[
                "Run landscape.gap for the missing-capabilities list",
                "Do not vendor commercial products from the catalog",
            ],
        )

    if action == "gap":
        missing_oss = [t["name"] for t in tools if t.get("aetherops_status") == "missing-oss"]
        commercial = [t["name"] for t in tools if t.get("aetherops_status") == "commercial"]
        return ok(
            f"Landscape gap: {len(gaps['shipped'])} capabilities wired this PR; "
            f"{len(gaps['needs_decision'])} follow-ups need a product decision; "
            f"{len(missing_oss)} unmapped OSS tools remain catalogued.",
            data={
                "shipped": gaps["shipped"],
                "needs_decision": gaps["needs_decision"],
                "categories": cats,
                "missing_oss_count": len(missing_oss),
                "commercial_count": len(commercial),
                "executed": False,
            },
            next_actions=[
                "Wire only OSS tools that fit the scope/ROE gate",
                "Leave needs-decision rows for a captain call",
            ],
        )

    if action == "map":
        wired = [
            {
                "name": t["name"],
                "category": t.get("category"),
                "surface": t.get("aetherops_surface"),
                "status": t.get("aetherops_status"),
            }
            for t in tools
            if t.get("aetherops_status") in {"wired", "catalogued"}
        ]
        return ok(
            f"{len(wired)} landscape tools already mapped onto AetherOps adapters/skills.",
            data={"mapped": wired, "executed": False},
            next_actions=["Use landscape.gap for what is still missing"],
        )

    # show — compact catalog by category
    by_cat: dict[str, list[str]] = {}
    for t in tools:
        by_cat.setdefault(str(t.get("category") or "unknown"), []).append(str(t.get("name")))
    return ok(
        f"Landscape show: {len(tools)} tools in {len(by_cat)} categories.",
        data={"by_category": by_cat, "provenance": provenance, "executed": False},
        next_actions=["Read docs/ai-security-tool-landscape.md for URLs and descriptions"],
    )
