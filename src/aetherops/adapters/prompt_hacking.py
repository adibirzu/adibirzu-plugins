"""Planning-only adapter for the pinned Prompt-Hacking-Resources catalog.

Inventory / search / show are citation frontmatter only. Load returns a
citation card. Jailbreak-body / L1B3RT4S-class corpora are dual_use:
unsigned load is SCOPE DENIED. Run never fetches corpora or writes vault/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aetherops.harness.observation import err
from aetherops.knowledge.prompt_hacking import (
    inventory_catalog,
    load_catalog,
    run_catalog,
    search_catalog,
    show_catalog,
)
from aetherops.types import Engagement, Observation

ALLOWLISTED_VERBS = frozenset({"health", "inventory", "search", "show", "load", "run", "pin"})


def run_prompt_hacking_adapter(
    verb: str,
    *,
    engagement: Engagement,
    target: str | None = None,
    live: bool = False,
    arguments: dict[str, Any] | None = None,
    catalog_root: Path | None = None,
) -> Observation:
    action = (verb or "inventory").strip().lower()
    args = arguments or {}
    if action not in ALLOWLISTED_VERBS:
        return err(
            f"Unknown prompt_hacking verb: {verb}",
            retry="Use inventory, search, show, load, or run.",
            stop_condition="SCOPE DENIED. Do not invent catalog verbs.",
            data={"adapter": "prompt_hacking", "verb": verb, "executed": False, "scope_refused": True},
        )
    if action in {"health", "inventory", "pin"}:
        return inventory_catalog(catalog_root)
    query = str(args.get("query") or "").strip()
    skill = str(args.get("skill") or "").strip()
    if action == "search":
        if not query:
            return err(
                "prompt_hacking.search requires a query",
                retry="Pass query= in arguments (not a payload key).",
                data={"adapter": "prompt_hacking", "executed": False},
            )
        limit_raw = args.get("limit") or 8
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            limit = 8
        return search_catalog(query, root=catalog_root, limit=limit)
    name = skill or query
    if action == "show":
        if not name:
            return err(
                "prompt_hacking.show requires skill=",
                data={"adapter": "prompt_hacking", "executed": False},
            )
        return show_catalog(name, root=catalog_root)
    if action == "load":
        if not name:
            return err(
                "prompt_hacking.load requires skill=",
                data={"adapter": "prompt_hacking", "executed": False},
            )
        return load_catalog(name, engagement=engagement, root=catalog_root)
    if not name:
        return err(
            "prompt_hacking.run requires skill=",
            data={"adapter": "prompt_hacking", "executed": False, "scope_refused": True},
        )
    return run_catalog(
        name,
        engagement=engagement,
        target=target,
        live=live,
        root=catalog_root,
    )
