"""Planning-only adapter for the pinned Anthropic Cybersecurity Skills snapshot.

Inventory / search / show are frontmatter-only. Load returns a bounded playbook
body. Run never executes upstream scripts; unsigned dual-use and every
permanent-deny live path return SCOPE DENIED.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aetherops.harness.observation import err
from aetherops.knowledge.cyber_library import (
    inventory_library,
    load_library,
    run_library,
    search_library,
    show_library,
)
from aetherops.types import Engagement, Observation

ALLOWLISTED_VERBS = frozenset({"health", "inventory", "search", "show", "load", "run", "pin"})


def run_library_adapter(
    verb: str,
    *,
    engagement: Engagement,
    target: str | None = None,
    live: bool = False,
    arguments: dict[str, Any] | None = None,
    library_root: Path | None = None,
) -> Observation:
    action = (verb or "inventory").strip().lower()
    args = arguments or {}
    if action not in ALLOWLISTED_VERBS:
        return err(
            f"Unknown library verb: {verb}",
            retry="Use inventory, search, show, load, or run.",
            stop_condition="SCOPE DENIED. Do not invent library verbs.",
            data={"adapter": "library", "verb": verb, "executed": False, "scope_refused": True},
        )
    if action in {"health", "inventory", "pin"}:
        return inventory_library(library_root)
    query = str(args.get("query") or target or "").strip()
    skill = str(args.get("skill") or args.get("name") or "").strip()
    if action == "search":
        if not query:
            return err(
                "library.search requires a query",
                retry="Pass query= in arguments (not a payload key).",
                data={"adapter": "library", "executed": False},
            )
        limit_raw = args.get("limit") or 8
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            limit = 8
        return search_library(query, root=library_root, limit=limit)
    name = skill or query
    if action == "show":
        if not name:
            return err(
                "library.show requires skill=",
                data={"adapter": "library", "executed": False},
            )
        return show_library(name, root=library_root)
    if action == "load":
        if not name:
            return err(
                "library.load requires skill=",
                data={"adapter": "library", "executed": False},
            )
        budget_raw = args.get("limit") or 4000
        try:
            budget = int(budget_raw)
        except (TypeError, ValueError):
            budget = 4000
        return load_library(name, engagement=engagement, root=library_root, budget=budget)
    if not name:
        return err(
            "library.run requires skill=",
            data={"adapter": "library", "executed": False, "scope_refused": True},
        )
    return run_library(
        name,
        engagement=engagement,
        target=target,
        live=live,
        root=library_root,
    )
