"""Readonly WebHackersWeapons technique adapter. Never dispatches a scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aetherops.harness.observation import err, ok
from aetherops.plan.whw import coverage, draft_weapon, list_weapons, load_whw_pack, next_technique
from aetherops.scope.verbs import extra_arg_keys
from aetherops.types import Engagement, Observation


def run_whw_adapter(
    verb: str = "coverage",
    *,
    engagement: Engagement,
    vault_index: dict[str, Any] | None = None,
    vault_dir: Path | None = None,
    arguments: dict[str, Any] | None = None,
    live: bool = False,
    llm_chat: Any | None = None,
    target: str | None = None,
) -> Observation:
    extra = extra_arg_keys(arguments)
    if extra:
        return err(
            f"Denied: unexpected tool arguments (fail closed): {', '.join(extra)}",
            stop_condition="Do not retry with extra arguments. Advertised keys only.",
            data={"scope_refused": True, "extra_keys": list(extra), "executed": False},
        )
    if live:
        return err(
            "SCOPE DENIED: whw never live-dispatches weapons.",
            stop_condition="Use whw.weapons / whw.draft (gated, words only) or pack.web.",
            data={"scope_refused": True, "executed": False, "live": True},
        )
    action = (verb or "coverage").strip().lower()
    if action in {"inventory", "health"}:
        from aetherops.knowledge.whw_names import inventory_pin

        rows = load_whw_pack()
        pin = inventory_pin()
        pin_data = pin.data or {}
        return ok(
            "WebHackersWeapons technique catalog (offline, readonly).",
            data={
                "adapter": "whw",
                "verb": action,
                "count": len(rows),
                "ids": [row.technique_id for row in rows],
                "allow": [row.technique_id for row in rows if row.policy == "allow"],
                "gated": [row.technique_id for row in rows if row.policy == "gated"],
                "deny": [row.technique_id for row in rows if row.policy == "deny"],
                "executed": False,
                "readonly": True,
                "llm_invoked": False,
                "present": pin_data.get("present"),
                "commit": pin_data.get("commit"),
                "index_commit": pin_data.get("index_commit"),
                "expected_commit": pin_data.get("expected_commit"),
                "upstream_yaml_count": pin_data.get("upstream_yaml_count"),
                "name_index": pin_data.get("counts"),
                "runtime_fetch": False,
                "body_vendored": False,
            },
            next_actions=["Call whw.coverage, whw.next, or whw.weapons"],
        )
    index = vault_index
    if index is None and vault_dir is not None:
        from aetherops.airlock.vault import index_vault

        index = index_vault(vault_dir)
    if action == "coverage":
        return coverage(engagement, index)
    if action == "next":
        return next_technique(engagement, index)
    if action == "weapons":
        return list_weapons(engagement)
    if action == "draft":
        args = arguments or {}
        weapon = str(args.get("weapon") or args.get("binary") or "").strip() or None
        issue_class = str(args.get("issue_class") or "").strip() or None
        return draft_weapon(
            engagement,
            weapon=weapon,
            target=target,
            issue_class=issue_class,
            vault_dir=vault_dir,
            llm_chat=llm_chat,
        )
    return err(
        "SCOPE DENIED: whw adapter verbs are coverage/next/weapons/draft/inventory/health.",
        stop_condition="Use whw.weapons or whw.draft. Do not live-dispatch a WHW binary.",
        data={"scope_refused": True, "executed": False, "verb": action},
    )
