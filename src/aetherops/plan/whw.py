"""Deterministic WebHackersWeapons technique planner.

Reads the in-tree pack (types/tags only). Never vendors weapon YAML,
never calls the LLM, never emits deny/exploit/payload rows as next.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from aetherops.config import ROOT
from aetherops.harness.observation import err, ok
from aetherops.plan.stages import is_signed, window_active
from aetherops.scope.verbs import is_exploit_dev, is_permanent_deny
from aetherops.types import Engagement, Observation

PACK_FILE = ROOT / "knowledge" / "packs" / "web-hackers-weapons.md"
WEAPONS_FILE = ROOT / "knowledge" / "packs" / "web-hackers-weapons-exploit.md"
KNOWN_ID_RE = re.compile(r"^WHW\.[A-Z0-9]+(?:\.[A-Z0-9]+)?$")
Policy = Literal["allow", "plan", "deny", "gated"]


@dataclass(frozen=True)
class TechniqueRow:
    technique_id: str
    title: str
    whw_type: str
    tags: tuple[str, ...]
    attck: str
    policy: Policy
    adapter: str
    verb: str
    internet: bool
    match_tokens: tuple[str, ...]


@dataclass(frozen=True)
class WeaponRow:
    weapon_id: str
    name: str
    whw_type: str
    tags: tuple[str, ...]
    attck: str
    policy: Policy
    proof_verb: str
    url: str


def _split_cells(line: str) -> list[str]:
    raw = line.strip().removeprefix("|").removesuffix("|")
    return [c.strip() for c in raw.split("|")]


def _is_separator(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in cells if c)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip().lower() for part in value.split(",") if part.strip())


def _policy(value: str) -> Policy:
    token = (value or "").strip().lower()
    if token in {"allow", "plan", "deny", "gated"}:
        return token  # type: ignore[return-value]
    return "deny"


def can_draft_gated(engagement: Engagement, *, today: str | None = None) -> bool:
    """True only for captain-signed L3 with allow_exploit_dev + validation_target."""
    return (
        is_signed(engagement)
        and window_active(engagement, today=today)
        and bool(engagement.allow_exploit_dev)
        and int(engagement.autonomy_level or 0) >= 3
        and bool(engagement.validation_target)
    )


def load_whw_pack(path: Path | None = None) -> tuple[TechniqueRow, ...]:
    """Parse the offline WHW technique table. Unknown IDs become unknown."""
    text = (path or PACK_FILE).read_text(encoding="utf-8")
    rows: list[TechniqueRow] = []
    headers: list[str] | None = None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = _split_cells(line)
        if not cells:
            continue
        if headers is None:
            headers = [re.sub(r"[^a-z0-9]+", " ", h.lower()).strip() for h in cells]
            continue
        if _is_separator(cells):
            continue
        idx = {name: i for i, name in enumerate(headers)}

        def cell(*names: str, default: str = "", _idx=idx, _cells=cells) -> str:
            for name in names:
                if name in _idx and _idx[name] < len(_cells):
                    return _cells[_idx[name]]
            return default

        raw_id = cell("id")
        technique_id = raw_id if KNOWN_ID_RE.fullmatch(raw_id) else "unknown"
        adapter = cell("adapter").lower()
        verb = cell("verb").lower()
        policy = _policy(cell("policy"))
        if policy == "allow" and (not adapter or not verb):
            policy = "plan"
        if adapter and (is_permanent_deny(adapter) or is_permanent_deny(verb)) or policy == "allow" and is_exploit_dev(verb):
            policy = "deny"
            adapter, verb = "", ""
        if policy == "gated" and (not adapter or not verb):
            adapter, verb = "exploit_dev", "draft"
        internet = cell("internet").lower() in {"yes", "true", "y", "1"}
        rows.append(
            TechniqueRow(
                technique_id=technique_id,
                title=cell("title"),
                whw_type=cell("whw type", "type"),
                tags=_csv(cell("whw tags", "tags")),
                attck=cell("att ck", "attck") or "unknown",
                policy=policy,
                adapter=adapter,
                verb=verb,
                internet=internet,
                match_tokens=_csv(cell("match tokens")),
            )
        )
    return tuple(rows)


def _weapon_from_pin(rec: Any) -> WeaponRow:
    return WeaponRow(
        weapon_id=rec.weapon_id,
        name=rec.name,
        whw_type=rec.whw_type,
        tags=rec.tags,
        attck=rec.attck or "unknown",
        policy=_policy(rec.policy),
        proof_verb=rec.proof_verb if rec.policy == "gated" else "",
        url=rec.url,
    )


def load_whw_weapons(
    path: Path | None = None,
    *,
    pin_root: Path | None = None,
) -> tuple[WeaponRow, ...]:
    """Parse the gated exploit/payload weapon table, then leftover pin names.

    The PR 34 markdown table is unchanged. Matching names keep those rows.
    Extra Exploit/payload-class names come from the pinned index when present.
    """
    from aetherops.scope.verbs import EXPLOITATION_TOOL_NAMES

    text = (path or WEAPONS_FILE).read_text(encoding="utf-8")
    rows: list[WeaponRow] = []
    headers: list[str] | None = None
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = _split_cells(line)
        if not cells:
            continue
        if headers is None:
            headers = [re.sub(r"[^a-z0-9]+", " ", h.lower()).strip() for h in cells]
            continue
        if _is_separator(cells):
            continue
        idx = {name: i for i, name in enumerate(headers)}

        def cell(*names: str, default: str = "", _idx=idx, _cells=cells) -> str:
            for name in names:
                if name in _idx and _idx[name] < len(_cells):
                    return _cells[_idx[name]]
            return default

        raw_id = cell("id")
        weapon_id = raw_id if KNOWN_ID_RE.fullmatch(raw_id) else "unknown"
        policy = _policy(cell("policy"))
        proof = cell("proof verb", "proof").strip().lower()
        if policy == "gated" and proof not in EXPLOITATION_TOOL_NAMES:
            policy = "deny"
            proof = ""
        if policy == "deny":
            proof = ""
        url = cell("url")
        if url and not url.startswith("https://"):
            url = ""
        rows.append(
            WeaponRow(
                weapon_id=weapon_id,
                name=cell("name"),
                whw_type=cell("whw type", "type"),
                tags=_csv(cell("whw tags", "tags")),
                attck=cell("att ck", "attck") or "unknown",
                policy=policy,
                proof_verb=proof,
                url=url,
            )
        )
    merge_pin = pin_root is not None or path is None or Path(path) == WEAPONS_FILE
    if merge_pin:
        from aetherops.knowledge.whw_names import load_index

        seen_names = {row.name.lower() for row in rows}
        seen_ids = {row.weapon_id for row in rows}
        for rec in load_index(pin_root):
            if rec.name.lower() in seen_names or rec.weapon_id in seen_ids:
                continue
            extra = _weapon_from_pin(rec)
            if extra.weapon_id == "unknown":
                continue
            rows.append(extra)
            seen_names.add(extra.name.lower())
            seen_ids.add(extra.weapon_id)
    return tuple(rows)


def lookup_weapon(weapon_id: str, rows: tuple[WeaponRow, ...] | None = None) -> WeaponRow | None:
    wanted = (weapon_id or "").strip()
    if not wanted or wanted.lower() == "unknown":
        return None
    needle = wanted.lower()
    for row in rows or load_whw_weapons():
        if row.weapon_id == wanted or row.name.lower() == needle:
            return row
    return None


def list_weapons(
    engagement: Engagement,
    *,
    today: str | None = None,
    rows: tuple[WeaponRow, ...] | None = None,
) -> Observation:
    catalog = rows or load_whw_weapons()
    draftable = can_draft_gated(engagement, today=today)
    table = [
        {
            "id": row.weapon_id,
            "name": row.name,
            "type": row.whw_type,
            "tags": list(row.tags),
            "attck": row.attck,
            "policy": row.policy,
            "proof_verb": row.proof_verb or None,
            "url": row.url or None,
            "executed": False,
            "draftable": bool(draftable and row.policy == "gated" and row.proof_verb),
        }
        for row in catalog
        if row.weapon_id != "unknown"
    ]
    return ok(
        "WebHackersWeapons exploit/payload weapons (names only, readonly).",
        data={
            "adapter": "whw",
            "verb": "weapons",
            "count": len(table),
            "gated": [row["id"] for row in table if row["policy"] == "gated"],
            "deny": [row["id"] for row in table if row["policy"] == "deny"],
            "weapons": table,
            "executed": False,
            "readonly": True,
            "llm_invoked": False,
            "draftable": draftable,
        },
        next_actions=[
            "Unsigned: inventory only",
            "Signed L3: whw.draft with weapon=<id> (words-only proof verb)",
        ],
    )


def draft_weapon(
    engagement: Engagement,
    *,
    weapon: str | None,
    target: str | None = None,
    issue_class: str | None = None,
    vault_dir: Path | None = None,
    llm_chat: Any | None = None,
    today: str | None = None,
    rows: tuple[WeaponRow, ...] | None = None,
) -> Observation:
    """Route a gated weapon to exploit_dev/proof.* words-only draft. Never live."""
    from aetherops.scope.exploitation import request_exploitation

    row = lookup_weapon(weapon or "", rows=rows)
    if row is None:
        return err(
            "SCOPE DENIED: unknown WHW weapon id.",
            stop_condition="Use whw.weapons. Do not invent a weapon or payload.",
            data={"scope_refused": True, "executed": False, "weapon": weapon, "capability": False},
        )
    if row.policy != "gated" or not row.proof_verb:
        return err(
            f"Denied: {row.weapon_id} is not a gated demonstration weapon.",
            stop_condition="Do not retry denied tools. C2/reverse-shell/brute stay refused.",
            data={
                "scope_refused": True,
                "executed": False,
                "weapon": row.weapon_id,
                "policy": row.policy,
                "capability": False,
            },
        )
    dest = target or engagement.validation_target
    return request_exploitation(
        tool=row.proof_verb,
        target=dest,
        engagement=engagement,
        airgap=bool(engagement.airgap),
        live=False,
        issue_class=issue_class or row.attck,
        vault_dir=vault_dir,
        llm_chat=llm_chat,
        finding={"name": row.name, "weapon_id": row.weapon_id, "issue_class": row.attck},
    )


def lookup(technique_id: str, rows: tuple[TechniqueRow, ...] | None = None) -> TechniqueRow | None:
    wanted = (technique_id or "").strip()
    if not wanted or wanted.lower() == "unknown":
        return None
    for row in rows or load_whw_pack():
        if row.technique_id == wanted:
            return row
    return None


def _completed_verbs(vault_index: dict[str, Any] | None) -> set[str]:
    idx = vault_index or {}
    done: set[str] = set()
    for item in idx.get("completed_stages") or []:
        text = str(item).strip().lower()
        if text:
            done.add(text)
    for finding in idx.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        adapter = str(finding.get("adapter") or "").strip().lower()
        verb = str(finding.get("verb") or "").strip().lower()
        if adapter and verb:
            done.add(f"{adapter}.{verb}")
        technique = str(finding.get("technique") or "").strip()
        if technique:
            done.add(technique.lower())
    return done


def _callable(row: TechniqueRow, *, airgap: bool) -> bool:
    if row.policy != "allow":
        return False
    if airgap and row.internet:
        return False
    if not row.adapter or not row.verb:
        return False
    return not (
        is_permanent_deny(row.adapter)
        or is_permanent_deny(row.verb)
        or is_exploit_dev(row.verb)
    )


def coverage(
    engagement: Engagement,
    vault_index: dict[str, Any] | None = None,
    *,
    today: str | None = None,
    rows: tuple[TechniqueRow, ...] | None = None,
) -> Observation:
    """Readonly coverage matrix. Never claims clean on an unsigned file."""
    catalog = rows or load_whw_pack()
    done = _completed_verbs(vault_index)
    signed = is_signed(engagement) and window_active(engagement, today=today)
    airgap = bool(engagement.airgap)
    table: list[dict[str, Any]] = []
    for row in catalog:
        key = f"{row.adapter}.{row.verb}" if row.adapter and row.verb else ""
        covered = bool(key and key in done) or row.technique_id.lower() in done or row.attck.lower() in done
        if row.policy == "deny" or (airgap and row.internet):
            status = "denied"
        elif row.policy == "gated":
            status = "gated" if can_draft_gated(engagement, today=today) else "gated-blocked"
        elif not signed:
            status = "gap"
        elif covered:
            status = "met"
        elif row.policy == "plan":
            status = "plan"
        else:
            status = "gap"
        table.append(
            {
                "id": row.technique_id,
                "title": row.title,
                "policy": row.policy,
                "attck": row.attck,
                "adapter": key or None,
                "status": status,
                "internet": row.internet,
            }
        )
    next_row = None
    if signed:
        for row in catalog:
            key = f"{row.adapter}.{row.verb}"
            if _callable(row, airgap=airgap) and key not in done and row.attck.lower() not in done:
                next_row = key
                break
    nxt = next_row or "STOP"
    return ok(
        "WebHackersWeapons technique coverage (deterministic, readonly).",
        data={
            "adapter": "whw",
            "verb": "coverage",
            "rows": table,
            "next": nxt,
            "executed": False,
            "readonly": True,
            "llm_invoked": False,
            "signed": signed,
        },
        next_actions=["Call whw.next for the next allowlisted adapter.verb or STOP"],
    )


def next_technique(
    engagement: Engagement,
    vault_index: dict[str, Any] | None = None,
    *,
    today: str | None = None,
    rows: tuple[TechniqueRow, ...] | None = None,
) -> Observation:
    """Pure next allowlisted adapter.verb or STOP. No LLM."""
    matrix = coverage(engagement, vault_index, today=today, rows=rows)
    nxt = str((matrix.data or {}).get("next") or "STOP")
    if nxt == "STOP":
        return ok(
            "WHW planner STOP (no remaining allowlisted technique, or unsigned).",
            data={
                "adapter": "whw",
                "verb": "next",
                "next": "STOP",
                "executed": False,
                "readonly": True,
                "llm_invoked": False,
            },
            next_actions=["Pair findings with purple-feedback or stop"],
        )
    adapter, _, verb = nxt.partition(".")
    return ok(
        f"WHW next: {nxt}",
        data={
            "adapter": "whw",
            "verb": "next",
            "next": nxt,
            "next_adapter": adapter,
            "next_verb": verb,
            "executed": False,
            "readonly": True,
            "llm_invoked": False,
        },
        next_actions=[f"Run {nxt} only if authorize() allows it"],
    )
