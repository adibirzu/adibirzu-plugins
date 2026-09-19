"""Offline living NIS2 / CRA / AI-Act / DORA / GDPR evidence ledger.

Maps in-memory vault observations onto public-law control IDs shipped in
``knowledge/packs/{nis2,cra,eu-ai-act,dora,gdpr}.md``. Unknown article IDs become
``unknown`` — never invented. Clean-negatives that match a pack row count
as ``met``. CRA Art. 14 is a posture checklist (which vault artifacts
would be attached); this module never opens a notification path.

No sockets, no HTTP client, no evolve, no walk of engagements/ or reports/.
Callers pass observation dicts; this module only reads the in-tree packs.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aetherops.config import ROOT
from aetherops.types import LedgerEntry, LedgerStatus

COMPLIANCE_PACK_FILES = ("nis2.md", "cra.md", "eu-ai-act.md", "dora.md", "gdpr.md")
KNOWN_PACK_ID_RE = re.compile(r"^(NIS2|CRA|AIA|DORA|GDPR)\.(Art|Annex)\.\d+[A-Z]?$")
STATUS_RANK: dict[LedgerStatus, int] = {
    "gap": 3,
    "partial": 2,
    "met": 1,
    "not-applicable": 0,
}
APPENDIX_STATUS = {
    "gap": "Open",
    "partial": "Partial",
    "met": "Met",
    "not-applicable": "N/A",
}


@dataclass(frozen=True)
class ControlRow:
    """One pack table row. Public article/annex number only."""

    control_id: str
    title: str
    evidence_looks_like: str
    satisfied_by: tuple[str, ...] = ()
    match_tokens: tuple[str, ...] = ()
    posture_only: bool = False
    source_pack: str = ""


def _truthy_yes(value: str) -> bool:
    return (value or "").strip().lower() in {"yes", "true", "y", "1", "posture"}


def _split_cells(line: str) -> list[str]:
    raw = line.strip().removeprefix("|").removesuffix("|")
    return [c.strip() for c in raw.split("|")]


def _is_separator(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", c.replace(" ", "")) for c in cells if c)


def _header_index(headers: list[str]) -> dict[str, int]:
    idx: dict[str, int] = {}
    for i, h in enumerate(headers):
        key = re.sub(r"[^a-z0-9]+", " ", h.lower()).strip()
        idx[key] = i
    return idx


def _cell(cells: list[str], headers: dict[str, int], *names: str, default: str = "") -> str:
    for name in names:
        if name in headers and headers[name] < len(cells):
            return cells[headers[name]]
    return default


def _csv_tokens(value: str) -> tuple[str, ...]:
    parts = [p.strip().lower() for p in re.split(r"[,;]", value or "") if p.strip()]
    return tuple(parts)


def parse_pack_markdown(text: str, source_pack: str = "") -> list[ControlRow]:
    """Extract control rows from markdown tables that have an ID column."""
    rows: list[ControlRow] = []
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        if "|" not in lines[i]:
            i += 1
            continue
        header_cells = _split_cells(lines[i])
        headers = _header_index(header_cells)
        if "id" not in headers:
            i += 1
            continue
        i += 1
        if i < len(lines) and _is_separator(_split_cells(lines[i])):
            i += 1
        while i < len(lines) and "|" in lines[i]:
            cells = _split_cells(lines[i])
            i += 1
            if _is_separator(cells) or not any(cells):
                continue
            raw_id = _cell(cells, headers, "id")
            if not raw_id or not KNOWN_PACK_ID_RE.match(raw_id):
                continue
            rows.append(
                ControlRow(
                    control_id=raw_id,
                    title=_cell(cells, headers, "title", "theme"),
                    evidence_looks_like=_cell(
                        cells, headers, "evidence looks like", "evidence"
                    ),
                    satisfied_by=_csv_tokens(_cell(cells, headers, "satisfied by")),
                    match_tokens=_csv_tokens(_cell(cells, headers, "match tokens")),
                    posture_only=_truthy_yes(_cell(cells, headers, "posture only")),
                    source_pack=source_pack,
                )
            )
        continue
    return rows


def load_compliance_packs(packs_dir: Path | None = None) -> list[ControlRow]:
    """Load the five in-tree public-law packs. Missing files are skipped."""
    root = packs_dir or (ROOT / "knowledge" / "packs")
    rows: list[ControlRow] = []
    seen: set[str] = set()
    for name in COMPLIANCE_PACK_FILES:
        path = root / name
        if not path.is_file():
            continue
        for row in parse_pack_markdown(path.read_text(encoding="utf-8"), source_pack=name):
            if row.control_id in seen:
                continue
            seen.add(row.control_id)
            rows.append(row)
    return rows


def known_control_ids(packs: Iterable[ControlRow] | None = None) -> set[str]:
    rows = list(packs) if packs is not None else load_compliance_packs()
    return {r.control_id for r in rows}


def normalize_control_id(value: str | None, known: Iterable[str]) -> str:
    """Return a pack ID or ``unknown``. Never invent an article number."""
    text = (value or "").strip()
    if not text:
        return "unknown"
    if text.lower() in {"unknown", "n/a", "na", "none", "null"}:
        return "unknown"
    known_list = list(known)
    known_map = {k.lower(): k for k in known_list}
    if text in known_map.values() or text in known_list:
        return text if text in known_list else known_map[text.lower()]
    if text.lower() in known_map:
        return known_map[text.lower()]
    compact = re.sub(r"\s+", "", text)
    compact_map = {re.sub(r"\s+", "", k).lower(): k for k in known_list}
    if compact.lower() in compact_map:
        return compact_map[compact.lower()]
    return "unknown"


def _as_dict(obs: Any) -> dict[str, Any]:
    if hasattr(obs, "model_dump"):
        return dict(obs.model_dump())
    return dict(obs or {})


def _is_clean_negative(obs: dict[str, Any]) -> bool:
    kind = str(obs.get("kind") or "").strip().lower()
    status = str(obs.get("status") or "").strip().lower()
    ev = str(obs.get("evidence_status") or "").strip().lower()
    return kind == "clean_negative" or status == "clean-negative" or ev == "clean-negative"


def _requested_ids(obs: dict[str, Any]) -> list[str]:
    collected: list[str] = []
    for key in ("control_ids", "regulatory_ids", "requirement_ids"):
        raw = obs.get(key)
        if isinstance(raw, (list, tuple)):
            collected.extend(str(x) for x in raw if str(x).strip())
    for key in ("control_id", "requirement_id", "regulatory_id"):
        raw = obs.get(key)
        if raw and str(raw).strip():
            collected.append(str(raw).strip())
    seen: set[str] = set()
    out: list[str] = []
    for item in collected:
        token = item.strip()
        if token and token.lower() not in seen:
            seen.add(token.lower())
            out.append(token)
    return out


def _blob(obs: dict[str, Any]) -> str:
    parts = [
        str(obs.get(k) or "")
        for k in (
            "observation",
            "title",
            "check_name",
            "control",
            "domain",
            "technique",
            "adapter",
            "verb",
            "detection_name",
            "remediation",
        )
    ]
    return " ".join(parts).lower()


def _finding_id(obs: dict[str, Any]) -> str:
    fid = str(obs.get("id") or "").strip()
    if fid:
        return fid
    title = str(obs.get("title") or obs.get("check_name") or obs.get("observation") or "").strip()
    return title[:48] if title else "observation"


def observation_hash(obs: dict[str, Any], control_id: str) -> str:
    identity = "|".join(
        [
            str(obs.get("id") or ""),
            str(obs.get("vault_ref") or ""),
            str(obs.get("observation") or obs.get("title") or obs.get("check_name") or ""),
            str(obs.get("asset") or obs.get("target") or ""),
            control_id,
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _status_for(obs: dict[str, Any], row: ControlRow | None) -> LedgerStatus:
    if row is None:
        return "not-applicable"
    if row.posture_only:
        if obs.get("vault_ref"):
            return "met"
        if obs.get("observation") or obs.get("id") or obs.get("title"):
            return "partial"
        return "gap"
    if _is_clean_negative(obs):
        return "met"
    has_control = bool(obs.get("control"))
    pair = obs.get("purple_pair")
    if isinstance(pair, dict) and (pair.get("control") or pair.get("detection")):
        has_control = True
    if has_control:
        return "partial"
    return "gap"


def _matching_rows(
    obs: dict[str, Any], packs: list[ControlRow], known: set[str]
) -> tuple[list[ControlRow], list[str]]:
    """Return (matched pack rows, leftover unknown requested IDs)."""
    requested = _requested_ids(obs)
    unknown_ids: list[str] = []
    matched: list[ControlRow] = []
    seen: set[str] = set()

    if requested:
        by_id = {r.control_id: r for r in packs}
        for raw in requested:
            nid = normalize_control_id(raw, known)
            if nid == "unknown":
                unknown_ids.append(raw)
                continue
            row = by_id.get(nid)
            if row and row.control_id not in seen:
                matched.append(row)
                seen.add(row.control_id)

    blob = _blob(obs)
    tech = str(obs.get("technique") or "").strip().lower()
    for row in packs:
        if row.control_id in seen:
            continue
        if row.match_tokens and any(tok in blob for tok in row.match_tokens):
            matched.append(row)
            seen.add(row.control_id)
            continue
        if tech and tech != "unknown" and tech in blob and tech in " ".join(row.match_tokens):
            matched.append(row)
            seen.add(row.control_id)

    return matched, unknown_ids


def _entry(
    obs: dict[str, Any],
    control_id: str,
    status: LedgerStatus,
    *,
    theme: str = "",
    posture_only: bool = False,
) -> LedgerEntry:
    fid = _finding_id(obs)
    return LedgerEntry(
        control_id=control_id,
        status=status,
        vault_ref=str(obs.get("vault_ref") or "") or None,
        hash=observation_hash(obs, control_id),
        theme=theme,
        finding_ids=[fid] if fid else [],
        posture_only=posture_only,
    )


def map_observation(
    observation: dict[str, Any] | Any,
    packs: list[ControlRow] | None = None,
) -> list[LedgerEntry]:
    """Hash one observation onto ≥1 pack ID, or explicit ``not-applicable``."""
    obs = _as_dict(observation)
    rows = list(packs) if packs is not None else load_compliance_packs()
    known = {r.control_id for r in rows}
    matched, unknown_ids = _matching_rows(obs, rows, known)
    entries: list[LedgerEntry] = []
    entries.extend(
        _entry(obs, "unknown", "not-applicable", theme="unrecognized article ID")
        for _ in unknown_ids
    )
    for row in matched:
        entries.append(
            _entry(
                obs,
                row.control_id,
                _status_for(obs, row),
                theme=row.title,
                posture_only=row.posture_only,
            )
        )
    if not entries:
        entries.append(_entry(obs, "not-applicable", "not-applicable", theme="no pack row matched"))
    return entries


def build_ledger(
    observations: Iterable[dict[str, Any] | Any] | None = None,
    clean_negatives: Iterable[dict[str, Any] | Any] | None = None,
    packs: list[ControlRow] | None = None,
) -> list[LedgerEntry]:
    """Build the run ledger from findings + clean-negatives (in memory)."""
    rows = list(packs) if packs is not None else load_compliance_packs()
    cards: list[dict[str, Any]] = []
    for item in list(observations or []) + list(clean_negatives or []):
        cards.append(_as_dict(item))
    entries: list[LedgerEntry] = []
    seen_hash: set[str] = set()
    for card in cards:
        for entry in map_observation(card, rows):
            if entry.hash in seen_hash:
                continue
            seen_hash.add(entry.hash)
            entries.append(entry)
    return entries


def _worst(statuses: Iterable[LedgerStatus]) -> LedgerStatus:
    worst: LedgerStatus = "not-applicable"
    rank = -1
    for status in statuses:
        if STATUS_RANK.get(status, -1) > rank:
            worst = status
            rank = STATUS_RANK[status]
    return worst


def aggregate_by_control(entries: Iterable[LedgerEntry]) -> list[dict[str, Any]]:
    """One Appendix E row per control ID (worst status wins)."""
    buckets: dict[str, dict[str, Any]] = {}
    for entry in entries:
        bucket = buckets.setdefault(
            entry.control_id,
            {
                "control_id": entry.control_id,
                "theme": entry.theme,
                "finding_ids": [],
                "statuses": [],
                "vault_refs": [],
                "posture_only": entry.posture_only,
            },
        )
        if entry.theme and not bucket["theme"]:
            bucket["theme"] = entry.theme
        for fid in entry.finding_ids:
            if fid not in bucket["finding_ids"]:
                bucket["finding_ids"].append(fid)
        bucket["statuses"].append(entry.status)
        if entry.vault_ref and entry.vault_ref not in bucket["vault_refs"]:
            bucket["vault_refs"].append(entry.vault_ref)
        bucket["posture_only"] = bucket["posture_only"] or entry.posture_only
    aggregated: list[dict[str, Any]] = []
    for control_id, bucket in buckets.items():
        status = _worst(bucket["statuses"])
        aggregated.append(
            {
                "control_id": control_id,
                "theme": bucket["theme"],
                "finding_ids": bucket["finding_ids"],
                "status": status,
                "appendix_status": APPENDIX_STATUS[status],
                "vault_refs": bucket["vault_refs"],
                "posture_only": bucket["posture_only"],
            }
        )
    order = {"gap": 0, "partial": 1, "met": 2, "not-applicable": 3}
    aggregated.sort(key=lambda r: (order.get(r["status"], 9), r["control_id"]))
    return aggregated


def _status_by_control(entries: Iterable[LedgerEntry]) -> dict[str, LedgerStatus]:
    grouped: dict[str, list[LedgerStatus]] = {}
    for entry in entries:
        if entry.control_id in {"unknown", "not-applicable"}:
            continue
        grouped.setdefault(entry.control_id, []).append(entry.status)
    return {cid: _worst(sts) for cid, sts in grouped.items()}


def diff_ledgers(
    ledger_a: Iterable[LedgerEntry],
    ledger_b: Iterable[LedgerEntry],
) -> dict[str, Any]:
    """Compare control status across two runs (not just finding counts)."""
    map_a = _status_by_control(ledger_a)
    map_b = _status_by_control(ledger_b)
    opened: list[dict[str, str]] = []
    closed: list[dict[str, str]] = []
    unchanged: list[dict[str, str]] = []
    changed: list[dict[str, str]] = []

    for cid, status_b in map_b.items():
        if cid not in map_a:
            opened.append({"control_id": cid, "status": status_b})
        elif map_a[cid] == status_b:
            unchanged.append({"control_id": cid, "status": status_b})
        else:
            changed.append(
                {
                    "control_id": cid,
                    "from": map_a[cid],
                    "to": status_b,
                }
            )
    for cid, status_a in map_a.items():
        if cid not in map_b:
            closed.append({"control_id": cid, "status": status_a})

    return {
        "opened": opened,
        "closed": closed,
        "unchanged": unchanged,
        "changed": changed,
        "summary_counts": {
            "opened": len(opened),
            "closed": len(closed),
            "unchanged": len(unchanged),
            "changed": len(changed),
        },
    }


def render_appendix_e(entries: Iterable[LedgerEntry]) -> str:
    rows = aggregate_by_control(entries)
    if not rows:
        return (
            "| Requirement ID | Theme | Related findings | Status |\n"
            "|---|---|---|---|\n"
            "| — | No compliance observations in this run | — | N/A |\n"
        )
    lines = [
        "| Requirement ID | Theme | Related findings | Status |",
        "|---|---|---|---|",
    ]
    for row in rows:
        findings = ", ".join(row["finding_ids"]) or "—"
        theme = row["theme"] or row["control_id"]
        if row["posture_only"]:
            theme = f"{theme} (posture checklist — no notification)"
        lines.append(
            f"| {row['control_id']} | {theme} | {findings} | {row['appendix_status']} |"
        )
    return "\n".join(lines) + "\n"


def render_section15_ledger(
    current: Iterable[LedgerEntry],
    previous: Iterable[LedgerEntry] | None = None,
) -> str:
    """Markdown for §15.3 — control-status ledger / diffs."""
    lines = [
        "## 15.3 Control-status ledger",
        "",
        "Control IDs come from in-tree public-law packs. Unknown article IDs stay `unknown`.",
        "CRA Art. 14 / NIS2 Art. 23 / DORA Art. 19 / GDPR Art. 33-34 rows are posture checklists — no regulator path.",
        "",
    ]
    current_rows = aggregate_by_control(current)
    if previous is None:
        lines += [
            "| Control ID | Theme | Status | Related findings |",
            "|---|---|---|---|",
        ]
        if not current_rows:
            lines.append("| — | No ledger rows | N/A | — |")
        else:
            for row in current_rows:
                findings = ", ".join(row["finding_ids"]) or "—"
                lines.append(
                    f"| {row['control_id']} | {row['theme'] or row['control_id']} | "
                    f"{row['status']} | {findings} |"
                )
        lines.append("")
        return "\n".join(lines)

    diff = diff_ledgers(previous, current)
    lines += [
        "| Control ID | Previous | Current | Delta |",
        "|---|---|---|---|",
    ]
    any_row = False
    for item in diff["opened"]:
        lines.append(f"| {item['control_id']} | — | {item['status']} | opened |")
        any_row = True
    for item in diff["closed"]:
        lines.append(f"| {item['control_id']} | {item['status']} | — | closed |")
        any_row = True
    for item in diff["changed"]:
        lines.append(
            f"| {item['control_id']} | {item['from']} | {item['to']} | changed |"
        )
        any_row = True
    for item in diff["unchanged"]:
        lines.append(
            f"| {item['control_id']} | {item['status']} | {item['status']} | unchanged |"
        )
        any_row = True
    if not any_row:
        lines.append("| — | — | — | no control-status delta |")
    lines.append("")
    return "\n".join(lines)
