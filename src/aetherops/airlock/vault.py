from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aetherops.types import Observation


def ensure_vault(vault_dir: Path) -> Path:
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "README").write_text(
        "LOCAL ENGAGEMENT VAULT — never commit, never upload, never include in evolve payloads.\n"
        "SEIF LOCAL DE ANGAJAMENT — nu se commitează, nu se încarcă, nu intră în payload-uri evolve.\n",
        encoding="utf-8",
    )
    return vault_dir


def store(vault_dir: Path, name: str, payload: dict) -> Path:
    ensure_vault(vault_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = vault_dir / f"{stamp}-{name}.json"
    if path.exists():
        import uuid

        uid = uuid.uuid4().hex[:6]
        path = vault_dir / f"{stamp}-{name}-{uid}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def list_artifacts(vault_dir: Path) -> Observation:
    ensure_vault(vault_dir)
    files = sorted(p.name for p in vault_dir.glob("*.json"))
    return Observation(
        status="success",
        summary=f"{len(files)} vault artifact(s) local only / {len(files)} artefact(e) doar locale",
        artifacts=[str(vault_dir / name) for name in files],
        next_actions=["Use aetherops report to render a bilingual offline report."],
    )


def index_vault(vault_dir: Path) -> dict[str, Any]:
    """Index all local engagement artifacts: findings, clean-negatives, pairs, and checkpoints."""
    ensure_vault(vault_dir)
    findings: list[dict[str, Any]] = []
    clean_negatives: list[dict[str, Any]] = []
    purple_pairs: list[dict[str, Any]] = []
    checkpoints: list[dict[str, Any]] = []

    # 1. Scan primary vault directory for findings, clean-negatives, and purple pairs
    for p in sorted(vault_dir.glob("*.json")):
        if p.name.startswith("checkpoint-") or p.name == "latest.json":
            continue
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(payload, dict):
            continue

        if "vault_ref" not in payload:
            payload["vault_ref"] = str(p)

        kind = str(payload.get("kind") or "").strip().lower()
        status = str(payload.get("status") or "").strip().lower()
        ev_status = str(payload.get("evidence_status") or "").strip().lower()

        if kind == "clean_negative" or status == "clean-negative" or ev_status == "clean-negative" or "clean-negative" in p.name:
            clean_negatives.append(payload)
        elif kind in {"purple_pair", "purple-pair"} or (
            payload.get("detection") and payload.get("control")
        ):
            purple_pairs.append(payload)
        elif kind == "finding" or (
            payload.get("observation") and (payload.get("asset") or payload.get("target"))
        ):
            findings.append(payload)

    # 2. Scan checkpoints subdirectory
    cp_dir = vault_dir / "checkpoints"
    coverage_dry = False
    if cp_dir.is_dir():
        for p in sorted(cp_dir.glob("checkpoint-*.json"), key=lambda f: f.stat().st_mtime):
            try:
                cp_data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(cp_data, dict):
                    if "checkpoint_path" not in cp_data:
                        cp_data["checkpoint_path"] = str(p)
                    checkpoints.append(cp_data)
                    # Check if checkpoint recorded clean-negatives or coverage dry
                    for cn in cp_data.get("clean_negatives", []):
                        if isinstance(cn, dict) and cn not in clean_negatives:
                            clean_negatives.append(cn)
                    if cp_data.get("coverage_dry") or "COVERAGE DRY" in str(cp_data):
                        coverage_dry = True
            except (OSError, json.JSONDecodeError):
                continue

    potential_count = sum(
        1 for f in findings if str(f.get("evidence_status", f.get("status", "Potential"))).capitalize() == "Potential"
    )
    verified_count = sum(
        1 for f in findings if str(f.get("evidence_status", f.get("status", ""))).capitalize() == "Verified"
    )

    return {
        "vault_dir": str(vault_dir),
        "total_findings": len(findings),
        "potential_count": potential_count,
        "verified_count": verified_count,
        "clean_negative_count": len(clean_negatives),
        "purple_pair_count": len(purple_pairs),
        "checkpoint_count": len(checkpoints),
        "coverage_dry": coverage_dry,
        "findings": findings,
        "clean_negatives": clean_negatives,
        "purple_pairs": purple_pairs,
        "checkpoints": checkpoints,
    }


def vault_index_obs(vault_dir: Path) -> Observation:
    """Return an Observation wrapping the vault index."""
    idx = index_vault(vault_dir)
    return Observation(
        status="success",
        summary=(
            f"Vault index: {idx['total_findings']} finding(s) ({idx['potential_count']} potential, "
            f"{idx['verified_count']} verified), {idx['clean_negative_count']} clean negative(s), "
            f"{idx['purple_pair_count']} purple pair(s), {idx['checkpoint_count']} checkpoint(s)."
        ),
        data=idx,
        next_actions=[
            "Keep findings in vault/",
            "Pair red findings with purple-feedback before reporting",
        ],
    )
