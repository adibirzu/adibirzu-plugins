"""Engagement-scoped lab destinations. Not a general RFC1918 hole.

HTTP EgressSession stays loopback-only. SSH/TCP to a lab guest is allowed
only to exec_host or validation_target, and only when that identity is in
the signed scope.
"""

from __future__ import annotations

from aetherops.scope.gate import normalize_target, target_in_scope
from aetherops.types import Engagement


class LabDestDenied(ValueError):
    """Lab transport targeted a host outside exec_host/validation_target."""


def lab_destinations(engagement: Engagement) -> set[str]:
    allowed: set[str] = set()
    for raw in (engagement.exec_host, engagement.validation_target):
        identity = normalize_target(raw)
        if identity and target_in_scope(identity, engagement):
            allowed.add(identity)
    return allowed


def assert_lab_dest(host: str | None, engagement: Engagement) -> str:
    identity = normalize_target(host)
    if not identity:
        raise LabDestDenied("lab transport refuses empty host")
    if identity not in lab_destinations(engagement):
        raise LabDestDenied(f"lab transport refuses host {identity!r}")
    return identity
