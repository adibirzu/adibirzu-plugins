"""Apply a re-resolved guest IP onto a signed engagement.

Does not call vmrun. Operators run:

    vmrun -T fusion getGuestIPAddress <vmx_path>

then pass the address here. If the new IP is outside signed CIDR → SCOPE DENIED.
"""

from __future__ import annotations

from aetherops.scope.gate import normalize_target, target_in_scope
from aetherops.types import Engagement, Observation

VMRUN_REFRESH = "vmrun -T fusion getGuestIPAddress <vmx_path>"


def apply_guest_ip(engagement: Engagement, new_ip: str | None) -> Observation:
    identity = normalize_target(new_ip)
    if not identity:
        return Observation(
            status="error",
            summary="SCOPE DENIED: empty guest IP.",
            stop_condition="SCOPE DENIED. Do not invent a lab address.",
            data={"scope_refused": True, "executed": False, "command": VMRUN_REFRESH},
        )
    if not target_in_scope(identity, engagement):
        return Observation(
            status="error",
            summary="SCOPE DENIED: refreshed guest IP is outside signed scope.",
            stop_condition="SCOPE DENIED. Do not follow DHCP off the signed CIDR.",
            data={"scope_refused": True, "ip": identity, "executed": False},
        )
    hosts = list(engagement.scope_hosts or [])
    if identity not in hosts:
        hosts.append(identity)
    updated = engagement.model_copy(
        update={
            "scope_hosts": hosts,
            "validation_target": identity,
            "exec_host": identity if (engagement.exec_host or engagement.lab_role == "both") else engagement.exec_host,
        }
    )
    return Observation(
        status="success",
        summary=f"Guest IP {identity} is in signed scope.",
        data={
            "ip": identity,
            "exec_host": updated.exec_host,
            "validation_target": updated.validation_target,
            "executed": False,
            "command": VMRUN_REFRESH,
        },
    )
