"""SSH remote-exec of allowlisted argv. No shell strings. No live SSH in tests.

Lane 1 injects a transport. Without a transport, live is STOP (do not invent).
sqlmap/msfconsole stay denied until exploit-dev is authorized.
"""

from __future__ import annotations

from collections.abc import Callable

from aetherops.airlock.lab_transport import LabDestDenied, assert_lab_dest
from aetherops.harness.observation import err, ok, warn
from aetherops.scope.verbs import is_exploit_dev, is_permanent_deny
from aetherops.types import Engagement, Observation

ALLOWED_BINARIES = frozenset({"nmap", "nuclei", "trivy", "checkov", "gdb"})
EXPLOIT_BINARIES = frozenset({"sqlmap", "msfconsole", "msfvenom", "metasploit"})
_SHELL_METACHAR = frozenset({";", "|", "&", "`", "$", "\n", "\r", ">", "<"})

RemoteRunner = Callable[[str, list[str]], str]


def build_argv(binary: str, extra: list[str] | None = None) -> list[str] | Observation:
    name = (binary or "").strip().lower()
    if not name or name not in ALLOWED_BINARIES:
        if name in EXPLOIT_BINARIES or is_exploit_dev(name) or is_permanent_deny(name):
            return err(
                "Denied: exploit/payload binaries are not available on remote-exec.",
                stop_condition="Do not retry denied tools. Use allowlisted wrappers only.",
                data={"executed": False, "binary": name, "scope_refused": True},
            )
        return err(
            f"Denied: {name or 'empty'} is not an allowlisted remote-exec binary.",
            stop_condition="Use nmap, nuclei, trivy, checkov, or gdb only.",
            data={"executed": False, "binary": name, "scope_refused": True},
        )
    argv = [name]
    for item in extra or []:
        text = str(item)
        if any(ch in text for ch in _SHELL_METACHAR):
            return err(
                "Denied: shell metacharacters in remote-exec arguments.",
                stop_condition="Do not retry with a shell string. Argv only.",
                data={"executed": False, "scope_refused": True},
            )
        argv.append(text)
    return argv


def run_remote_exec(
    *,
    engagement: Engagement,
    binary: str,
    extra: list[str] | None = None,
    live: bool = False,
    transport: RemoteRunner | None = None,
) -> Observation:
    argv = build_argv(binary, extra)
    if isinstance(argv, Observation):
        return argv
    host = engagement.exec_host or engagement.validation_target
    try:
        dest = assert_lab_dest(host, engagement)
    except LabDestDenied as exc:
        return err(
            "SCOPE DENIED: exec_host is missing or out of signed scope.",
            root_cause_hint=str(exc),
            stop_condition="SCOPE DENIED. Do not SSH off the signed lab identity.",
            data={"executed": False, "scope_refused": True},
        )
    if not live:
        return ok(
            f"remote-exec planned: {' '.join(argv)} on {dest}",
            data={"argv": argv, "host": dest, "executed": False, "live": False},
            next_actions=["Live SSH requires a signed engagement and an injected transport"],
        )
    if transport is None:
        return warn(
            "STOP live-unwired: no remote-exec transport (Lane 1 does not SSH).",
            stop_condition="Do not invent scanner results. Inject a mock transport in tests; Lane 2 supplies SSH.",
            data={"argv": argv, "host": dest, "executed": False},
        )
    output = transport(dest, argv)
    return ok(
        f"remote-exec {argv[0]} on {dest}",
        data={"argv": argv, "host": dest, "executed": True, "output": str(output)[:2000]},
    )
