"""Shared deny lists for the scope gate and adapter registry.

Exploit-dev verbs stay refused in Phase 1 even if a future engagement
sets allow_exploit_dev. Permanent denies never lift.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

# Never allowed, even on a signed allow_exploit_dev engagement.
# Additive only — never remove a token from this tuple.
PERMANENT_DENY = (
    "reverse_shell",
    "c2_",
    "exfil",
    "worm",
    "ransomware",
    "wiper",
    "self_propagat",
    "beacon",
    "self_replicate",
    "command_and_control",
    "disk_wiper",
    "ransom_note",
    "implant",
    "backdoor",
    "rootkit",
    "botnet",
    "keylogger",
    "spyware",
    "trojan",
    "dropper",
    "webshell",
    "web_shell",
    "bind_shell",
    "bind-shell",
    "reverse-shell",
    "revshell",
    "cryptolocker",
    "lockbit",
    "data_wipe",
    "exfiltration",
    "data_exfil",
    "c2channel",
    "c2-channel",
    "command-and-control",
)

# Adapter names that are C2 / implant frameworks even without a trailing "_".
# Additive only — never remove a name from this set.
PERMANENT_DENY_ADAPTERS = frozenset(
    {
        "c2",
        "cobalt",
        "sliver",
        "mythic",
        "empire",
        "meterpreter",
        "beacon",
        "havoc",
        "covenant",
        "poshc2",
        "bruteratel",
        "brute_ratel",
        "nighthawk",
        "pupy",
        "koadic",
        "merlin",
    }
)

# Gated in later phases. Phase 1 refuses these regardless of the flag
# so the harness stays honest and adds no new offensive power.
EXPLOIT_DEV_SUBSTRINGS = (
    "generate_payload",
    "msfvenom",
    "metasploit",
    "pacu_exploitation",
    "pwntools_exploit",
    "hydra_attack",
    "john_crack",
    "hashcat_crack",
    "hashpump_attack",
    "generate_exploit",
    "exploit_dev",
    "sqlmap",
    "weaponized",
    # Bare verb stems: hexstrike.exploit / hexstrike.payload must not slip
    # through because they lack the generate_ prefix.
    ".exploit",
    ".payload",
    "exploit.",
    "payload.",
    "klinvm",
    "proof.",
    "validator.confirm",
    "validator.proof",
    "validator.bind",
    "validator.snapshot",
    "validator.restore",
    "validator.evidence",
    "validator.promote",
    "impacket",
    "mimikatz",
    "evil-winrm",
    "evil_winrm",
    "crackmapexec",
    "netexec",
    "wmiexec",
    "smbexec",
    "psexec",
    "atexec",
    "dcomexec",
    "secretsdump",
    "autopwn",
    "auto_pwn",
    "weaponize",
    "generate_shellcode",
    "shellcode_gen",
    "cobaltstrike",
    "cobalt_strike",
    "rubeus",
    "certipy",
    "nanodump",
    "lsassy",
)

# Governed proof-of-exploitability verbs. Signed L3 may draft a local
# Qwythos demonstration artifact (words/vault). Payload execution stays off.
EXPLOITATION_TOOL_NAMES = frozenset(
    {
        "exploit_dev.draft",
        "exploit_dev.hypothesis",
        "exploit_dev.validate",
        "exploit_dev.confirm",
        "exploit_dev.promote",
        "exploit_dev.poc",
        "validator.confirm",
        "validator.proof",
        "validator.bind",
        "validator.snapshot",
        "validator.restore",
        "validator.evidence",
        "validator.promote",
        "klinvm.validate",
        "klinvm.bind",
        "klinvm.restore",
        "klinvm.snapshot",
        "proof.authn_bypass",
        "proof.authz_idor",
        "proof.injection_class",
        "proof.ssrf_class",
        "proof.xss_class",
        "proof.path_traversal",
        "proof.misconfig_class",
        "proof.default_auth",
        "proof.privilege_class",
        "proof.deserial_class",
        "proof.upload_class",
    }
)

# Combined list for adapters.yaml-style matching.
DENY_SUBSTRINGS = PERMANENT_DENY + EXPLOIT_DEV_SUBSTRINGS

# Tool-call argument keys the advertised schema does not include.
# Extra keys are a smuggle path for payloads; fail closed.
ALLOWED_ARG_KEYS = frozenset(
    {
        "name",
        "verb",
        "adapter",
        "target",
        "host",
        "ip",
        "live",
        "argv",
        "extra",
        "binary",
        "query",
        "skill",
        "limit",
        "weapon",
        "issue_class",
        "tool",
        "path",
    }
)

# Keys that are themselves exploit/payload shaped (subset of extra keys).
EXPLOIT_ARG_KEYS = frozenset(
    {
        "payload",
        "shellcode",
        "exploit",
        "poc",
        "lhost",
        "lport",
        "rhost",
        "stager",
        "implant",
        "meterpreter",
        "weaponized",
        "raw",
        "code",
        "cmd",
        "command",
        "script",
        "encoder",
        "badchars",
        "nopsled",
        "nop",
        "rop",
        "ropchain",
        "stage0",
        "c2_url",
        "callback",
        "reverse",
        "bind_shell",
        "msf",
        "venom",
        "exploit_code",
        "payload_b64",
        "listener",
        "handler",
        "shell",
        "luri",
    }
)

PATH_SCOPED_VERBS = frozenset({"mcp_scan", "skill_scan"})
FORBIDDEN_SCAN_PARTS = frozenset({"vault", "engagements", "reports"})

READONLY_VERBS = frozenset(
    {
        "health",
        "inventory",
        "next",
        "mission_plan",
        "mission-plan",
        "search",
        "show",
        "load",
        "pin",
        "checklist",
        "mcp_checklist",
        "gap",
        "map",
    }
)

# Shapes that mean "emit capability" rather than "name a class".
PAYLOAD_SHAPES = (
    "msfvenom -p",
    "msfvenom -",
    "reverse shell one-liner",
    "#!/bin/bash",
    "nc -e",
    "exploit_type: weaponized",
    "meterpreter/",
    "windows/meterpreter",
    "linux/x64/shell",
    "bash -i >& /dev/tcp",
    "/dev/tcp/",
    "powershell -enc",
    "powershell -nop",
    "mkfifo /tmp",
    "python -c 'import socket",
    "php -r '",
    "perl -e",
    "ruby -rsocket",
    "curl | sh",
    "curl | bash",
    "wget | sh",
    "base64 -d | sh",
    "windows/shell/",
    "linux/x86/shell",
    "cmd/unix/reverse",
    "use exploit/",
    "exploit/multi/",
    "nc -nv",
    "rm -rf --no-preserve-root",
)


def _lowered(tool: str) -> str:
    return (tool or "").lower()


def _adapter_name(tool: str) -> str:
    blob = _lowered(tool).strip()
    if not blob:
        return ""
    return blob.split(".", 1)[0]


def is_permanent_deny(tool: str) -> bool:
    blob = _lowered(tool)
    if any(token in blob for token in PERMANENT_DENY):
        return True
    return _adapter_name(tool) in PERMANENT_DENY_ADAPTERS


def is_exploit_dev(tool: str) -> bool:
    blob = _lowered(tool)
    if blob in EXPLOITATION_TOOL_NAMES:
        return True
    if any(token in blob for token in EXPLOIT_DEV_SUBSTRINGS):
        return True
    # Bare adapter or verb named exploit / payload (no prefix/suffix).
    name = _adapter_name(tool)
    verb = blob.split(".", 1)[1] if "." in blob else ""
    return name in {"exploit", "payload"} or verb in {"exploit", "payload"}


def is_catalogued_demo_verb(tool: str, verb: str | None = None) -> bool:
    """True for exploit_dev.* / proof.* verbs that may draft a vault demo artifact.

    klinvm.* and validator.* remain the unwired jail; they are catalogued but
    do not produce a demonstration artifact in this build.
    """
    blob = _lowered(tool)
    action = (verb or "").strip().lower()
    full = f"{blob}.{action}" if action and "." not in blob else blob
    if full.startswith(("exploit_dev.", "proof.")):
        return True
    if blob.startswith(("exploit_dev.", "proof.")):
        return True
    return blob == "exploit_dev" and bool(action)


def is_readonly_verb(verb: str) -> bool:
    return (verb or "").strip().lower() in READONLY_VERBS


def is_path_scoped_verb(verb: str | None) -> bool:
    """Verbs that scan a local workspace path instead of a network target."""
    return (verb or "").strip().lower() in PATH_SCOPED_VERBS


def is_workspace_scan_path(raw: str | None) -> bool:
    """True for a workspace-relative path that never touches vault/engagements/reports."""
    text = (raw or "").strip()
    if not text:
        return False
    candidate = PurePosixPath(text.replace("\\", "/"))
    if candidate.is_absolute():
        return False
    parts = [part for part in candidate.parts if part != "."]
    if not parts or any(part == ".." for part in parts):
        return False
    return not any(part.lower() in FORBIDDEN_SCAN_PARTS for part in parts)


def extra_arg_keys(arguments: dict[str, Any] | None) -> tuple[str, ...]:
    if not arguments:
        return ()
    return tuple(k for k in arguments if str(k).lower() not in ALLOWED_ARG_KEYS)


def exploit_arg_keys(arguments: dict[str, Any] | None) -> tuple[str, ...]:
    if not arguments:
        return ()
    return tuple(k for k in arguments if str(k).lower() in EXPLOIT_ARG_KEYS)


def contains_payload_shape(text: str | None) -> bool:
    blob = (text or "").lower()
    return any(shape in blob for shape in PAYLOAD_SHAPES)


def _value_has_payload_shape(value: Any) -> bool:
    if isinstance(value, str):
        return contains_payload_shape(value)
    if isinstance(value, (list, tuple)):
        return any(_value_has_payload_shape(item) for item in value)
    if isinstance(value, dict):
        return any(
            _value_has_payload_shape(k) or _value_has_payload_shape(v)
            for k, v in value.items()
        )
    return False


def arguments_have_payload_shape(arguments: dict[str, Any] | None) -> bool:
    if not arguments:
        return False
    for key, value in arguments.items():
        if _value_has_payload_shape(key) or _value_has_payload_shape(value):
            return True
    return False
