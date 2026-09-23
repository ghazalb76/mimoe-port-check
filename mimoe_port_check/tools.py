"""Read-only system inspection tools: list_ports, inspect_process, check_exposure.

Security rules enforced here (not negotiable, not model-controlled):
  - subprocess.run is always called with an argument list, never shell=True.
  - Every argument that reaches a command (e.g. a PID) is validated/coerced
    to the expected type in code before it's used.
  - No sudo, no state-changing commands. Only lsof and ps, read-only flags.
  - Command lines are treated as untrusted, attacker-influenceable text:
    they're redacted for likely secrets before being printed or handed to
    the model, and are never executed or interpreted as instructions.
"""
import re
import subprocess
from dataclasses import dataclass

SUBPROCESS_TIMEOUT_SECONDS = 5

# Known services table: port -> (name, note). Risk labels are derived from
# this table plus exposure (see label_risk), never from the model.
KNOWN_SERVICES: dict[int, tuple[str, str]] = {
    20: ("FTP (data)", "File transfer — unencrypted by default."),
    21: ("FTP (control)", "File transfer — unencrypted by default."),
    22: ("SSH", "Remote shell access."),
    23: ("Telnet", "Unencrypted remote shell — avoid exposing."),
    25: ("SMTP", "Mail transfer."),
    53: ("DNS", "Name resolution."),
    80: ("HTTP", "Web server, unencrypted."),
    443: ("HTTPS", "Web server, TLS."),
    3000: ("Dev server", "Common local development server (Node/etc.)."),
    3306: ("MySQL", "Database — typically should not be network-exposed."),
    5000: ("Dev server", "Common local development server (Flask/etc.)."),
    5432: ("PostgreSQL", "Database — typically should not be network-exposed."),
    5900: ("VNC", "Remote screen sharing."),
    6379: ("Redis", "In-memory data store, often unauthenticated by default."),
    8080: ("HTTP-alt", "Common alternate HTTP or dev server port."),
    8083: ("mimOE", "Local AI inference endpoint used by this agent."),
    9200: ("Elasticsearch", "Search/data store — typically should not be network-exposed."),
    27017: ("MongoDB", "Database — typically should not be network-exposed."),
}

@dataclass(frozen=True)
class KnownProcess:
    service_name: str
    local_note: str
    exposed_note: str
    exposed_risk: str  # most known processes are "INFO"; see mimoe below for why one isn't
    path_prefixes: tuple[str, ...]  # empty means no fixed install path to verify -- name-only match


def _info_process(service_name: str, note: str, path_prefixes: tuple[str, ...]) -> KnownProcess:
    """Most known processes are broadcast/discovery services that are
    *supposed* to be reachable on the LAN (AirPlay, Handoff, Spotify
    Connect) -- exposure there is expected, not a finding, hence INFO."""
    return KnownProcess(
        service_name=service_name,
        local_note=f"{note} Bound to localhost only.",
        exposed_note=f"{note} Exposed to the network — expected for this service.",
        exposed_risk="INFO",
        path_prefixes=path_prefixes,
    )


# Known macOS system/app processes: lowercased command name -> KnownProcess.
# A command name alone is spoofable (any process can set its own
# argv[0]/name), so a match here is only trusted when the process's actual
# executable path (from `ps -o comm=`, which the process can't fake) starts
# with one of path_prefixes -- see _match_known_process. An empty
# path_prefixes means the process has no fixed install location to check
# (e.g. mimoe runs from wherever the user set it up) and the name match is
# trusted on its own.
KNOWN_PROCESSES: dict[str, KnownProcess] = {
    "rapportd": _info_process(
        "Handoff/Continuity",
        "Apple continuity between your devices.",
        ("/usr/libexec/rapportd",),
    ),
    "controlcenter": _info_process(
        "AirPlay Receiver",
        "macOS Control Center's AirPlay receiver (commonly ports 5000/7000).",
        ("/System/Library/CoreServices/ControlCenter.app/",),
    ),
    "spotify": _info_process(
        "Spotify Connect",
        "Spotify's local device-discovery service.",
        ("/Applications/Spotify.app/",),
    ),
    "code helper": _info_process(
        "VS Code",
        "A VS Code helper process (extension host, GPU, renderer, etc.).",
        (
            "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper",
            "/Applications/Visual Studio Code - Insiders.app/Contents/Frameworks/Code Helper",
        ),
    ),
    # mimoe is deliberately NOT an _info_process: unlike the broadcast/
    # discovery services above, it isn't meant to be reachable by other
    # machines, and mimOE's API key defaults to a fixed, publicly-documented
    # value (see .env.example) -- so if it's exposed, anyone on the local
    # network can use this machine's inference endpoint. That's a real
    # finding, not expected behavior, hence MEDIUM rather than INFO.
    "mimoe": KnownProcess(
        service_name="mimOE",
        local_note="Local AI inference endpoint used by this agent. Bound to localhost only.",
        exposed_note=(
            "Local AI inference endpoint used by this agent. Exposed to all network "
            "interfaces — the API key is a shared default, so anyone on the local "
            "network could reach and use this inference endpoint."
        ),
        exposed_risk="MEDIUM",
        path_prefixes=(),
    ),
}

SENSITIVE_IF_EXPOSED = {21, 22, 23, 3306, 5432, 5900, 6379, 9200, 27017}

ALL_INTERFACES_MARKERS = {"*", "0.0.0.0", "::", "[::]"}

# lsof escapes characters that would otherwise break whitespace-delimited
# column parsing (most commonly a space in a command name) as \xHH.
_LSOF_ESCAPE_PATTERN = re.compile(r"\\x([0-9A-Fa-f]{2})")


def _decode_lsof_escapes(text: str) -> str:
    """Decode lsof's \\xHH escapes (e.g. \\x20 for a space) back to characters."""
    return _LSOF_ESCAPE_PATTERN.sub(lambda m: chr(int(m.group(1), 16)), text)

# Redaction patterns for likely secrets in command lines / process args.
_REDACTION_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*=\s*\S+"),
    re.compile(r"(?i)(token|api[_-]?key|secret)\s*=\s*\S+"),
    re.compile(r"(?i)--(password|token|api[_-]?key|secret)[= ]\S+"),
    re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/]+:[^\s@/]+@\S+"),  # user:pass@host URIs
    re.compile(r"(?i)bearer\s+\S+"),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),  # long opaque tokens (hex/base64-like)
]


def redact_secrets(text: str) -> str:
    """Best-effort redaction of likely secrets from untrusted command-line text."""
    redacted = text
    for pattern in _REDACTION_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


@dataclass
class PortEntry:
    port: int
    protocol: str
    local_address: str
    pid: int
    command: str
    exposed_to_network: bool
    service_name: str
    risk: str
    risk_note: str


def _fetch_exe_path(pid: int) -> str | None:
    """Full executable path for a PID (from `ps -o comm=`, which on macOS
    reports the full path, not just a short name). Used to verify a
    KNOWN_PROCESSES name match isn't spoofed: a process can name itself
    anything, but it can't fake the path of the binary that's actually
    running."""
    output = _run(["ps", "-p", str(pid), "-o", "comm="])
    path = output.strip()
    return path or None


def _match_known_process(command: str, pid: int | None) -> KnownProcess | None:
    """Return the KnownProcess entry if `command` matches one and, when that
    entry has expected path prefixes, the process's real executable path
    confirms it. A name match with a failed path check falls through to the
    port-based table instead of being trusted."""
    normalized = command.strip().lower()
    for name, known_process in KNOWN_PROCESSES.items():
        if normalized != name and not normalized.startswith(name):
            continue
        if known_process.path_prefixes:
            exe_path = _fetch_exe_path(pid) if pid is not None else None
            if not exe_path or not exe_path.startswith(known_process.path_prefixes):
                continue
        return known_process
    return None


def label_risk(port: int, exposed_to_network: bool, command: str = "", pid: int | None = None) -> tuple[str, str, str]:
    """Return (service_name, risk_level, risk_note).

    Process identity is checked first via KNOWN_PROCESSES: a recognized,
    path-verified macOS system/app process is labeled LOW when bound to
    localhost, and each entry defines its own network-exposed risk/note
    (most are INFO -- e.g. AirPlay/Handoff/Spotify Connect are *meant* to be
    reachable on the LAN -- but mimoe is MEDIUM, since it isn't). This
    matching happens regardless of port. Falls back to the port-based
    KNOWN_SERVICES table when nothing in KNOWN_PROCESSES matches.
    """
    known_process = _match_known_process(command, pid)
    if known_process is not None:
        if exposed_to_network:
            return known_process.service_name, known_process.exposed_risk, known_process.exposed_note
        return known_process.service_name, "LOW", known_process.local_note

    known = KNOWN_SERVICES.get(port)
    service_name = known[0] if known else "Unknown service"
    base_note = known[1] if known else "Unrecognized port — not in the known-services table."

    if exposed_to_network and port in SENSITIVE_IF_EXPOSED:
        return service_name, "HIGH", f"{base_note} Exposed to all network interfaces — high risk."
    if exposed_to_network and known is None:
        return service_name, "MEDIUM", f"{base_note} Also exposed to all network interfaces."
    if exposed_to_network:
        return service_name, "MEDIUM", f"{base_note} Exposed to all network interfaces."
    if known is None:
        return service_name, "LOW", f"{base_note} Bound to localhost only."
    return service_name, "LOW", f"{base_note} Bound to localhost only."


def _run(args: list[str]) -> str:
    """Run a read-only whitelisted command with an argument list (never shell=True)."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            shell=False,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Command not found: {args[0]}") from exc
    except PermissionError as exc:
        raise RuntimeError(
            f"Permission denied running '{args[0]}'. Check that it's executable "
            "and that this terminal has the necessary permissions."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(args)}") from exc
    return result.stdout


def _split_addr_port(name_field: str) -> tuple[str, int | None]:
    """Parse an lsof NAME field like '*:8083' or '[::1]:5432' into (address, port)."""
    name_field = name_field.strip()
    if name_field.startswith("["):
        addr, _, rest = name_field[1:].partition("]:")
        return f"[{addr}]", int(rest) if rest.isdigit() else None
    addr, _, port_str = name_field.rpartition(":")
    return addr, int(port_str) if port_str.isdigit() else None


def list_ports() -> list[PortEntry]:
    """List TCP ports in LISTEN state, with owning process and risk label.

    UDP sockets are excluded: they have no connection state comparable to
    LISTEN, so "is this open" is ambiguous for UDP in a way that would need
    separate handling — noted as a limitation rather than guessed at here.
    """
    # +c 0 disables lsof's COMMAND column truncation so full process names
    # (e.g. "Code Helper (Plugin)") come through instead of being cut off.
    output = _run(["lsof", "-i", "-P", "-n", "+c", "0"])
    raw_rows: list[tuple[int, int, str, str, bool]] = []

    for line in output.splitlines()[1:]:  # skip header
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid_str, _user, _fd, type_, _device, _size, _node, name = parts
        if type_ != "IPv4" and type_ != "IPv6":
            continue
        if "(LISTEN)" not in name:
            continue
        if not pid_str.isdigit():
            continue

        addr_port = name.split(" (LISTEN)")[0]
        address, port = _split_addr_port(addr_port)
        if port is None:
            continue

        exposed = address in ALL_INTERFACES_MARKERS
        command = redact_secrets(_decode_lsof_escapes(command))
        raw_rows.append((port, int(pid_str), command, address, exposed))

    return _merge_dual_stack(raw_rows)


def _merge_dual_stack(rows: list[tuple[int, int, str, str, bool]]) -> list[PortEntry]:
    """Merge IPv4/IPv6 rows for the same (port, pid) into one PortEntry.

    A dual-stack process (e.g. one listening on both `*:PORT` over IPv4 and
    `[::]:PORT` over IPv6) shows up as two separate lsof lines for what a
    user experiences as one listening service. Merging keeps `list_ports`
    output at one row per actual service, and treats the port as exposed if
    *either* stack is bound to all interfaces.
    """
    merged: dict[tuple[int, int], dict] = {}
    order: list[tuple[int, int]] = []

    for port, pid, command, address, exposed in rows:
        key = (port, pid)
        if key not in merged:
            merged[key] = {"command": command, "addresses": [], "exposed": False}
            order.append(key)
        group = merged[key]
        if address not in group["addresses"]:
            group["addresses"].append(address)
        group["exposed"] = group["exposed"] or exposed

    entries: list[PortEntry] = []
    for port, pid in order:
        group = merged[(port, pid)]
        service_name, risk, risk_note = label_risk(port, group["exposed"], group["command"], pid)
        entries.append(
            PortEntry(
                port=port,
                protocol="tcp",
                local_address=", ".join(group["addresses"]),
                pid=pid,
                command=group["command"],
                exposed_to_network=group["exposed"],
                service_name=service_name,
                risk=risk,
                risk_note=risk_note,
            )
        )

    return entries


@dataclass
class ProcessDetails:
    pid: int
    ppid: int | None
    user: str | None
    command: str
    args: str
    found: bool


def inspect_process(pid: int) -> ProcessDetails:
    """Return details for a single PID. pid must already be a validated int."""
    if not isinstance(pid, int) or isinstance(pid, bool):
        raise ValueError(f"pid must be an int, got {type(pid).__name__}")
    if pid <= 0:
        raise ValueError(f"pid must be a positive integer, got {pid}")

    output = _run(["ps", "-p", str(pid), "-o", "pid=,ppid=,user=,comm=,args="])
    line = output.strip()
    if not line:
        return ProcessDetails(pid=pid, ppid=None, user=None, command="", args="", found=False)

    parts = line.split(None, 4)
    if len(parts) < 5:
        return ProcessDetails(pid=pid, ppid=None, user=None, command="", args="", found=False)

    pid_str, ppid_str, user, comm, args = parts
    return ProcessDetails(
        pid=int(pid_str) if pid_str.isdigit() else pid,
        ppid=int(ppid_str) if ppid_str.isdigit() else None,
        user=user,
        command=redact_secrets(comm),
        args=redact_secrets(args),
        found=True,
    )


@dataclass
class ExposureReport:
    port: int
    found: bool
    exposed_to_network: bool = False
    local_address: str = ""
    service_name: str = ""
    risk: str = ""
    risk_note: str = ""
    pid: int | None = None


def check_exposure(port: int) -> ExposureReport:
    """Check whether a specific listening port is bound to all interfaces or localhost only."""
    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError(f"port must be an int, got {type(port).__name__}")
    if not (1 <= port <= 65535):
        raise ValueError(f"port must be between 1 and 65535, got {port}")

    for entry in list_ports():
        if entry.port == port:
            return ExposureReport(
                port=port,
                found=True,
                exposed_to_network=entry.exposed_to_network,
                local_address=entry.local_address,
                service_name=entry.service_name,
                risk=entry.risk,
                risk_note=entry.risk_note,
                pid=entry.pid,
            )

    return ExposureReport(port=port, found=False)
