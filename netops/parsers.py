"""Parse raw Cisco IOS CLI captures into structured data.

A capture is a plain text file containing one or more commands and their output, exactly as
copied from a terminal session, e.g.

    SW1#show interfaces
    ...
    SW1#show ip ospf neighbor
    ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PROMPT_RE = re.compile(r"^(?P<host>[\w.\-]+)[#>]\s*(?P<cmd>show .+?)\s*$", re.M | re.I)


@dataclass
class Interface:
    name: str
    status: str
    protocol: str
    description: str = ""
    duplex: str = ""
    speed: str = ""
    reliability: int = 255
    txload: int = 0
    rxload: int = 0
    packets_in: int = 0
    input_errors: int = 0
    crc: int = 0
    frame: int = 0
    output_errors: int = 0
    collisions: int = 0
    late_collisions: int = 0
    resets: int = 0
    output_drops: int = 0

    @property
    def is_up(self) -> bool:
        return self.status == "up" and self.protocol == "up"


@dataclass
class OspfNeighbor:
    neighbor_id: str
    state: str
    role: str
    address: str
    interface: str


@dataclass
class LogEntry:
    timestamp: str
    facility: str
    severity: int
    mnemonic: str
    message: str

    @property
    def code(self) -> str:
        return f"{self.facility}-{self.severity}-{self.mnemonic}"


@dataclass
class Capture:
    hostname: str = "unknown"
    commands: list[str] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    ospf_neighbors: list[OspfNeighbor] = field(default_factory=list)
    cpu: dict[str, int] | None = None
    cpu_top: list[tuple[str, float]] = field(default_factory=list)
    logs: list[LogEntry] = field(default_factory=list)
    raw: str = ""

    def interface(self, name: str) -> Interface | None:
        short = normalize_ifname(name)
        return next((i for i in self.interfaces if normalize_ifname(i.name) == short), None)


# --------------------------------------------------------------------------- helpers
_IF_ABBR = [("tengigabitethernet", "te"), ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("ethernet", "eth")]


def normalize_ifname(name: str) -> str:
    """GigabitEthernet1/0/2, Gi1/0/2 and gi1/0/2 all become 'gi1/0/2'."""
    n = name.strip().lower()
    for long, short in _IF_ABBR:
        if n.startswith(long):
            return short + n[len(long):]
    for _, short in _IF_ABBR:
        if n.startswith(short):
            return n
    return n


def _int(pattern: str, text: str, default: int = 0) -> int:
    m = re.search(pattern, text)
    return int(m.group(1)) if m else default


def split_sections(text: str) -> tuple[str, dict[str, str]]:
    """Return (hostname, {command: output})."""
    matches = list(PROMPT_RE.finditer(text))
    if not matches:
        return "unknown", {"": text}
    sections: dict[str, str] = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections[m.group("cmd").lower().strip()] = text[m.end():end]
    return matches[0].group("host"), sections


# --------------------------------------------------------------------------- per-command parsers
_IF_HEADER = re.compile(
    r"^(?P<name>\S+) is (?P<status>administratively down|up|down), line protocol is (?P<proto>up|down)",
    re.M,
)


def parse_show_interfaces(output: str) -> list[Interface]:
    headers = list(_IF_HEADER.finditer(output))
    result = []
    for i, h in enumerate(headers):
        block = output[h.start(): headers[i + 1].start() if i + 1 < len(headers) else len(output)]
        duplex_m = re.search(r"^\s*(Full|Half|Auto)-duplex, ([^,]+),", block, re.M)
        result.append(
            Interface(
                name=h.group("name"),
                status=h.group("status"),
                protocol=h.group("proto"),
                description=(re.search(r"Description: (.+)", block) or [None, ""])[1].strip(),
                duplex=duplex_m.group(1).lower() if duplex_m else "",
                speed=duplex_m.group(2).strip() if duplex_m else "",
                reliability=_int(r"reliability (\d+)/255", block, 255),
                txload=_int(r"txload (\d+)/255", block),
                rxload=_int(r"rxload (\d+)/255", block),
                packets_in=_int(r"(\d+) packets input", block),
                input_errors=_int(r"(\d+) input errors", block),
                crc=_int(r"(\d+) CRC", block),
                frame=_int(r"(\d+) frame", block),
                output_errors=_int(r"(\d+) output errors", block),
                collisions=_int(r"(\d+) collisions", block),
                late_collisions=_int(r"(\d+) late collision", block),
                resets=_int(r"(\d+) interface resets", block),
                output_drops=_int(r"(\d+) output drops", block)
                or _int(r"Total output drops: (\d+)", block),
            )
        )
    return result


_OSPF_ROW = re.compile(
    r"^(?P<id>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<state>[A-Z0-9]+)/\s*(?P<role>\S+)\s+\S+\s+(?P<addr>\d+\.\d+\.\d+\.\d+)\s+(?P<intf>\S+)",
    re.M,
)


def parse_ospf_neighbors(output: str) -> list[OspfNeighbor]:
    return [
        OspfNeighbor(m["id"], m["state"], m["role"], m["addr"], m["intf"]) for m in _OSPF_ROW.finditer(output)
    ]


def parse_cpu(output: str) -> tuple[dict[str, int] | None, list[tuple[str, float]]]:
    m = re.search(r"five seconds: (\d+)%.*?one minute: (\d+)%; five minutes: (\d+)%", output)
    if not m:
        return None, []
    cpu = {"5s": int(m.group(1)), "1m": int(m.group(2)), "5m": int(m.group(3))}
    top = [
        (p.group(2).strip(), float(p.group(1)))
        for p in re.finditer(r"^\s*\d+\s+\d+\s+\d+\s+\d+\s+([\d.]+)%\s+[\d.]+%\s+[\d.]+%\s+\d+\s+(.+)$", output, re.M)
    ]
    return cpu, top


_LOG_RE = re.compile(r"^\*?(?P<ts>[A-Z][a-z]{2}\s+\d+\s+[\d:.]+):\s+%(?P<fac>[\w-]+?)-(?P<sev>\d)-(?P<mn>\w+):\s+(?P<msg>.+)$", re.M)


def parse_logging(output: str) -> list[LogEntry]:
    return [
        LogEntry(m["ts"], m["fac"], int(m["sev"]), m["mn"], m["msg"].strip()) for m in _LOG_RE.finditer(output)
    ]


# --------------------------------------------------------------------------- entry point
def parse_capture(text: str) -> Capture:
    hostname, sections = split_sections(text)
    cap = Capture(hostname=hostname, commands=list(sections), raw=text)
    for cmd, out in sections.items():
        if cmd.startswith("show interfaces") and "status" not in cmd:
            cap.interfaces.extend(parse_show_interfaces(out))
        elif cmd.startswith("show ip ospf nei"):
            cap.ospf_neighbors.extend(parse_ospf_neighbors(out))
        elif cmd.startswith("show proc") and "cpu" in cmd:
            cap.cpu, cap.cpu_top = parse_cpu(out)
        elif cmd.startswith("show log"):
            cap.logs.extend(parse_logging(out))
    return cap
