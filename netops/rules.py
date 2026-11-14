"""Deterministic diagnostic rules.

Every finding is grounded in evidence from the capture. The AI layer only explains and
prioritises these findings; it never invents them. This keeps the tool trustworthy.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .parsers import Capture, normalize_ifname

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


@dataclass
class Finding:
    id: str
    severity: str  # critical | warning | info
    title: str
    target: str
    evidence: list[str]
    likely_cause: str
    next_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


RULES = []


def rule(func):
    RULES.append(func)
    return func


# --------------------------------------------------------------------------- physical layer
@rule
def duplex_problems(cap: Capture):
    mismatch_logs = [l for l in cap.logs if l.mnemonic == "DUPLEX_MISMATCH"]
    for intf in cap.interfaces:
        evidence = []
        if intf.duplex == "half" and intf.is_up:
            evidence.append(f"{intf.name} is running Half-duplex at {intf.speed}")
        if intf.late_collisions:
            evidence.append(f"{intf.late_collisions:,} late collisions (a classic duplex-mismatch symptom)")
        for log in mismatch_logs:
            m = re.search(r"discovered on (\S+)", log.message)
            if m and normalize_ifname(m.group(1)) == normalize_ifname(intf.name):
                evidence.append(f"Log {log.timestamp}: %{log.code}: {log.message[:160]}")
        if evidence:
            yield Finding(
                id="DUPLEX_MISMATCH",
                severity="critical" if intf.late_collisions else "warning",
                title="Duplex mismatch",
                target=intf.name + (f" ({intf.description})" if intf.description else ""),
                evidence=evidence,
                likely_cause="One side is hard-coded to full duplex while the other auto-negotiates and falls back to half duplex.",
                next_steps=[
                    f"show interfaces {intf.name} status",
                    "Set both ends to auto/auto (preferred) or the same fixed speed/duplex",
                    f"clear counters {intf.name}  # then confirm late collisions stop increasing",
                ],
            )


@rule
def crc_errors(cap: Capture):
    for intf in cap.interfaces:
        if not intf.crc or not intf.packets_in:
            continue
        ratio = intf.crc / intf.packets_in
        if ratio < 0.0001:  # below 0.01% is noise
            continue
        flaps = _flap_count(cap, intf.name)
        evidence = [
            f"{intf.crc:,} CRC errors out of {intf.packets_in:,} input packets ({ratio:.2%})",
            f"Reliability {intf.reliability}/255",
        ]
        if flaps:
            evidence.append(f"Interface flapped {flaps} times in the log (correlated)")
        yield Finding(
            id="CRC_ERRORS",
            severity="critical" if ratio >= 0.001 or flaps else "warning",
            title="Physical layer errors (CRC)",
            target=intf.name + (f" ({intf.description})" if intf.description else ""),
            evidence=evidence,
            likely_cause="A damaged or poor-quality cable, a bad patch panel port, a failing SFP or NIC, or electrical interference.",
            next_steps=[
                f"test cable-diagnostics tdr interface {intf.name}",
                f"show interfaces {intf.name} transceiver detail  # if fibre/SFP",
                "Replace the patch cable, then move the device to another port to isolate it",
            ],
        )


def _flap_count(cap: Capture, ifname: str) -> int:
    key = normalize_ifname(ifname)
    return sum(
        1
        for l in cap.logs
        if l.mnemonic == "UPDOWN" and "to down" in l.message and _log_iface(l.message) == key
    )


def _log_iface(message: str) -> str:
    m = re.search(r"Interface (\S+?),", message)
    return normalize_ifname(m.group(1)) if m else ""


@rule
def link_flapping(cap: Capture):
    downs = Counter(
        _log_iface(l.message) for l in cap.logs if l.mnemonic == "UPDOWN" and "to down" in l.message
    )
    for iface, count in downs.items():
        if count < 3:
            continue
        intf = cap.interface(iface)
        name = intf.name if intf else iface
        ts = [l.timestamp for l in cap.logs if l.mnemonic == "UPDOWN" and _log_iface(l.message) == iface]
        yield Finding(
            id="LINK_FLAP",
            severity="critical",
            title="Link flapping",
            target=name + (f" ({intf.description})" if intf and intf.description else ""),
            evidence=[f"{count} down/up cycles between {ts[0]} and {ts[-1]}"]
            + ([f"Same port has {intf.crc:,} CRC errors"] if intf and intf.crc else []),
            likely_cause="An unstable physical link (cabling/SFP) or the connected device rebooting or losing power.",
            next_steps=[
                f"show logging | include {name}",
                f"show interfaces {name} counters errors",
                "Consider `link state dampening` / `carrier-delay` while the root cause is fixed",
            ],
        )


# --------------------------------------------------------------------------- routing
@rule
def ospf_adjacency(cap: Capture):
    for n in cap.ospf_neighbors:
        if n.state == "FULL" or (n.state == "2WAY" and n.role.upper() == "DROTHER"):
            continue
        related = [l for l in cap.logs if l.facility == "OSPF" and (n.address in l.message or n.neighbor_id in l.message)]
        mtu = any("mtu" in l.message.lower() for l in related)
        evidence = [f"Neighbor {n.neighbor_id} ({n.address}) on {n.interface} is stuck in {n.state}"]
        evidence += [f"Log {l.timestamp}: %{l.code}: {l.message[:160]}" for l in related]

        if n.state in ("EXSTART", "EXCHANGE"):
            cause = "MTU mismatch between the two interfaces." if mtu else (
                "Usually an MTU mismatch; can also be a duplicate router-id or unicast reachability issues.")
            steps = [f"show ip ospf interface {n.interface}", "show interface <peer side> | include MTU",
                     "Make MTU identical on both sides (or `ip ospf mtu-ignore` as a temporary workaround)"]
        elif n.state == "INIT":
            cause = ("Hellos are received from the neighbor but it does not see ours: one-way communication, "
                     "an ACL blocking 224.0.0.5, or authentication / hello-dead timer mismatch.")
            steps = [f"show ip ospf interface {n.interface}", "debug ip ospf hello  # briefly, look for mismatched parameters",
                     "Check ACLs and authentication configuration on both sides"]
        else:
            cause = "Adjacency not completing; check area, timers, authentication and network type on both sides."
            steps = [f"show ip ospf interface {n.interface}"]

        yield Finding("OSPF_ADJACENCY", "critical", "OSPF adjacency not FULL", f"{n.neighbor_id} via {n.interface}",
                      evidence, cause, steps)


# --------------------------------------------------------------------------- capacity / control plane
@rule
def utilisation(cap: Capture):
    for intf in cap.interfaces:
        peak = max(intf.txload, intf.rxload)
        if peak < 204 and not intf.output_drops:  # 204/255 = 80%
            continue
        evidence = [f"txload {intf.txload}/255 ({intf.txload / 255:.0%}), rxload {intf.rxload}/255 ({intf.rxload / 255:.0%})"]
        if intf.output_drops:
            evidence.append(f"{intf.output_drops:,} output drops (queue overflow)")
        yield Finding(
            id="CONGESTION",
            severity="warning",
            title="Link congestion",
            target=intf.name + (f" ({intf.description})" if intf.description else ""),
            evidence=evidence,
            likely_cause="The link is near capacity, so egress queues overflow and packets are dropped. Users see slowness and retransmissions.",
            next_steps=[
                f"show interfaces {intf.name} | include rate|drops",
                "Identify top talkers (NetFlow / `show ip cache flow`)",
                "Add an EtherChannel member, upgrade the uplink, or apply QoS to protect voice/critical traffic",
            ],
        )


@rule
def high_cpu(cap: Capture):
    if not cap.cpu or cap.cpu["5m"] < 50:
        return
    top = ", ".join(f"{name} {pct:.0f}%" for name, pct in cap.cpu_top[:3])
    ip_input = any(name.startswith("IP Input") for name, _ in cap.cpu_top[:2])
    yield Finding(
        id="HIGH_CPU",
        severity="critical" if cap.cpu["5m"] >= 70 else "warning",
        title="High CPU utilisation",
        target=cap.hostname,
        evidence=[f"CPU 5s/1m/5m: {cap.cpu['5s']}% / {cap.cpu['1m']}% / {cap.cpu['5m']}%"]
        + ([f"Top processes: {top}"] if top else []),
        likely_cause=(
            "`IP Input` at the top means traffic is being process-switched by the CPU. Common causes are a broadcast storm or L2 loop, "
            "packets punted by ACL logging, or traffic destined to the switch itself."
            if ip_input else "A control-plane process is consuming CPU; check the process list."
        ),
        next_steps=["show processes cpu history", "show interfaces | include broadcast", "show ip traffic"],
    )


@rule
def mac_flapping(cap: Capture):
    flaps = [l for l in cap.logs if l.mnemonic == "MACFLAP_NOTIF"]
    if not flaps:
        return
    m = re.search(r"Host (\S+) in vlan (\d+) is flapping between port (\S+) and port (\S+)", flaps[0].message)
    target = f"VLAN {m.group(2)}: {m.group(3)} ↔ {m.group(4)}" if m else "unknown"
    yield Finding(
        id="MAC_FLAP",
        severity="critical",
        title="MAC address flapping (possible Layer 2 loop)",
        target=target,
        evidence=[f"{len(flaps)} MACFLAP notifications, first at {flaps[0].timestamp}"]
        + ([f"Host {m.group(1)} seen alternately on {m.group(3)} and {m.group(4)}"] if m else []),
        likely_cause="A Layer 2 loop (an unmanaged switch or a cable plugged into two ports), or a server NIC team misconfigured.",
        next_steps=[
            "show spanning-tree summary  # is STP enabled on the VLAN?",
            f"show mac address-table address {m.group(1) if m else '<mac>'}",
            "Enable BPDU Guard on access ports: `spanning-tree portfast bpduguard default`",
        ],
    )


# --------------------------------------------------------------------------- informational
@rule
def config_changes(cap: Capture):
    changes = [l for l in cap.logs if l.mnemonic == "CONFIG_I"]
    if changes:
        yield Finding(
            id="CONFIG_CHANGE",
            severity="info",
            title="Recent configuration change",
            target=cap.hostname,
            evidence=[f"{l.timestamp}: {l.message}" for l in changes],
            likely_cause="If the problems started after this time, the change is a prime suspect.",
            next_steps=["show archive log config all", "Compare running config with the last backup"],
        )


def analyze(cap: Capture) -> list[Finding]:
    findings = [f for r in RULES for f in r(cap)]
    return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])


def health_score(findings: list[Finding]) -> int:
    penalty = sum({"critical": 20, "warning": 8, "info": 0}[f.severity] for f in findings)
    return max(0, 100 - penalty)
