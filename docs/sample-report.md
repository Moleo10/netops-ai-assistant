# NetOps report: BRANCH-SW01

_Analysis mode: offline_

| Health score | Critical | Warning | Info | Interfaces parsed | OSPF neighbors | Log lines |
|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| **0/100** | 7 | 1 | 1 | 4 | 3 | 12 |

## Summary
BRANCH-SW01: 7 critical and 1 warning findings. Most urgent: **Duplex mismatch** on GigabitEthernet1/0/1 (FINANCE-PC-01).

## Action plan
1. **Duplex mismatch** (GigabitEthernet1/0/1 (FINANCE-PC-01)): show interfaces GigabitEthernet1/0/1 status
2. **Physical layer errors (CRC)** (GigabitEthernet1/0/2 (PRINTER-2F)): test cable-diagnostics tdr interface GigabitEthernet1/0/2
3. **Link flapping** (GigabitEthernet1/0/2 (PRINTER-2F)): show logging | include GigabitEthernet1/0/2
4. **OSPF adjacency not FULL** (10.255.0.7 via Vlan100): show ip ospf interface Vlan100
5. **OSPF adjacency not FULL** (10.255.0.9 via Vlan200): show ip ospf interface Vlan200
6. **High CPU utilisation** (BRANCH-SW01): show processes cpu history
7. **MAC address flapping (possible Layer 2 loop)** (VLAN 10: Gi1/0/5 ↔ Gi1/0/6): show spanning-tree summary  # is STP enabled on the VLAN?
8. **Link congestion** (GigabitEthernet1/0/24 (UPLINK-TO-CORE)): show interfaces GigabitEthernet1/0/24 | include rate|drops

_Offline mode: set `ANTHROPIC_API_KEY` for an AI root-cause analysis that correlates the findings._

---

# Findings (evidence)

### 🔴 Duplex mismatch: `GigabitEthernet1/0/1 (FINANCE-PC-01)`

**Evidence**
- GigabitEthernet1/0/1 is running Half-duplex at 100Mb/s
- 3,398 late collisions (a classic duplex-mismatch symptom)
- Log Nov 14 11:02:17.920: %CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered on GigabitEthernet1/0/1 (not half duplex), with FIN-SW02 GigabitEthernet0/3 (full duplex).

**Likely cause:** One side is hard-coded to full duplex while the other auto-negotiates and falls back to half duplex.

**Next steps**
```
show interfaces GigabitEthernet1/0/1 status
Set both ends to auto/auto (preferred) or the same fixed speed/duplex
clear counters GigabitEthernet1/0/1  # then confirm late collisions stop increasing
```

### 🔴 Physical layer errors (CRC): `GigabitEthernet1/0/2 (PRINTER-2F)`

**Evidence**
- 47,902 CRC errors out of 8,821,930 input packets (0.54%)
- Reliability 251/255
- Interface flapped 3 times in the log (correlated)

**Likely cause:** A damaged or poor-quality cable, a bad patch panel port, a failing SFP or NIC, or electrical interference.

**Next steps**
```
test cable-diagnostics tdr interface GigabitEthernet1/0/2
show interfaces GigabitEthernet1/0/2 transceiver detail  # if fibre/SFP
Replace the patch cable, then move the device to another port to isolate it
```

### 🔴 Link flapping: `GigabitEthernet1/0/2 (PRINTER-2F)`

**Evidence**
- 3 down/up cycles between Nov 14 09:12:03.411 and Nov 14 10:02:12.551
- Same port has 47,902 CRC errors

**Likely cause:** An unstable physical link (cabling/SFP) or the connected device rebooting or losing power.

**Next steps**
```
show logging | include GigabitEthernet1/0/2
show interfaces GigabitEthernet1/0/2 counters errors
Consider `link state dampening` / `carrier-delay` while the root cause is fixed
```

### 🔴 OSPF adjacency not FULL: `10.255.0.7 via Vlan100`

**Evidence**
- Neighbor 10.255.0.7 (10.1.1.7) on Vlan100 is stuck in EXSTART
- Log Nov 14 10:15:00.118: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.0.7 on Vlan100 from FULL to EXSTART, Neighbor Down: Too many retransmissions
- Log Nov 14 10:15:40.812: %OSPF-4-ERRRCV: Received invalid packet: mismatched MTU from 10.1.1.7, Vlan100

**Likely cause:** MTU mismatch between the two interfaces.

**Next steps**
```
show ip ospf interface Vlan100
show interface <peer side> | include MTU
Make MTU identical on both sides (or `ip ospf mtu-ignore` as a temporary workaround)
```

### 🔴 OSPF adjacency not FULL: `10.255.0.9 via Vlan200`

**Evidence**
- Neighbor 10.255.0.9 (10.1.2.9) on Vlan200 is stuck in INIT

**Likely cause:** Hellos are received from the neighbor but it does not see ours: one-way communication, an ACL blocking 224.0.0.5, or authentication / hello-dead timer mismatch.

**Next steps**
```
show ip ospf interface Vlan200
debug ip ospf hello  # briefly, look for mismatched parameters
Check ACLs and authentication configuration on both sides
```

### 🔴 High CPU utilisation: `BRANCH-SW01`

**Evidence**
- CPU 5s/1m/5m: 91% / 87% / 79%
- Top processes: IP Input 41%, ARP Input 18%, Spanning Tree 6%

**Likely cause:** `IP Input` at the top means traffic is being process-switched by the CPU. Common causes are a broadcast storm or L2 loop, packets punted by ACL logging, or traffic destined to the switch itself.

**Next steps**
```
show processes cpu history
show interfaces | include broadcast
show ip traffic
```

### 🔴 MAC address flapping (possible Layer 2 loop): `VLAN 10: Gi1/0/5 ↔ Gi1/0/6`

**Evidence**
- 2 MACFLAP notifications, first at Nov 14 10:22:31.077
- Host 0050.56a1.22b3 seen alternately on Gi1/0/5 and Gi1/0/6

**Likely cause:** A Layer 2 loop (an unmanaged switch or a cable plugged into two ports), or a server NIC team misconfigured.

**Next steps**
```
show spanning-tree summary  # is STP enabled on the VLAN?
show mac address-table address 0050.56a1.22b3
Enable BPDU Guard on access ports: `spanning-tree portfast bpduguard default`
```

### 🟠 Link congestion: `GigabitEthernet1/0/24 (UPLINK-TO-CORE)`

**Evidence**
- txload 231/255 (91%), rxload 120/255 (47%)
- 88,123 output drops (queue overflow)

**Likely cause:** The link is near capacity, so egress queues overflow and packets are dropped. Users see slowness and retransmissions.

**Next steps**
```
show interfaces GigabitEthernet1/0/24 | include rate|drops
Identify top talkers (NetFlow / `show ip cache flow`)
Add an EtherChannel member, upgrade the uplink, or apply QoS to protect voice/critical traffic
```

### 🔵 Recent configuration change: `BRANCH-SW01`

**Evidence**
- Nov 14 10:40:02.551: Configured from console by admin on vty0 (10.9.9.9)

**Likely cause:** If the problems started after this time, the change is a prime suspect.

**Next steps**
```
show archive log config all
Compare running config with the last backup
```
