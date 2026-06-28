---
id: can_uds
technology: "CAN bus + UDS"
domain: OT
transport: can
safety_class: intrusive
severity: critical
life_safety: true
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "cansniffer -c vcan0", safety: intrusive, note: "Passive CAN frame capture via SocketCAN. Requires SocketCAN adapter (Peak PCAN, Kvaser, CANable) or HWBridge connection. Read-only but physically attached to vehicle bus." }
  - { cmd: "candump -l vcan0", safety: intrusive, note: "Log all CAN frames to timestamped file for offline analysis with can-utils. SocketCAN adapter required — no frames injected." }
  - { cmd: "python3 -c \"import can; bus=can.interface.Bus('vcan0',bustype='socketcan'); [print(bus.recv()) for _ in range(200)]\"", safety: intrusive, note: "Passive sniff via python-can. Replace 'vcan0' with your physical interface (can0, slcan0). No transmission." }
  - { cmd: "caringcaribou.py uds discovery -min 0x00 -max 0x7F vcan0", safety: intrusive, note: "Caring Caribou UDS ECU discovery — sends Tester Present (0x3E) to each arbitration ID. Active but non-destructive; logs responding ECU addresses." }
  - { cmd: "caringcaribou.py uds services 0x7E0 vcan0", safety: intrusive, note: "Probe supported UDS services on ECU at CAN ID 0x7E0 (request) / 0x7E8 (response). Iterates all service IDs — active enumeration." }
  - { cmd: "caringcaribou.py uds read_data_by_identifier 0x7E0 0xF190 vcan0", safety: intrusive, note: "UDS 0x22 ReadDataByIdentifier — read VIN (DID 0xF190) from target ECU. Read-only diagnostic; requires physical CAN access." }
  - { cmd: "caringcaribou.py uds read_data_by_identifier 0x7E0 0xF189 vcan0", safety: intrusive, note: "UDS 0x22 ReadDataByIdentifier — read ECU software version (DID 0xF189). Read-only." }
  - { cmd: "caringcaribou.py xcp discovery vcan0", safety: intrusive, note: "Caring Caribou XCP (Extended Calibration Protocol) discovery — identifies ECUs accepting XCP CONNECT. Active scan; XCP can expose memory read/write." }
  - { cmd: "<caringcaribou.py uds security_access 0x7E0 vcan0> or <cansend vcan0 7E0#0227010000000000>", safety: disruptive, note: "GATED — UDS 0x27 SecurityAccess or arbitrary frame injection. Can corrupt ECU state, trigger fault codes, disable airbags or ABS. Requires explicit written authorization and a defined recovery procedure." }
references: ["CVE-2015-5611", "CVE-2024-23959", "DEF CON 23 - Miller & Valasek 'Remote Exploitation of an Unaltered Passenger Vehicle'", "Black Hat 2014 - 'A Survey of Remote Automotive Attack Surfaces'", "ICSA-21-257-01", "ISO 14229-1 (UDS)", "ISO 11898 (CAN)"]
mitre: "T0854 / ICS T0843"
---
# CAN bus + UDS guidance

CAN bus (ISO 11898) is the primary in-vehicle network that connects ECUs controlling the engine,
transmission, brakes (ABS/ESC), airbags, and other safety-critical systems. It is a shared,
broadcast medium with **no authentication, no encryption, and no access control** — any node
physically connected to the bus can send frames to any other. Unified Diagnostic Services (UDS,
ISO 14229) is the diagnostic protocol layered on top of CAN (and increasingly Automotive Ethernet
via DoIP, ISO 13400); it exposes services for reading sensor data, fault codes, and VIN (0x22),
clearing faults (0x14), unlocking extended sessions (0x27 SecurityAccess), and reflashing firmware
(0x34/0x36/0x37). This combination is the primary attack surface for automotive security
assessments. ARGUS surfaces this protocol as operator guidance only — execution requires physical
bus hardware and explicit engagement authorization.

**Hardware required.** To interact with a CAN bus you need a SocketCAN-compatible adapter: Peak
PCAN-USB, Kvaser Leaf, CANable/CANtact, or a Raspberry Pi with MCP2515 shield. The adapter
exposes a Linux `can0` / `vcan0` network interface consumed by **can-utils** (`candump`,
`cansend`, `cansniffer`) and **python-can**. The **Caring Caribou** toolkit (GitHub:
CaringCaribou/caringcaribou) provides structured UDS, XCP, and fuzzing modules over this
interface. For remote-access scenarios the **HWBridge** protocol (Metasploit auxiliary) allows a
can-utils instance on a pivot host to be tunnelled back to the operator over TCP. A Flipper Zero
with the Vehicle CAN module can perform basic frame sniffing and replay for triage, but Caring
Caribou over SocketCAN is the authoritative toolchain. DoIP (port 13400) is the IP-side foothold
when vehicle Ethernet is reachable — once a routing-activation session is open, UDS frames can
be tunnelled without a physical CAN adapter (see the `doip` skill for that path).

**Passive-first, always.** Begin with **read-only passive sniffing** (`candump -l can0`) to
record traffic before transmitting any frame. Analyse the capture offline with `cantools` and
a DBC/ARXML database file to decode signal values and identify ECU arbitration IDs. Use Caring
Caribou's `uds discovery` module to locate UDS-capable ECUs by probing Tester Present (0x3E),
then enumerate supported services with `uds services` before reading any DID. UDS **0x22
ReadDataByIdentifier** against known DIDs (F190 VIN, F111 part number, F189 SW version, F18C
manufacturing date) is the safe enumeration layer — it changes no ECU state. **Never** inject
arbitrary CAN frames, send UDS SecurityAccess unlock sequences (0x27), WriteDataByIdentifier
(0x2E), or RoutineControl (0x31) commands, or attempt XCP memory writes without written
authorization, a vehicle in a controlled environment (ignition off or dynamometer), and a
defined ECU recovery procedure. A single malformed UDS write to a body-control or powertrain
ECU can disable safety systems or require dealer reflash.

**Life safety and scope.** CAN bus attacks are `life_safety: true`. Injecting frames to a
running vehicle CAN bus — even during a scope-limited pentest — can disable ABS, trigger
unintended airbag deployment, or interfere with power steering on steer-by-wire platforms. All
testing must be conducted with the vehicle stationary, engine off where possible, and with the
OEM or client engineering team present. Findings should be mapped to **UNECE WP.29 R155**
(vehicle cybersecurity) and **ISO/SAE 21434** risk framework rather than CVSS alone. Remediation
involves CAN bus segmentation with gateway firewalls, UDS SecurityAccess hardening (PKI-based
certificate authentication replacing static seed/key), disabling diagnostic services in
production firmware via ECU configuration, and network anomaly detection on the vehicle gateway
logging all diagnostic session attempts.