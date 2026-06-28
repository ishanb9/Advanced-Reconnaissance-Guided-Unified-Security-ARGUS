---
id: doip
technology: "DoIP (automotive over IP)"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [13400]
  banners: ["DoIP", "ISO 13400", "DoIP Gateway"]
  markers: ["ff fe 00 01", "ff fe 00 05", "routing-activation", "Vehicle-Identification"]
quick_wins:
  - { cmd: "nmap -Pn -sU -sT -p13400 --script doip-info {host}", safety: safe, note: "Identify DoIP gateway: entity status, logical address, EID/GID. Read-only." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',13400)); hdr=struct.pack('>BBHI',0xFF,0xFE,0x0001,0x00); s.send(hdr); print(s.recv(256).hex()); s.close()\"", safety: safe, note: "Send DoIP Vehicle Identification Request (payload type 0x0001) — returns VIN, EID, GID. Passive read." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',13400)); act=struct.pack('>BBHIHH',0xFF,0xFE,0x0005,0x07,0x0000,0x0000,0x00); s.send(act); print(s.recv(256).hex()); s.close()\"", safety: intrusive, note: "Send Routing Activation Request to open a UDS channel. Required before sending UDS — active but non-destructive if no UDS payload follows." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',13400)); # Routing activation first, then UDS 0x22 ReadDataByIdentifier DID 0xF190 (VIN); uds=bytes([0x22,0xF1,0x90]); hdr=struct.pack('>BBHIHHB',0xFF,0xFE,0x8001,len(uds)+5,0x0E00,0x0010,0x00)+uds; s.send(hdr); print(s.recv(256).hex()); s.close()\"", safety: intrusive, note: "UDS 0x22 ReadDataByIdentifier — read VIN (F190), ECU part number (F111), SW version (F189). Read-only diagnostic; active session required." }
  - { cmd: "<UDS 0x27 SecurityAccess seed/key unlock then 0x2E WriteDataByIdentifier or 0x31 RoutineControl>", safety: disruptive, note: "GATED — writing calibration data or triggering routines can corrupt ECU firmware or alter safety parameters. Requires explicit, scoped authorization." }
references: ["CVE-2023-28655", "CVE-2022-39023", "ICSA-22-244-01"]
mitre: "T0843 / ICS T0866"
---
# DoIP (Diagnostic over IP)

DoIP (ISO 13400) is the automotive standard that tunnels **UDS (ISO 14229) diagnostic
messages over TCP/IP**, replacing the old K-line and CAN-based transport layers used in
traditional vehicle diagnostics. It listens on **13400/tcp and 13400/udp**: UDP is used for
network discovery (Vehicle Identification Request/Response, Entity Status), while TCP carries
the full diagnostic session including routing activation and UDS payload exchange. Modern
vehicles, charging stations, and telematics gateways increasingly expose DoIP on internal
Ethernet (100BASE-T1 automotive Ethernet) and, critically, on OBD-II interfaces and backend
servers reachable over cellular/Wi-Fi.

**Why it matters for assessors.** A DoIP gateway with no authentication and no firewall is a
remote OBD port. An attacker who completes routing activation can send arbitrary UDS commands
to every ECU behind the gateway — reading VIN, odometer, fault codes (0x19), live sensor data
(0x22), and, with a SecurityAccess seed/key bypass (0x27), potentially writing calibration data
or flashing firmware (0x34/0x36/0x37). The attack surface is particularly acute in vehicles
that expose DoIP over Wi-Fi hotspots or in fleet telematics servers that proxy diagnostic
channels for remote diagnostics.

**Safe-first testing.** Begin with **UDP discovery** (payload type 0x0001 Vehicle Identification
Request) to recover the VIN, EID (entity ID), and GID (group ID) — this is fully read-only
and mirrors what a workshop scan tool sends before connecting. Follow with a TCP connection and
a Routing Activation Request (payload type 0x0005) which opens a logical UDS channel; stop at
this stage unless a deeper session is authorized. UDS **0x22 ReadDataByIdentifier** against
well-known DIDs (F190 VIN, F111 part number, F18C manufacturing date) is the safe enumeration
layer — it changes no state. **Never** send UDS SecurityAccess unlock attempts, WriteData,
or RoutineControl commands without written authorization and a defined rollback procedure;
ECU bricking is a real outcome.

**Remediation.** Restrict DoIP gateway access to authenticated diagnostic tools using TLS client
certificates or firewall ACLs tied to workshop IP ranges. Require SecurityAccess (seed/key or
PKI-based certificate authentication per ISO 14229-1:2023) before any write-capable UDS service.
Segment vehicle Ethernet from infotainment and telematics interfaces. Log all Routing Activation
attempts and alert on requests from unexpected source logical addresses. Reference UNECE WP.29
R155/R156 cybersecurity regulations and ISO/SAE 21434 for a full OEM risk framework.
