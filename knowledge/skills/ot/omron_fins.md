---
id: omron_fins
technology: "OMRON FINS"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [9600]
  banners: ["OMRON FINS", "CJ2", "NJ501", "NX102", "CS1"]
  markers: ["fins-tcp", "\\x46\\x49\\x4e\\x53\\x00", "FINS/TCP node"]
quick_wins:
  - { cmd: "nmap -Pn -sU -sT -p9600 --script omron-info {host}", safety: safe, note: "Read CPU model, firmware version, and unit configuration via FINS CPU Unit Data Read (command 0501). Read-only." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',9600)); fins=bytes([0x80,0x00,0x02,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x05,0x01]); s.send(fins); print(s.recv(256).hex())\"", safety: safe, note: "Raw FINS-TCP CPU Unit Data Read (cmd 05 01) — returns model string and firmware. Read-only, no state change." }
  - { cmd: "<FINS Memory Area Read 0x0101 — read DM/IO/HR regions>", safety: intrusive, note: "Active read of process memory areas (DM, CIO, HR, AR). Non-destructive but reveals live process values; obtain authorization before enumerating production PLCs." }
  - { cmd: "<FINS Program Area Write / Memory Area Write 0x0102>", safety: disruptive, note: "GATED — overwrites PLC program or data memory; can alter process logic and halt live production. Requires explicit, scoped authorization and human gate." }
references: ["CVE-2023-27396", "ICSA-22-090-05", "ICSA-16-336-05"]
mitre: "T0843 / ICS T0821"
---
# OMRON FINS

OMRON FINS (Factory Interface Network Service) is a proprietary application-layer protocol
used across OMRON PLCs (CJ, CS, NJ, NX, CP series) for peer-to-peer and host-to-PLC
communication. It runs on **9600/tcp** (FINS-TCP) and **9600/udp** (FINS-UDP), operates
with **no authentication and no encryption**, and was designed for isolated factory
segments. Any host that can reach port 9600 can read CPU identity and firmware, enumerate
memory regions, and — without additional controls — overwrite program and data memory.

**CPU Data Read is the safe entry point.** FINS command **05 01** (CPU Unit Data Read) and
**05 02** (CPU Unit Status Read) return the PLC model string, firmware version, run/stop
state, and error registers with zero side effects. The Nmap `omron-info` script issues
exactly these commands and is the preferred first-touch probe. Avoid crafting raw UDP
packets against production targets because FINS-UDP does not guarantee idempotency at the
network layer.

**Memory and program access requires scoped authorization.** Memory Area Read (01 01) and
Memory Area Write (01 02) operate on CIO, DM, HR, AR, and timer/counter regions.
Reads are active-but-non-destructive; a single Write can change a setpoint, trip a relay,
or corrupt a running ladder program — equivalent to physically modifying wiring on a live
panel. Program Area Write (03 01–03 03) allows upload and download of the full PLC program.
Never issue write commands against a live target without explicit authorization, a defined
test window, and a qualified OT engineer present.

**Remediation.** Segment CX-Programmer and FINS traffic to a dedicated engineering VLAN
with firewall rules restricting 9600/tcp+udp to authorized engineering workstations only.
Where firmware supports it, enable FINS node verification (IP address filtering on the
OMRON CPU unit itself). Monitor for unexpected FINS sessions from IT-side hosts. Map
findings to CISA ICS advisories (ICSA-22-090-05, ICSA-16-336-05) and the relevant
OMRON security bulletins, which track the protocol's lack of origin authentication as a
known architectural limitation.
