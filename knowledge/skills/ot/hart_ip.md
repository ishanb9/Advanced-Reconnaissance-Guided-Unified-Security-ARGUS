---
id: hart_ip
technology: "HART-IP"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [5094]
  banners: ["HART-IP", "HART IP Server", "FieldComm"]
  markers: ["hart-ip", "01 00 00 00 00 00", "HART-IP/1"]
quick_wins:
  - { cmd: "nmap -Pn -sU -sT -p5094 --script banner {host}", safety: safe, note: "Probe both TCP and UDP 5094; banner reveals HART-IP server vendor and version. Read-only." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',5094)); hdr=struct.pack('>BBHHH',1,0,0,1,0); s.send(hdr); print(s.recv(256).hex()); s.close()\"", safety: safe, note: "Send HART-IP Command 0 (Read Unique Identifier) over TCP — returns manufacturer ID, device type, revision, and unique device tag. Read-only." }
  - { cmd: "<HART Command 75 / 76 / 79 write or initiate>", safety: disruptive, note: "GATED — write commands alter instrument configuration or trim calibration. Requires explicit authorization." }
references: ["CVE-2020-16209", "ICSA-20-252-01"]
mitre: "T0861"
---
# HART-IP guidance

HART-IP (Highway Addressable Remote Transducer over IP) is the Ethernet/IP encapsulation of the classic
HART field-instrument protocol. It listens on **5094/tcp and 5094/udp** and is used to configure and
monitor field instruments — pressure, temperature, flow, and level transmitters — in process plants,
water utilities, and oil-and-gas facilities. Like its serial predecessor, HART-IP was designed for a
trusted plant network and ships with **no authentication and no encryption** in its default configuration.

**Why it matters.** HART-IP grants full access to the HART command set: Command 0 returns a device's
unique identifier (manufacturer code, device type, tag, and firmware revision) without touching any
process variable. Higher commands let an attacker read live process data, write instrument tags,
change range/trim settings, or initiate self-test sequences — all of which can invalidate calibration
or, in worst cases, mask a process anomaly from the DCS. CVE-2020-16209 (CVSS 9.1, ICSA-20-252-01)
demonstrates an integer overflow in FieldComm Group's HART-IP Server that achieves remote code execution
before any authentication is required.

**Safe-first testing.** Begin with a dual-mode (`-sT -sU`) nmap scan on port 5094 combined with banner
grabbing to confirm the service. Follow with a hand-crafted Command 0 session-initiation packet — the
six-byte HART-IP header with command byte 0x00 — to read the unique device identifier. This is
**entirely read-only**: it touches no process variable and mirrors what a legitimate HART handheld
communicator does during device discovery. Do not issue any write command (Command 35 Write Tag,
Command 245 Write I/O Configuration, or any method command above Command 128) without an explicit,
scoped change-control approval and a human gate.

**Remediation.** Restrict 5094/tcp+udp to the asset-management VLAN and block from IT/user segments
at the firewall. Upgrade to HART-IP implementations that support the optional DTLS/TLS session layer
(introduced in HART-IP revision 2). Apply the vendor patch for CVE-2020-16209 where affected. Audit
all HART-IP servers with Shodan-style passive discovery before running active probes, and correlate
findings against CISA advisory ICSA-20-252-01 rather than relying on CVSS scores alone.
