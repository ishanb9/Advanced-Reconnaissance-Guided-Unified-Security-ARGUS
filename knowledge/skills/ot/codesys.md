---
id: codesys
technology: "CODESYS Runtime"
domain: OT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [1200, 2455, 11740]
  banners: ["CODESYS", "CmpGateway", "3S Smart Software", "WAGO", "Beckhoff"]
  markers: ["CmpGateway", "3S-Smart", "CODESYS V3", "codesys-runtime"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p1200,2455,11740 --script banner {host}", safety: safe, note: "Grab banner — reveals CODESYS version, OEM PLC brand, and runtime build string. Read-only." }
  - { cmd: "nmap -Pn -sT -p1200,2455,11740 -sV {host}", safety: safe, note: "Service version probe — distinguishes V2 (1200/2455) from V3 (11740) and fingerprints OEM fleet." }
  - { cmd: "nmap -Pn -sT -p11740 --script codesys-v3-info {host}", safety: safe, note: "CODESYS V3 info script — reads device name, vendor, serial, application state. No writes." }
  - { cmd: "python3 -c \"import socket,sys; s=socket.create_connection(('{host}',1200),3); s.send(b'\\x00\\x00\\x00\\x00'); print(s.recv(256).hex())\"", safety: intrusive, note: "Raw CmpGateway V2 probe — elicits gateway identification packet. Active but no state change." }
  - { cmd: "<CODESYS V3 write PLC application / force variable>", safety: disruptive, note: "GATED — downloads or modifies PLC logic, forces process variables; can halt running machinery. Requires explicit authorization." }
references: ["CVE-2023-37545", "CVE-2023-37546", "CVE-2023-37547", "CVE-2023-37548", "CVE-2023-37549", "CVE-2025-0631", "CVE-2025-0632", "ICSA-23-208-01"]
mitre: "T0843 / T0821"
---
# CODESYS Runtime

CODESYS (Controller Development System) is a vendor-neutral IEC 61131-3 development and
runtime environment published by 3S-Smart Software Solutions. Because it is embedded as a
licensed runtime inside PLCs and PACs from **hundreds of OEMs** — including Wago, Schneider,
Beckhoff, B&R, Phoenix Contact, and many others — a single open port can reveal the entire
OEM fleet at a site. **V2** surfaces on **1200/tcp** (CmpGateway) and **2455/tcp** (programming
channel); **V3** moves to **11740/tcp** (unified communication channel). Banner and service-version
responses typically disclose vendor name, firmware string, and hardware model before any
authentication is attempted.

**Banner-based fleet identification.** Because CODESYS licenses are embedded, the banner
response from port 1200/11740 is often the fastest path to understanding which PLC vendor is
deployed across a site. A single `nmap -sV` sweep can fingerprint dozens of distinct OEM
models (Wago 750-xxx, Beckhoff CX-series, Schneider SoMachine targets, etc.) with no
authentication required. This OEM diversity matters: a Nozomi 2023 advisory (ICSA-23-208-01)
disclosed **15 CVEs** (CVE-2023-37545 through -37549 and related) across CODESYS V3 covering
heap overflows in the CmpGateway and CmpApp components, allowing unauthenticated remote
code execution and denial-of-service on any OEM PLC running the affected runtime — regardless
of brand.

**Safe-first testing.** Start with read-only banner grabs and `nmap -sV` to confirm CODESYS
version and OEM identity without modifying controller state. The CODESYS V3 NSE script
(`codesys-v3-info`) reads device metadata and application run/stop status through the session
layer without issuing any write or download primitives. Only escalate to active probing (raw
gateway packets) if the banner alone is insufficient — these still send no write commands.
**Never** issue PLC application download, variable force, or run/stop commands against a live
target without explicit written authorization and a human gate; CODESYS application writes can
alter setpoints, restart PLCs, or modify interlock logic mid-process.

**Remediation.** Apply the 3S-Smart Software patched CODESYS V3 runtime (≥ 3.5.19.40 for
the Nozomi 2023 batch; verify CVE-2025-0631/0632 patch status for 2025 additions). Segment
CODESYS ports behind an OT DMZ — there is no legitimate reason for 1200/2455/11740 to be
reachable from IT or the internet. Enable CODESYS user-management and certificate-based
authentication (V3.5.17+). Monitor for unexpected programming-channel sessions (port 11740
connections outside maintenance windows) and map findings to CISA ICSA-23-208-01 and the
vendor-specific advisories rather than raw CVSS scores alone, which under-represent OT impact.
