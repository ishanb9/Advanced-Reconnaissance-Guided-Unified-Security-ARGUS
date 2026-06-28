---
id: iconics-genesis64
technology: "ICONICS GENESIS64 SCADA/HMI"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [8778, 4840]
  banners: ["ICONICS", "GENESIS64", "Genesis32", "FrameWorX"]
  markers: ["iconics", "genesis64", "FrameWorX", "/ICONICS/", "ICONICS.Dynamics"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p8778 -sV {host}", safety: safe, note: "ICONICS WebHMI / Hyper Historian service; banner reveals product and version." }
  - { cmd: "nmap -Pn -sT -p4840 --script opcua-info {host}", safety: safe, note: "GENESIS64 exposes OPC-UA for data connectivity; enumerate endpoints and security policies read-only." }
  - { cmd: "curl -sk http://{host}:8778/ -I", safety: safe, note: "HTTP header grab on ICONICS WebHMI port; response includes server header and version information." }
  - { cmd: "<ICONICS GENESIS64 WebHMI login page enumeration>", safety: safe, note: "Read-only HTTP enumeration of WebHMI login page for version disclosure in page source." }
references: ["CVE-2022-33315", "CVE-2022-33316", "CVE-2022-33317", "CVE-2021-27453", "ICSA-22-181-01"]
mitre: "T0817 / ICS T0856"
---
# ICONICS GENESIS64 SCADA/HMI

ICONICS GENESIS64 is a Microsoft-certified SCADA/HMI platform built natively on .NET and OPC-UA,
widely deployed in building automation, energy management, power utilities, and smart
manufacturing. The platform includes GraphWorX64 (HMI display), TrendWorX64 (historian),
AlarmWorX64 (alarm management), and Hyper Historian for high-speed data capture. Clients access
the system via browser-based WebHMI on TCP 8778, via a .NET thick client, or through OPC-UA on
4840. The platform connects to PLCs, BAS controllers, and historians via OPC-UA, OPC-DA/DCOM,
and Modbus/TCP interfaces.

**Attack surface.** CVE-2022-33315 through 33317 (path traversal, deserialization, and
authentication bypass in GENESIS64 WebHMI) allow pre-authentication RCE in versions prior to
10.97.2. CVE-2021-27453 (use-after-free in the ICONICS configuration service) allows RCE via
crafted project files. The WebHMI interface on 8778/tcp may expose unauthenticated configuration
endpoints in default installations. GENESIS64 project files (`.gdfx`, `.gdfxp`) are XML-based
and can be modified to inject scripted actions — the platform's QuickScript64 engine can access
the Windows OS and write OPC-UA values to connected PLCs.

**Safe-first testing.** Begin with HTTP enumeration of the WebHMI on port 8778 and OPC-UA
endpoint discovery on 4840. Check whether the WebHMI login page discloses the product version in
HTML source or HTTP headers. Enumerate OPC-UA endpoints using `opcua-info` (NSE) — this is a
read-only operation that reveals server name, application URI, and security modes. Do not attempt
QuickScript64 execution or OPC-UA write services against live systems — GENESIS64 is deployed to
control physical processes including building HVAC (life-safety relevance), electrical substations,
and manufacturing lines.

**Remediation.** Upgrade to GENESIS64 10.97.2 or later (patches CVE-2022-33315-33317). Restrict
WebHMI access (TCP 8778) to engineering workstations and enable authentication. Configure OPC-UA
with `SignAndEncrypt` security mode. Implement allowlisting on GENESIS64 server nodes. Review
project files for unauthorized QuickScript64 code. Disable OPC-DA/DCOM connectivity and migrate
fully to OPC-UA where possible.
