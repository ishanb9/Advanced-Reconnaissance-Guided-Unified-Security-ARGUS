---
id: kepware-kepserverex
technology: "PTC Kepware KEPServerEX OPC Server"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [57412, 49320, 4840]
  banners: ["KEPServerEX", "Kepware", "ThingWorx Kepware"]
  markers: ["kepware", "kepserverex", "KEPServerEX", "/config/v1/", "KepServer"]
quick_wins:
  - { cmd: "curl -sk https://{host}:57412/config/v1/server/properties -H 'Accept: application/json'", safety: safe, note: "KEPServerEX Configuration API root; may respond unauthenticated and reveals server version and build." }
  - { cmd: "nmap -Pn -sT -p57412,49320,4840 -sV {host}", safety: safe, note: "Fingerprint KEPServerEX Configuration API (57412), OPC-UA (4840), and OPC-DA dynamic port (49320)." }
  - { cmd: "nmap -Pn -sT -p4840 --script opcua-info {host}", safety: safe, note: "OPC-UA endpoint enumeration on KEPServerEX; reveals server name, URI, and security mode." }
  - { cmd: "<GET /config/v1/project/channels to enumerate driver channels>", safety: safe, note: "Read-only REST API enumeration of KEPServerEX channels and connected devices — reveals PLC inventory." }
  - { cmd: "<PUT /config/v1/project/channels/<channel>/devices/<device>/tags with write value>", safety: disruptive, note: "GATED — REST API tag writes flow through to the PLC; can actuate process equipment." }
references: ["CVE-2023-29444", "CVE-2023-29445", "CVE-2022-2825", "CVE-2020-27265", "ICSA-23-108-01", "ICSA-22-228-01"]
mitre: "T0817 / ICS T0836"
---
# PTC Kepware KEPServerEX OPC Server

KEPServerEX (now PTC ThingWorx Kepware Server) is the world's most widely deployed OPC
aggregation server, used as a universal industrial connectivity hub in thousands of plants
globally. It acts as a single OPC-UA and OPC-DA server that bridges 150+ industrial protocols
— including Modbus, EtherNet/IP, S7comm, DNP3, and BACnet — to SCADA/HMI applications.
KEPServerEX exposes a REST-based Configuration API on **TCP 57412** (HTTPS) that allows
programmatic creation, modification, and deletion of channels, devices, and tags at runtime.
OPC-UA is served on **4840/tcp** and OPC-DA via DCOM on **135/tcp** plus dynamic ports.

**Attack surface.** The Configuration REST API on 57412/tcp is the primary attack surface:
default credentials (`Administrator` with empty password or `ptc`/`ptc`) allow full remote
configuration control, including adding new PLC connections, modifying tag definitions, and
changing communication parameters. CVE-2023-29444 and CVE-2023-29445 (heap buffer overflow
and use-after-free in the Configuration API) allow pre-authentication RCE. CVE-2022-2825
(improper access control) allows low-privileged users to read the project configuration.
Because KEPServerEX is a **protocol gateway** wired to every PLC on the OT network, a single
compromise provides immediate read/write access to all connected field devices simultaneously.

**Safe-first testing.** Issue a GET to `/config/v1/server/properties` — this often responds
without authentication and reveals the version. Enumerate `/config/v1/project/channels` to
map the PLC inventory. OPC-UA endpoint enumeration on 4840 is read-only. Do not issue any
Configuration API PUT/POST/DELETE requests without explicit authorization — modifying channels
or tags can immediately disrupt communication between SCADA and PLCs. Do not write tag values
via OPC-UA or the REST API without authorization — KEPServerEX forwards writes directly to
connected field devices.

**Remediation.** Set a strong Administrator password on KEPServerEX immediately (default is
blank). Restrict TCP 57412 to engineering workstations via firewall; disable the Configuration
API entirely if not needed for automation. Upgrade to KEPServerEX 6.14 or later (patches
CVE-2023-29444/29445). Configure OPC-UA with `SignAndEncrypt` security mode. Audit
KEPServerEX event log for unauthorized API calls. Apply network segmentation to ensure
KEPServerEX is not directly reachable from IT or DMZ networks.
