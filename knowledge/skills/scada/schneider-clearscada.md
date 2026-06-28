---
id: schneider-clearscada
technology: "Schneider Electric ClearSCADA / EcoStruxure Geo SCADA"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [10001, 10002]
  banners: ["ClearSCADA", "EcoStruxure", "Schneider Electric", "Geo SCADA"]
  markers: ["ClearSCADA", "/ClearSCADA/", "ViewX", "WebX", "geodesign", "geo-scada"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p10001,10002 -sV {host}", safety: safe, note: "ClearSCADA client/server protocol ports; banner identifies version and confirms product." }
  - { cmd: "nmap -Pn -sT -p10001,10002 --script http-title,http-server-header {host}", safety: safe, note: "Enumerate service banners on ClearSCADA listener ports; WebX path /ClearSCADA/ in responses confirms product." }
  - { cmd: "curl -sk http://{host}:10001/ClearSCADA/ -I", safety: safe, note: "ClearSCADA WebX web client path on technology-dedicated port; HTTP response headers and title leak product version." }
  - { cmd: "<ClearSCADA ViewX/WebX login with default credentials admin/admin>", safety: intrusive, note: "GATED — default credential test; constitutes an active authentication attempt." }
references: ["CVE-2022-24318", "CVE-2022-24319", "CVE-2020-7493", "CVE-2020-7494", "ICSA-22-067-01"]
mitre: "T0817 / ICS T0856"
---
# Schneider Electric ClearSCADA / EcoStruxure Geo SCADA Expert

ClearSCADA (rebranded as EcoStruxure Geo SCADA Expert) is Schneider Electric's SCADA platform
targeting remote telemetry/SCADA for water, wastewater, oil & gas pipeline, and utilities.
It uses a client-server architecture where a single ClearSCADA server hosts the database,
historian, and communications stack. The Windows-based server listens on proprietary TCP ports
**10001** (main client protocol) and **10002**, and exposes a web client (WebX) through HTTPS
on 443. The platform communicates with RTUs and PLCs via DNP3, Modbus, IEC 60870-5, and
proprietary Schneider protocols.

**Attack surface.** CVE-2020-7493 (unauthenticated path traversal) and CVE-2020-7494 (XSS in
WebX) allow pre-authentication file reads and session hijacking through the WebX interface.
CVE-2022-24318 and CVE-2022-24319 (authentication bypass and unencrypted credential handling
in the server protocol) allow attackers to capture or bypass credentials on the client-server
channel. Default credentials (`admin/admin`) are documented in installation guides and persist
in many field deployments. ClearSCADA is specifically deployed for SCADA of distributed
infrastructure (water wells, pump stations, pipeline segments) — compromise means remote
control of physical infrastructure.

**Safe-first testing.** Begin with the WebX HTTPS interface: HTTP header analysis and
unauthenticated page enumeration (title, version) are read-only. Check `/ClearSCADA/` for the
login page and note the disclosed version. Port-scan 10001/10002 for service banners. Do not
attempt to interact with the ClearSCADA client protocol (TCP 10001) beyond banner grabbing —
the protocol has no authentication challenge at connection time in older versions, and even
passive queries alter server-side connection state. Never issue SCADA control commands against
live infrastructure.

**Remediation.** Upgrade to EcoStruxure Geo SCADA Expert 2022 R1 or later (addresses
CVE-2022-24318/24319). Change default credentials immediately and enforce password complexity.
Enable TLS on the client-server protocol channel. Restrict TCP 10001/10002 to engineering
workstations via firewall ACL. Apply Schneider Electric SESB advisories. Segment WebX HTTPS
to a DMZ with reverse proxy authentication if remote access is required.
