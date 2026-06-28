---
id: vtscada
technology: "VTScada (Trihedral) SCADA"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: medium
life_safety: true
match:
  ports: [1959, 1960]
  banners: ["VTScada", "Trihedral", "VTSCADA"]
  markers: ["vtscada", "trihedral", "VTScada Server"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p1959,1960 -sV {host}", safety: safe, note: "VTScada server communication ports; banner identifies version and product." }
  - { cmd: "curl -sk http://{host}:1959/ -I", safety: safe, note: "VTScada may expose a web interface on 1959/tcp; HTTP headers reveal product version." }
  - { cmd: "nmap -Pn -sT -p1959,1960 --script banner {host}", safety: safe, note: "Grab raw banner from VTScada ports to identify version and configuration." }
  - { cmd: "<VTScada web interface browsing for unauthenticated pages>", safety: safe, note: "Read-only HTTP enumeration of VTScada web interface for status pages and version disclosure." }
references: ["CVE-2022-34152", "CVE-2022-34153", "CVE-2021-3914", "ICSA-22-195-04"]
mitre: "T0817 / ICS T0856"
---
# VTScada (Trihedral) SCADA

VTScada, developed by Trihedral Engineering, is a SCADA platform specifically strong in water/
wastewater management, oil & gas pipeline monitoring, and remote telemetry applications in North
America. It is notable for its integrated thin-client web access (no plugin required) and
support for a wide range of field protocols including Modbus, DNP3, IEC 60870-5, and OPC-UA.
VTScada uses TCP ports **1959** and **1960** for inter-server and client-server communication.
It is commonly deployed on standalone Windows servers managing geographically dispersed RTUs
and PLCs across pipeline and water distribution networks.

**Attack surface.** CVE-2022-34152 and CVE-2022-34153 (path traversal and authentication bypass
in VTScada web interface) allow unauthenticated file reads from the VTScada server directory,
potentially exposing configuration files containing database connection strings, driver
credentials, and PLC addressing schemes. CVE-2021-3914 (improper access control in VTScada
REST API) allows unauthenticated tag reads in older versions. Because VTScada is commonly
deployed for remote site management (water wells, pump stations) where physical access is
limited, compromise of the SCADA layer provides broad reach over distributed physical assets.

**Safe-first testing.** Enumerate ports 1959/1960 passively and attempt an HTTP GET on the web
interface to obtain version information from HTTP headers or the login page. Check for
unauthenticated access to the VTScada REST API (`/api/`). Review any accessible configuration
files for driver/protocol credentials. Do not issue tag write commands via the REST API or the
native client protocol — VTScada deployments controlling pump stations and treatment plants
pose direct life-safety risks if water flow or chemical dosing is disrupted.

**Remediation.** Upgrade VTScada to version 11.3.03 or later (patches CVE-2022-34152/34153).
Enable authentication on the VTScada web interface and REST API. Restrict TCP 1959/1960 to
known engineering workstations and SCADA client nodes via firewall rules. Do not expose VTScada
directly to the internet; use a VPN with MFA for remote access. Review VTScada audit logs for
unauthorized tag read/write activity.
