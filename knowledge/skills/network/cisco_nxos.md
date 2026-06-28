---
id: cisco_nxos
technology: "Cisco NX-OS (Nexus)"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [830]
  banners: ["Cisco Nexus", "NX-OS", "nx-os software", "nexus operating system"]
  markers: ["cisco-nxos", "NX-OS", "Nexus", "nx-osv"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,443,830 --script=ssh-hostkey,http-title,netconf-info {host}", safety: safe, note: "Banner grab: SSH host key fingerprint and NX-OS version; NETCONF capability dump on 830/tcp." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr,snmp-info {host}", safety: safe, note: "SNMP v1/v2c sysDescr — leaks NX-OS release, platform (Nexus 3k/5k/7k/9k), serial number." }
  - { cmd: "curl -sk https://{host}/api/mo/sys/intf.json | python3 -m json.tool 2>/dev/null | head -80", safety: safe, note: "NX-API REST (HTTPS) — read-only interface list if NX-API is enabled without auth (misconfiguration)." }
  - { cmd: "nmap -Pn -p443 --script http-auth-finder,http-methods {host}", safety: safe, note: "Check NX-API or DCNM management HTTPS — identifies authentication posture and exposed endpoints." }
references: ["CVE-2019-1590", "CVE-2022-20650", "CVE-2023-20169", "cisco-sa-nxos-nxapi-cmdinj-wCxbKxD"]
mitre: "T1190"
---
# Cisco NX-OS (Nexus)

Cisco NX-OS runs on the Nexus data-center switching family (3000, 5000, 7000, 9000 series). Unlike IOS,
NX-OS is purpose-built for high-density data-center fabrics and exposes management via SSH, SNMP,
an HTTP/HTTPS NX-API REST and JSON-RPC interface, and NETCONF. NX-OS underpins the spine-leaf
architectures carrying east-west traffic in virtually every large enterprise and cloud data center,
making it a high-value target for lateral movement and data exfiltration.

**Why it matters.** Nexus switches sit at the convergence point of compute, storage, and network traffic.
CVE-2022-20650 (CVSS 8.8) allowed authenticated NX-API command injection via crafted JSON payloads.
CVE-2023-20169 allowed a remote attacker on the management network to cause a reload via a crafted
IS-IS PDU. NX-API, when misconfigured without authentication, exposes full CLI to any HTTP client.
Spine switches often also carry ACI policy or vPC peer links whose disruption affects entire racks.

**Safe-first testing.** Use SNMP read and NETCONF GET operations to identify version, VLANs, and
interfaces without state change. Probe NX-API with GET requests to read-only model paths only — never
issue POST with configuration payloads. Check whether the sandbox (NX-OS open agent container) or
third-party app hosting is enabled, as these surfaces expand the attack footprint.

**Remediation.** Disable NX-API if not required; enforce HTTPS with valid certificates when in use;
apply NX-OS security advisories; segment management traffic to an out-of-band network; use AAA with
TACACS+; restrict SNMP to SNMPv3 auth+priv; and audit ACI fabric policies for overly permissive EPG
contracts.
