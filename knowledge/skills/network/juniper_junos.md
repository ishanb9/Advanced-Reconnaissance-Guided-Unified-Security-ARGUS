---
id: juniper_junos
technology: "Juniper Junos OS"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [830]
  banners: ["Juniper", "JUNOS", "junos", "Junos OS", "juniper networks"]
  markers: ["junos", "juniper-srx", "juniper-mx", "juniper-ex", "Junos OS Release"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,830 --script=ssh-hostkey,netconf-info {host}", safety: safe, note: "SSH banner grab (Junos version in SSH comments) + NETCONF hello — reveals Junos release and capabilities." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr {host}", safety: safe, note: "SNMP sysDescr — leaks Junos OS version, product (MX480, SRX4100, EX4300, etc.) with default community." }
  - { cmd: "nmap -Pn -p3000,3001 --script http-title {host}", safety: safe, note: "J-Web management interface fingerprint (port 3000/3001 on older Junos); identifies unauthenticated access." }
  - { cmd: "ssh -o StrictHostKeyChecking=no -o BatchMode=yes {host} 'show version' 2>&1 | head -20", safety: safe, note: "Read-only version retrieval via SSH if credentials are known — reveals product, Junos release, uptime." }
references: ["CVE-2023-36844", "CVE-2023-36845", "CVE-2024-21591", "CVE-2024-30394", "JSA72300"]
mitre: "T1190"
---
# Juniper Junos OS

Juniper Junos is the network operating system running on Juniper's MX-series core/edge routers,
SRX-series firewalls, EX-series enterprise switches, and QFX-series data-center switches. Junos is
architecturally split: the Routing Engine (RE) runs a FreeBSD-derived control plane and exposes
SSH, NETCONF (830/tcp), J-Web HTTPS, and SNMP; the Packet Forwarding Engine (PFE) handles forwarding.
Junos is used in the majority of Tier-1/Tier-2 ISP backbones and in high-security enterprise
environments that prefer it over Cisco for its clean configuration model.

**Why it matters.** CVE-2023-36844 through -36847 (the "PHP cascades" chain, CVSS 9.8) allowed
unauthenticated remote code execution on SRX firewalls and EX switches via J-Web — thousands of
devices were exploited in the wild within days of disclosure. CVE-2024-21591 enabled unauthenticated
root RCE on SRX and EX via J-Web again. Junos devices routinely appear at internet-edge and
BGP peering points; compromise grants full routing-table manipulation capability.

**Safe-first testing.** NETCONF `get-configuration` queries with read-only access reveal the full
device configuration including firewall policies. SNMP sysDescr with the `public` community string
leaks Junos version and platform instantly. SSH banner comments include the Junos release string.
Do not use NETCONF `edit-config` or CLI `set` commands without explicit authorization — these change
routing, firewall, or interface state.

**Remediation.** Disable J-Web if not in use; apply Juniper Security Advisories (JSA) promptly,
especially for J-Web and PHP components; restrict NETCONF and SSH access to a dedicated management
VRF with source-address restrictions; enforce SNMPv3; rotate default credentials on J-Web; and
enable Junos commit confirmation so accidental changes auto-rollback.
