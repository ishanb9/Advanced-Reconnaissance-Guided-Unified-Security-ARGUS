---
id: mikrotik_routeros
technology: "MikroTik RouterOS"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [8291, 8728, 8729]
  banners: ["MikroTik", "RouterOS", "mikrotik routeros"]
  markers: ["mikrotik", "routeros", "winbox", "MikroTik RouterOS"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p21,22,23,80,443,8291,8728,8729 --script=banner,ftp-anon,telnet-info {host}", safety: safe, note: "Full service enumeration — identifies Winbox (8291), REST API (443), API (8728/8729), Telnet; reveals RouterOS version." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr,snmp-info {host}", safety: safe, note: "SNMP sysDescr leaks RouterOS version, board name, and serial number with default community string." }
  - { cmd: "nmap -Pn -p8728,8729 --script mikrotik-discover {host}", safety: safe, note: "RouterOS API enumeration on 8728 (plain) / 8729 (TLS) — identifies version and available services read-only." }
  - { cmd: "curl -sk https://{host}/rest/system/identity 2>/dev/null", safety: safe, note: "RouterOS REST API (added in v7) identity read — leaks device name if unauthenticated access is misconfigured." }
references: ["CVE-2018-14847", "CVE-2019-3924", "CVE-2023-30799", "CVE-2023-32154"]
mitre: "T1190"
---
# MikroTik RouterOS

MikroTik RouterOS is a Linux-based proprietary OS running on MikroTik's RouterBOARD hardware and
the CHR (Cloud Hosted Router) virtual appliance. RouterOS is ubiquitous in ISP last-mile, small
business, and home-office environments globally — Shodan indexes over two million exposed devices.
It exposes management via Winbox (proprietary protocol, port 8291), RouterOS API (8728/8729),
SSH (22), Telnet (23), FTP (21), an HTTP/HTTPS web interface, and SNMP. The wide variety of
enabled services and the prevalence of default or weak credentials make RouterOS one of the most
targeted platforms in botnet campaigns and exploitation.

**Why it matters.** CVE-2018-14847 (Winbox protocol directory traversal, CVSS 9.1) allowed
unauthenticated attackers to extract the user database file, recovering credentials in cleartext —
this vulnerability was exploited by the Slingshot and Meris botnet campaigns at massive scale.
CVE-2023-30799 (CVSS 9.1) allowed a Winbox or HTTP super-admin to achieve RCE via a privilege
escalation vulnerability, bypassing RouterOS's jailed environment. Millions of unpatched devices
remain exposed on the internet.

**Safe-first testing.** Banner-grab all management services to determine the RouterOS version,
then cross-reference against the CVE-2018-14847 and CVE-2023-30799 fix versions. SNMP sysDescr
with `public` reveals version and board type. Do not attempt Winbox authentication exploits without
scope authorization; Winbox connections to vulnerable firmware can crash the management process,
causing a brief outage.

**Remediation.** Upgrade RouterOS to the latest stable branch (7.x); disable Winbox and Telnet
if not required; restrict all management access to a specific management VLAN with source-IP ACLs;
rotate default `admin` credentials (empty password is the factory default); disable the FTP service;
and enable strong password policies via `/ip service` configuration.
