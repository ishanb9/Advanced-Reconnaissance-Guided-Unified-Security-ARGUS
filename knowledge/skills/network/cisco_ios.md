---
id: cisco_ios
technology: "Cisco IOS / IOS-XE"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [23, 830]
  banners: ["Cisco IOS", "IOS-XE", "cisco ios software", "cisco internetwork operating system"]
  markers: ["cisco-ios", "iosxe", "IOS XE Software", "Cisco IOS XE"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p23,22,161,830 --script=telnet-info,ssh-hostkey,snmp-info {host}", safety: safe, note: "Banner grab and service enumeration — identifies IOS vs IOS-XE, software version, hostname." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-info,snmp-sysdescr -e lo0 {host}", safety: safe, note: "SNMP v1/v2c sysDescr retrieval — leaks IOS version and platform if community string is default (public)." }
  - { cmd: "nmap -Pn -p80,443 --script http-title,http-auth-finder {host}", safety: safe, note: "Check for Cisco IOS HTTP/HTTPS management web UI; older IOS versions exposed unauthenticated endpoints." }
  - { cmd: "nmap -Pn -p22 --script ssh-auth-methods,ssh2-enum-algos {host}", safety: safe, note: "Enumerate SSH auth methods and weak cipher suites (3DES, MD5 MACs) — common on legacy IOS." }
  - { cmd: "nmap -Pn -p830 --script netconf-info {host}", safety: safe, note: "NETCONF (RFC 6241) capability advertisement — reveals device model, OS version, feature set without auth." }
references: ["CVE-2018-0171", "CVE-2023-20198", "CVE-2023-20273", "KEV 2023-10-16", "cisco-sa-iosxe-webui-privesc-j22SaA4z"]
mitre: "T1190"
---
# Cisco IOS / IOS-XE

Cisco IOS and its successor IOS-XE power the majority of enterprise and carrier-grade routers and
multilayer switches worldwide. IOS-XE (used on ASR, CSR 1000v, Catalyst 9000) runs a hardened Linux
kernel hosting an IOS process, while classic IOS still dominates older ISR and Catalyst platforms.
Both expose management via SSH (port 22), Telnet (port 23), SNMP (161/udp), NETCONF (830/tcp), and
an optional HTTP/HTTPS management interface. Misconfigurations such as default community strings, weak
enable passwords, or unpatched management-plane CVEs routinely appear on internet-facing infrastructure.

**Why it matters.** IOS and IOS-XE devices form the routing core, VPN termination, and policy
enforcement points of virtually every enterprise network. Compromise delivers persistent network-level
access, traffic interception capability, and a pivot point into every connected segment. CVE-2023-20198
(CVSS 10.0, KEV) allowed unauthenticated creation of privilege-15 accounts on IOS-XE devices with the
web UI exposed; follow-on CVE-2023-20273 achieved root code execution. Shodan regularly indexes tens
of thousands of exposed IOS management interfaces.

**Safe-first testing.** Begin with passive banner grabs and SNMP sysDescr reads using the default
`public` community string — these are read-only and reveal version, platform, and hostname in seconds.
NETCONF on 830/tcp advertises full capability sets without authentication on older builds.
Do not attempt to log in or issue CLI commands without explicit scope authorization. Avoid write SNMP
(setRequest) operations entirely during enumeration; they can alter routing state or ACLs.

**Remediation.** Rotate all SNMP community strings and migrate to SNMPv3 with auth+priv; disable Telnet
and the HTTP management interface; apply Cisco's IOS XE security advisories promptly (especially web UI
exposure); restrict management-plane access via control-plane policing (CoPP) and interface ACLs;
enable AAA with RADIUS/TACACS+; and audit privilege-15 accounts regularly.
