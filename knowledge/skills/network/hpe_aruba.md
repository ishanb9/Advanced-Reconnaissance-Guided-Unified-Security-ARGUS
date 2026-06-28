---
id: hpe_aruba
technology: "HPE Aruba AOS / ArubaOS"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [4343]
  banners: ["ArubaOS", "Aruba Networks", "AOS", "Aruba Instant", "Aruba ClearPass"]
  markers: ["aruba", "arubaos", "aruba-instant", "Aruba", "HPE Aruba"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,443,4343,8443 --script=ssh-hostkey,http-title,ssl-cert {host}", safety: safe, note: "SSH hostkey + TLS certificate (CN leaks hostname/cluster) + WebUI title — identifies Mobility Controller, Instant AP, or ClearPass." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr,snmp-info {host}", safety: safe, note: "SNMP sysDescr — leaks ArubaOS version, platform, and serial with default 'public' community." }
  - { cmd: "curl -sk https://{host}:4343/ -I 2>/dev/null | head -20", safety: safe, note: "Mobility Controller WebUI probe on 4343 — server header and redirect reveal ArubaOS version string." }
  - { cmd: "nmap -Pn -p8443 --script http-auth-finder,http-title {host}", safety: safe, note: "ClearPass Policy Manager probe — identifies version, auth method, and exposed API endpoints." }
references: ["CVE-2023-22747", "CVE-2023-22748", "CVE-2024-26305", "CVE-2024-26304", "HPESB2024-0002"]
mitre: "T1190"
---
# HPE Aruba AOS / ArubaOS

HPE Aruba Networks produces the ArubaOS operating system for Mobility Controllers (wireless LAN
controllers), Aruba Instant access points (controller-less mode), AOS-CX switching, and the
ClearPass Policy Manager NAC solution. ArubaOS is the dominant wireless LAN controller platform
in enterprises globally, particularly in education and healthcare. Management interfaces include
SSH, an HTTPS WebUI (4343/tcp on controllers), SNMP, and a REST API. ClearPass (8443/tcp) manages
network access control policies and integrates with Active Directory and RADIUS.

**Why it matters.** CVE-2023-22747/22748 (CVSS 9.8) were a pair of unauthenticated stack-based
buffer overflows in ArubaOS PAPI protocol, allowing RCE on Mobility Controllers and gateways —
affecting hundreds of thousands of deployed devices. CVE-2024-26304/26305 (CVSS 9.8) again hit
the ArubaOS CLI service and SOAP web service with unauthenticated RCE. Compromise of a Mobility
Controller gives an attacker visibility into all wireless client traffic, RADIUS secrets, and
the ability to deauthenticate or intercept wireless sessions.

**Safe-first testing.** Read TLS certificate details and SNMP sysDescr to determine software
version without authentication. Probe the WebUI HTTP response headers on port 4343 — these leak
version strings in server or X-header fields. Do not send PAPI (UDP 8211) protocol messages to
the controller; crafted PAPI is the attack vector for the RCE CVEs and can crash the management
daemon. Avoid ClearPass API enumeration beyond unauthenticated endpoint discovery.

**Remediation.** Apply HPE Aruba Security Advisories immediately for PAPI and web service
vulnerabilities; enable PAPI security (shared secret between APs and controllers); restrict
WebUI and SSH to an out-of-band management network; enforce SNMPv3; require certificates for
ClearPass RADIUS; and segment wireless controller management traffic from production VLANs.
