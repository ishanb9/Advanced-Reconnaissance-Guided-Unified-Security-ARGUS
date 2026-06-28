---
id: checkpoint_gaia
technology: "Check Point GAIA / Security Gateway"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [257, 264, 18190, 18209, 18264]
  banners: ["check point", "checkpoint", "gaia", "cpshell", "smart-1"]
  markers: ["/SmartConsole/", "/cgi-bin/home.tcl", "/login", "x-chkp-sid", "CP_CSRF_TOKEN"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p257,264,18190,18209 --script banner {host}", safety: safe, note: "Check Point proprietary FW1 (257/tcp) and topology (264/tcp) ports — banner confirms Security Gateway presence." }
  - { cmd: "curl -sk -D - https://{host}/login | grep -i 'check.point\\|gaia\\|x-chkp\\|server'", safety: safe, note: "Gaia web management login page header fingerprinting — may reveal Gaia OS version." }
  - { cmd: "python3 -c \"import socket; s=socket.socket(); s.connect(('{host}',264)); s.send(b'\\x51\\x00\\x00\\x00\\x00\\x00\\x00\\x21\\x00\\x00\\x00\\x0bsecuremote\\x00'); print(s.recv(1024))\"", safety: safe, note: "FW1 topology (SecureRemote) banner grab on 264/tcp — read-only version handshake. No state change." }
  - { cmd: "snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1.1", safety: safe, note: "SNMP sysDescr may reveal Check Point version and Gaia OS build if default community string is set." }
  - { cmd: "curl -sk -X POST 'https://{host}/web_api/login' -H 'Content-Type: application/json' -d '{\"user\":\"admin\",\"password\":\"admin\"}'", safety: intrusive, note: "Management API default credential check (R80+ API); produces authentication log on SmartCenter. Gate with scope authorisation." }
references:
  - "CVE-2024-24919"
  - "CVE-2022-23741"
  - "CVE-2020-6017"
  - "CVE-2019-8461"
  - "CISA KEV 2024-05-30 (Check Point Security Gateway Information Disclosure)"
  - "Check Point Advisory sk182337"
mitre: "T1190"
---
# Check Point GAIA / Security Gateway

Check Point Security Gateways running the Gaia OS are deployed by enterprises, financial institutions, and government agencies worldwide, particularly strong in EMEA and highly regulated sectors. The Gaia platform provides NGFW, IPS, URL filtering, Anti-Bot, and mobile access (VPN) capabilities, managed centrally via SmartConsole connecting to a SmartCenter / Management Server. The proprietary Check Point FW1 protocol runs on ports 257/tcp (FW1 management) and 264/tcp (FW1 topology / SecureRemote), making remote fingerprinting straightforward even without web access. The R80+ REST Management API on HTTPS provides programmatic access to configuration.

The most critical recent exposure is CVE-2024-24919, a path traversal vulnerability in the IPSec VPN and Mobile Access blades that allows unauthenticated reading of arbitrary files including `/etc/shadow` and local VPN credentials — added to CISA KEV in May 2024 with active exploitation confirmed by Check Point and Mandiant. CVE-2019-8461 and CVE-2020-6017 affected the Mobile Access portal and management daemon. The FW1 topology port 264/tcp has historically leaked network topology and encryption domain information to unauthenticated clients via the SecureRemote handshake, which is a low-risk read but provides valuable reconnaissance.

**Safe-first testing.** Banner-grab the FW1 proprietary ports (257, 264) using raw socket or nmap to confirm a Security Gateway and extract version information. SNMP sysDescr on default community strings often returns the Gaia OS build. For CVE-2024-24919 exposure, send the path traversal payload only under explicit written authorisation — it is a pre-auth read but produces server-side logs. Cross-reference the exact Gaia version and hotfix level against the Check Point sk (solution knowledge) advisory index before escalating.

**Remediation.** Apply Check Point hotfixes via CPUSE; enable the Check Point Quantum Intrusion Prevention System to block exploitation attempts; disable the Mobile Access and IPSec VPN blades if not in use; restrict SmartConsole access (18190/tcp, 19009/tcp) to administrator jump hosts; enable MFA on SmartConsole login; rotate all admin and VPN credentials if CVE-2024-24919 exposure is confirmed; and review the Mobile Access configuration for overly permissive portal settings.
