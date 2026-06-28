---
id: fortigate
technology: "Fortinet FortiGate / FortiOS"
domain: IT
category: security
transport: ip
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [541, 10443]
  banners: ["fortinet", "fortigate", "fortiOS", "forticlient", "forti"]
  markers: ["/remote/login", "/remote/fgt_lang", "/api/v2/cmdb/system/status", "APSCOOKIE", "SVPNCOOKIE"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/remote/login | grep -i 'fortinet\\|fortigate\\|set-cookie\\|server'", safety: safe, note: "SSL-VPN login page header grab — confirms FortiOS presence and may expose version in HTTP headers." }
  - { cmd: "curl -sk https://{host}/api/v2/cmdb/system/status 2>/dev/null | python3 -m json.tool | head -30", safety: safe, note: "REST API system/status endpoint — may be unauthenticated on older firmware; returns model and FortiOS version." }
  - { cmd: "nmap -Pn -sT -p541,443,8443 --script ssl-cert,http-title {host}", safety: safe, note: "TLS cert CN/SAN and HTTP title reliably fingerprint FortiGate management vs SSL-VPN interface." }
  - { cmd: "curl -sk 'https://{host}/remote/fgt_lang?lang=../../../../etc/passwd'", safety: intrusive, note: "CVE-2018-13379 path traversal probe — read-only but active; confirm scope authorisation before running." }
  - { cmd: "python3 check_cve_2022_40684.py --target https://{host} --check-only", safety: intrusive, note: "Auth-bypass fingerprint check (CVE-2022-40684); only confirm presence, never change config without authorisation." }
references:
  - "CVE-2024-21762"
  - "CVE-2023-27997"
  - "CVE-2022-42475"
  - "CVE-2022-40684"
  - "CVE-2018-13379"
  - "CISA KEV 2024-02-09 (FortiOS Out-of-Bound Write)"
  - "CISA KEV 2022-10-10 (FortiOS Auth Bypass)"
  - "CISA KEV 2020-03-31 (FortiOS Path Traversal)"
mitre: "T1190"
---
# Fortinet FortiGate / FortiOS

FortiGate is Fortinet's flagship next-generation firewall and unified threat management (UTM) platform, running FortiOS. It is one of the most widely deployed enterprise firewalls globally, found at the perimeter of SMBs, large enterprises, service providers, and government networks. FortiGate combines firewall policy, IPS, SSL-VPN, SD-WAN, and deep-packet inspection. The management web UI is typically on port 443 (or 8443/10443), the SSL-VPN portal on port 4443 or 10443, and the legacy SSLVPN client port 541/tcp. Multiple critically exploited vulnerabilities have made FortiOS one of the most actively targeted platforms in the CISA KEV catalogue.

The vulnerability history is severe. CVE-2018-13379 (pre-auth path traversal exposing SSL-VPN session files and credentials) was exploited by multiple nation-state actors and remains relevant against unpatched instances. CVE-2022-40684 (authentication bypass via the management API, CVSS 9.8) allowed unauthenticated configuration changes. CVE-2022-42475 and CVE-2023-27997 are heap-based buffer overflows in the SSL-VPN daemon exploited as zero-days. CVE-2024-21762 is an out-of-bounds write in the SSL-VPN web management interface rated CVSS 9.6, added to CISA KEV in February 2024. All of these were exploited before patches were widely applied.

**Safe-first testing.** Confirm FortiOS with header and certificate fingerprinting (`/remote/login`, cookie names `SVPNCOOKIE`/`APSCOOKIE`), then check the REST API status endpoint for unauthenticated version disclosure. Cross-reference the exact FortiOS version against all open PSIRT advisories. Only escalate to the CVE-2018-13379 path traversal or auth-bypass probes under explicit written authorisation — these produce observable log entries on the target. Do not issue any REST API configuration write calls.

**Remediation.** Upgrade FortiOS to the latest supported release in each branch; restrict the management UI and SSL-VPN to known source IP ranges; require certificate-based admin authentication; disable any unused SSLVPN interfaces; enable FortiGuard threat intelligence; and rotate all admin and VPN credentials if any historically vulnerable version was exposed. Monitor for new PSIRT advisories via the Fortinet advisory feed.
