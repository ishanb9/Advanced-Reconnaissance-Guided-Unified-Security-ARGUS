---
id: f5_asm_waf
technology: "F5 BIG-IP ASM / Advanced WAF"
domain: IT
category: security
transport: ip
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [4353]
  banners: ["big-ip", "f5", "tmm", "tmos", "icontrol", "bigip"]
  markers: ["/mgmt/tm/sys/version", "/tmui/login.jsp", "TS01", "BigIPCookie", "BIGipServer", "X-WA-Info", "F5_ST"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/mgmt/tm/sys/version 2>/dev/null | head -20", safety: safe, note: "iControl REST unauthenticated version probe — some TMOS versions return build and product info without credentials." }
  - { cmd: "curl -sk -D - https://{host}/tmui/login.jsp | grep -i 'f5\\|big-ip\\|tmos\\|server\\|BIGip'", safety: safe, note: "TMUI login page header and body fingerprinting for F5 BIG-IP version and TMOS generation." }
  - { cmd: "curl -sk https://{host}/ | grep -i 'BIGipServer\\|TS01\\|F5_ST\\|X-WA-Info'", safety: safe, note: "HTTP cookie and response header inspection for BIG-IP persistence cookie name (BIGipServer*) — passive, no impact." }
  - { cmd: "nmap -Pn -sT -p4353,443,8443 --script ssl-cert,http-title {host}", safety: safe, note: "TLS cert SAN and HTTPS title identify management console vs traffic-passing virtual server." }
  - { cmd: "curl -sk -X POST https://{host}/mgmt/shared/authn/login -H 'Content-Type: application/json' -d '{\"username\":\"admin\",\"password\":\"admin\",\"loginProviderName\":\"tmos\"}'", safety: intrusive, note: "iControl REST default credential check (CVE-2021-22986 surface); produces auth log. Gate with scope authorisation." }
references:
  - "CVE-2023-46747"
  - "CVE-2022-1388"
  - "CVE-2021-22986"
  - "CVE-2020-5902"
  - "CVE-2019-6649"
  - "CISA KEV 2022-05-09 (F5 BIG-IP iControl REST Auth Bypass)"
  - "CISA KEV 2020-07-10 (F5 BIG-IP TMUI RCE)"
  - "CISA KEV 2023-11-01 (F5 BIG-IP Config Utility Auth Bypass)"
mitre: "T1190"
---
# F5 BIG-IP ASM / Advanced WAF

F5 BIG-IP is the market-leading application delivery controller, widely deployed as a load balancer, SSL offload appliance, and Web Application Firewall (ASM / Advanced WAF module). BIG-IP appliances are found in front of banking platforms, healthcare portals, government web services, and Fortune 500 applications worldwide. The TMOS management plane exposes the TMUI web console (typically on 443 or 8443) and the iControl REST API (4353/tcp or overlapping 443), both of which have been the source of some of the most critically exploited vulnerabilities in recent years.

The vulnerability record is severe and well-known to threat actors. CVE-2020-5902 (TMUI path traversal enabling pre-auth RCE, CVSS 10) was exploited within 24 hours of disclosure. CVE-2021-22986 (iControl REST unauthenticated RCE, CVSS 9.8) followed in 2021. CVE-2022-1388 (iControl REST auth bypass via X-F5-Auth-Token manipulation, CVSS 9.8) was exploited within days of public PoC release and is on CISA KEV. CVE-2023-46747 (authentication bypass in the Configuration Utility leading to unauthenticated RCE via AJP request smuggling, CVSS 9.8) was disclosed in October 2023. F5 BIG-IP systems are consistently high-value targets for initial access due to their position in front of critical applications.

**Safe-first testing.** Fingerprint BIG-IP via HTTP headers (`BIGipServer*` persistence cookies, `X-WA-Info` WAF response header), TMUI login page source, and TLS certificate CN/SAN. The iControl REST `/mgmt/tm/sys/version` endpoint may return version data with guest credentials or even unauthenticated on very old builds — this is a safe read-only check. Version triage against F5 security advisories is sufficient to establish criticality without further active testing. Only attempt credential checks or advisory-specific probes under explicit written authorisation.

**Remediation.** Apply F5 security patches immediately — these advisories are reliably weaponised within 24-72 hours of publication. Restrict TMUI and iControl REST access to dedicated management networks; disable the management interface on traffic-passing interfaces; enable iControl REST authentication; rotate all admin credentials; and use F5's iHealth diagnostic tool to assess compliance posture. The ASM/Advanced WAF policy itself should be tuned to block application-layer attacks relevant to the protected application.
