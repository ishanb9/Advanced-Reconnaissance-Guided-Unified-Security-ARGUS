---
id: f5_bigip
technology: "F5 BIG-IP"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [4353, 6699]
  banners: ["BIG-IP", "F5", "TMOS", "iControl", "f5 big-ip"]
  markers: ["bigip", "f5-bigip", "icontrol", "BIG-IP", "TMOS", "F5_ST", "BigipServer"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p443,4353 --script=http-title,ssl-cert,http-headers {host}", safety: safe, note: "TLS cert (CN often 'bigip*') + HTTP headers (Server: BigIP or X-WA-Info) — identifies TMOS version and management interface." }
  - { cmd: "curl -sk https://{host}/mgmt/tm/sys/version -u admin:admin 2>/dev/null | python3 -m json.tool | head -30", safety: safe, note: "iControl REST API version read — read-only with admin credentials; leaks exact TMOS version for CVE correlation." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr {host}", safety: safe, note: "SNMP sysDescr — leaks TMOS version and BIG-IP platform (i4800, i15800, VE, etc.) with default community." }
  - { cmd: "curl -sk -X POST https://{host}/tmui/login.jsp --data 'username=&passwd=' -I 2>/dev/null | head -20", safety: safe, note: "TMUI login probe — CVE-2020-5902 path traversal check (no credentials needed); safe read-only HTTP request." }
references: ["CVE-2020-5902", "CVE-2021-22986", "CVE-2022-1388", "CVE-2023-46747", "CVE-2023-46748", "KEV 2020-09-03"]
mitre: "T1190"
---
# F5 BIG-IP

F5 BIG-IP is the world's most widely deployed application delivery controller (ADC), providing
load balancing, SSL offload, WAF (ASM/AWAF), access management (APM), and DNS services. BIG-IP
runs TMOS (Traffic Management Operating System), a hardened Linux with an iControl REST and SOAP
management API on HTTPS (443/4353/tcp), an SSH console, and the TMUI web interface. BIG-IP sits
in front of web applications at financial institutions, healthcare systems, and government agencies
globally — making it a prime target for attackers seeking to intercept application traffic or gain
persistent access to the application layer.

**Why it matters.** F5 BIG-IP has accumulated a string of CVSS 9.8-10.0 vulnerabilities that have
been widely exploited. CVE-2020-5902 (CVSS 10.0, KEV) allowed unauthenticated RCE via a path
traversal in TMUI — exploited within 24 hours of disclosure. CVE-2022-1388 (CVSS 9.8, KEV)
bypassed iControl REST authentication entirely with a crafted HTTP header. CVE-2023-46747 chained
with CVE-2023-46748 to achieve unauthenticated RCE via request smuggling to the config utility.
Nation-state actors have repeatedly targeted BIG-IP within days of PoC publication.

**Safe-first testing.** Inspect TLS certificates (the CN or SAN often reads `bigip*` or contains
the F5 management hostname) and HTTP response headers (`Server: BigIP`, `X-WA-Info`). Query the
iControl REST API with a GET on `/mgmt/tm/sys/version` — this is fully read-only and leaks the
precise TMOS version needed for CVE correlation. Do not issue iControl REST POST/PATCH/DELETE
or run `tmsh` commands without explicit authorization; these change live load-balancer state.

**Remediation.** Apply F5 Security Advisories immediately; restrict TMUI and iControl REST to
a dedicated management VLAN or out-of-band network; disable the management interface from data
plane VLANs; enable iControl REST authentication at the highest assurance level; rotate admin
credentials; enable F5's TMUI IP allow-listing; and monitor iControl REST access logs for
anomalous GET/POST patterns.
