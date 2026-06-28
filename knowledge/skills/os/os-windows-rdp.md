---
id: os-windows-rdp
technology: "Windows RDP (Remote Desktop Protocol)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["RDP", "MSTSHASH", "rdpdr", "mstshash="]
  markers: ["mstshash=", "rdp_fingerprint", "MSTSHASH=Negotiate", "rdpdr\x00"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p3389 --script rdp-enum-encryption,rdp-vuln-ms12-020 {host}", safety: safe, note: "Enumerate RDP encryption level and check MS12-020 DoS without authentication." }
  - { cmd: "nmap -Pn -p3389 --script rdp-enum-encryption --script-args 'rdp-enum-encryption.level=all' {host}", safety: safe, note: "Enumerate all supported encryption and NLA settings — read-only." }
  - { cmd: "hydra -L users.txt -P passwords.txt rdp://{host}", safety: intrusive, note: "Credential brute-force — GATED; generates lockouts and logs." }
  - { cmd: "xfreerdp /v:{host} /u:Administrator /p:'' /cert-ignore", safety: intrusive, note: "Attempt null/blank password authentication — active login attempt." }
references: ["CVE-2019-0708 (BlueKeep)", "CVE-2019-1181 (DejaBlue)", "CVE-2012-0002 (MS12-020)", "KEV CVE-2019-0708", "MS-RDPBCGR"]
mitre: "T1021.001"
---
# Windows RDP (Remote Desktop Protocol)

Remote Desktop Protocol (RDP) runs on **3389/tcp** (and optionally 3389/udp) and provides full interactive GUI access to Windows desktops and servers. It is one of the highest-value attack surfaces in enterprise environments because successful exploitation or credential abuse yields an authenticated interactive shell as the targeted user — often SYSTEM or Administrator. **BlueKeep (CVE-2019-0708)** and **DejaBlue (CVE-2019-1181)** demonstrated that pre-authentication, unauthenticated RCE is possible against unpatched hosts, and both appear in CISA's Known Exploited Vulnerabilities catalog.

**Common exposures.** Millions of RDP endpoints are internet-exposed on Shodan/Censys. Weak passwords, lack of Network Level Authentication (NLA), outdated Windows builds, and exposed management interfaces in cloud environments (AWS, Azure security-group misconfigurations) all contribute to wide attack surface. Ransomware groups routinely use brute-forced or purchased RDP credentials as initial access.

**Safe-first testing.** Start with `rdp-enum-encryption` (Nmap NSE) to fingerprint the server's offered encryption and NLA posture — this is read-only and produces no failed login events. Check MS12-020 (which is a DoS, not RCE) with the NSE script only in authorized, non-production windows. Avoid brute-force attempts unless explicitly scoped; even a single failed attempt increments Windows lockout counters and may lock production accounts. BlueKeep exploitation requires an exploit payload; never attempt against production systems without a snapshot/rollback capability in place.

**Remediation.** Enforce NLA on all RDP listeners; place RDP behind a VPN or jump host rather than exposing 3389 directly; apply all MS-RDPBCGR patches promptly; enable Windows Defender Credential Guard; restrict RDP access via Windows Firewall to known management IPs; enable account lockout policies; and monitor for lateral movement via Event IDs 4624/4625/4778/4779.
