---
id: vpn_edge
technology: "VPN / edge appliances"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [10443, 8843]
  banners: ["pulse secure", "globalprotect", "juniper ssl vpn", "fortinet", "palo alto networks", "cisco anyconnect", "ivanti connect", "sonicwall netextender", "check point mobile", "f5 big-ip edge"]
  markers: ["/dana-na/", "/dana-na/auth/url_default/welcome.cgi", "/remote/login", "/remote/fgt_lang", "/global-protect/gpclientauth.esp", "/global-protect/login.esp", "/+CSCOE+/logon.html", "/+webvpn+/", "/CACHE/sslvpn/", "/prx/000/http/localhost/dana-na/", "/vpn/index.html", "/sslvpn/Login/Login"]
quick_wins:
  - { cmd: "curl -sk -o /dev/null -w '%{http_code} %{url_effective}\\n' https://{host}/dana-na/auth/url_default/welcome.cgi", safety: safe, note: "Pulse/Ivanti portal detection via response code and redirect chain" }
  - { cmd: "curl -sk -D - https://{host}/remote/login | grep -i 'set-cookie\\|server\\|x-powered-by\\|fortinet'", safety: safe, note: "FortiGate SSL-VPN header banner grab to confirm product and infer firmware version" }
  - { cmd: "curl -sk https://{host}/global-protect/gpclientauth.esp -d '' -H 'Content-Type: application/x-www-form-urlencoded' | grep -i 'palo\\|panorama\\|gp-version'", safety: safe, note: "GlobalProtect version disclosure via unauthenticated client-auth endpoint" }
  - { cmd: "nmap -sV -p 10443,8843 --script ssl-cert,http-title,http-headers {host}", safety: safe, note: "TLS certificate CN / SAN and HTTP title reveal vendor and hostname on vendor-specific alternate ports" }
  - { cmd: "curl -sk https://{host}/+CSCOE+/logon.html | grep -i 'webvpn\\|version\\|cisco'", safety: safe, note: "Cisco AnyConnect / ASA version string disclosure from login page source" }
  - { cmd: "python3 CVE-2024-21893-poc.py --target https://{host} --check-only", safety: intrusive, note: "Ivanti Connect Secure SSRF check (CVE-2024-21893); read-only probe, no exploitation" }
  - { cmd: "curl -sk 'https://{host}/remote/fgt_lang?lang=../../../../etc/passwd' -o /tmp/out.txt && head /tmp/out.txt", safety: intrusive, note: "FortiGate path traversal CVE-2018-13379 / CVE-2022-42475 read probe — confirm scope authorisation before running" }
references:
  - "CVE-2024-21893"
  - "CVE-2024-21888"
  - "CVE-2023-46805"
  - "CVE-2023-21716"
  - "CVE-2022-42475"
  - "CVE-2022-40684"
  - "CVE-2021-22893"
  - "CVE-2019-11510"
  - "CVE-2018-13379"
  - "CISA KEV 2024-01-10 (Ivanti Connect Secure)"
  - "CISA KEV 2021-11-03 (Pulse Secure)"
  - "CISA KEV 2022-10-10 (Fortinet SSL-VPN)"
mitre: "T1133"
---
# VPN / Edge Appliance Guidance

VPN and edge appliances (Palo Alto GlobalProtect, Ivanti/Pulse Secure Connect, Fortinet FortiGate SSL-VPN, Cisco ASA/AnyConnect, SonicWall SSLVPN, F5 BIG-IP APM, Check Point Mobile Access) are the single most targeted class of perimeter device in modern intrusion campaigns. They are internet-facing by design, run proprietary operating systems that receive patches slowly, and sit at the trust boundary between untrusted networks and internal infrastructure. A confirmed portal on an engagement immediately warrants version enumeration and CVE matching before any deeper testing.

Detection begins with passive HTTP probing against well-known login URI markers. Each vendor ships a distinctive path that is present even on unauthenticated sessions: `/dana-na/` and its sub-paths for Ivanti/Pulse; `/remote/login` and `/remote/fgt_lang` for FortiGate; `/global-protect/gpclientauth.esp` and `/global-protect/login.esp` for PAN-OS GlobalProtect; `/+CSCOE+/logon.html` and `/+webvpn+/` for Cisco ASA. A single `curl -sk -D -` request to these paths is sufficient to confirm vendor and often infer firmware generation from banner strings or TLS certificate metadata. All of this is read-only and carries no impact on availability or session state.

The risk profile of exposed VPN portals is extreme. CVE-2019-11510 (Pulse pre-auth arbitrary file read), CVE-2021-22893 (Pulse RCE), CVE-2018-13379 and CVE-2022-42475 (FortiGate path traversal and heap overflow), CVE-2022-40684 (FortiOS auth bypass), and the 2024 Ivanti SSRF/RCE chain (CVE-2023-46805, CVE-2024-21888, CVE-2024-21893) are all present on CISA KEV and have been exploited by nation-state actors to harvest credentials, plant webshells, and pivot to internal networks without any prior authentication. Version disclosure alone justifies an elevated finding even if no PoC is run.

For authorised assessments: start with the safe quick-wins above to enumerate vendor and version, cross-reference against CISA KEV and vendor advisories, and report any unpatched instance as critical without needing to trigger a payload. Only escalate to the intrusive traversal or SSRF checks under explicit written scope approval. Remediation: ensure appliances are on the latest vendor-released firmware, restrict management and portal interfaces to known source IPs, enable multi-factor authentication on all VPN profiles, and rotate all credentials if a historically vulnerable version was internet-exposed.
