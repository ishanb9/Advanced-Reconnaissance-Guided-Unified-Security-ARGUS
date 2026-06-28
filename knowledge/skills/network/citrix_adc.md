---
id: citrix_adc
technology: "Citrix ADC / NetScaler"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [9080, 9443]
  banners: ["NetScaler", "Citrix ADC", "Citrix Gateway", "netscaler", "NS"]
  markers: ["netscaler", "citrix-adc", "NSC_", "CitrixAGBasic", "Citrix Gateway", "X-NS-"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p443,9080,9443 --script=ssl-cert,http-title,http-headers {host}", safety: safe, note: "TLS cert + HTTP headers (Set-Cookie: NSC_ cookies, X-NS-* headers) — fingerprints NetScaler and reveals version in Server header." }
  - { cmd: "curl -sk https://{host}/nitro/v1/config/nsversion 2>/dev/null | python3 -m json.tool | head -20", safety: safe, note: "NetScaler NITRO REST API read — unauthenticated version query on some builds; reveals ADC firmware version." }
  - { cmd: "curl -sk https://{host}/oauth/idp/.well-known/openid-configuration 2>/dev/null | python3 -m json.tool | head -20", safety: safe, note: "nFactor/AAA OIDC endpoint discovery — leaks realm information and confirms Citrix Gateway is active." }
  - { cmd: "curl -sk 'https://{host}/logon/LogonPoint/tmindex.html' -I 2>/dev/null | head -20", safety: safe, note: "Citrix StoreFront/Gateway logon page probe — response headers reveal ADC firmware in X-Citrix-* headers." }
references: ["CVE-2019-19781", "CVE-2023-3519", "CVE-2023-4966", "CVE-2024-6235", "KEV 2020-01-17", "KEV 2023-07-18"]
mitre: "T1190"
---
# Citrix ADC / NetScaler

Citrix ADC (formerly NetScaler) is a widely deployed application delivery controller and SSL VPN
gateway used in enterprise, healthcare, and government environments. It provides load balancing,
content switching, SSL offload, and remote access via Citrix Gateway. Management is via NSIP (a
dedicated management IP) using SSH, an HTTPS WebUI, and the NITRO REST API (9080/9443). The
Citrix Gateway component handles clientless VPN, ICA proxy, and nFactor authentication — placing
NetScaler at the perimeter for hundreds of thousands of organizations.

**Why it matters.** Citrix ADC has a recurring history of critical perimeter vulnerabilities.
CVE-2019-19781 (KEV) was a path traversal allowing unauthenticated RCE exploited by ransomware
groups and nation-state actors for months after disclosure. CVE-2023-3519 (CVSS 9.8, KEV) was an
unauthenticated RCE requiring only Gateway functionality to be enabled — CISA reported 2,000+
compromised instances within weeks. CVE-2023-4966 ("Citrix Bleed") allowed session token theft
from memory, bypassing MFA — exploited by ransomware groups targeting healthcare and government.
NetScaler is Shodan-indexed at scale with fingerprints visible from TLS certificates and cookies.

**Safe-first testing.** Inspect TLS certificates (the SAN or CN often names the Gateway FQDN)
and look for `NSC_` cookies in HTTP responses — these are the NetScaler session cookie prefix
visible unauthenticated. Query the NITRO API version endpoint as a read-only probe. Check
response headers for `X-NS-*` or `Citrix-*` identifiers. Do not send malformed requests to
test for CVE-2019-19781 or CVE-2023-3519 — these involve path traversal or buffer overflow
payloads that crash the nsppe process on vulnerable appliances.

**Remediation.** Apply Citrix Security Bulletins immediately (especially for CVE-2023-3519 and
CVE-2023-4966); restrict NSIP management to a dedicated out-of-band management network; disable
Gateway if not required; rotate session encryption keys after patching CVE-2023-4966; enable Web
Application Firewall policies; and monitor for unexpected `nsppe` crashes which are a known
compromise indicator.
