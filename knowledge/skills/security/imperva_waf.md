---
id: imperva_waf
technology: "Imperva WAF / SecureSphere"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [8083, 8085]
  banners: ["imperva", "securesphere", "incapsula", "x-cdn: imperva", "x-iinfo", "visid_incap"]
  markers: ["/_Incapsula_Resource", "incap_ses", "visid_incap", "X-CDN: Imperva", "X-Iinfo", "reese84"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/ | grep -i 'imperva\\|incapsula\\|x-iinfo\\|visid_incap\\|x-cdn'", safety: safe, note: "HTTP response header inspection for Imperva cloud WAF response headers and cookies — passive, read-only fingerprint." }
  - { cmd: "curl -sk 'https://{host}/_Incapsula_Resource?SWCGHOEL=v2' | head -10", safety: safe, note: "Incapsula resource endpoint probe — response confirms cloud WAF presence and may reveal version info." }
  - { cmd: "nmap -Pn -sT -p8083,8085 --script http-title,ssl-cert {host}", safety: safe, note: "SecureSphere management port probe (8083/8085) — management console presence and TLS cert fingerprinting." }
  - { cmd: "curl -sk -X GET 'https://{host}/SecureSphere/api/v1/conf/systemDefinitions/generalSettings' -u admin:admin", safety: intrusive, note: "SecureSphere REST API default credential probe — gated; produces authentication log on MX appliance." }
  - { cmd: "wafw00f https://{host}", safety: safe, note: "WAF fingerprinting tool — identifies Imperva vs other WAF vendors from challenge page and header patterns." }
references:
  - "CVE-2019-7483"
  - "CVE-2018-16975"
  - "CVE-2021-45477"
  - "Imperva Security Advisory 2021-01"
mitre: "T1190"
---
# Imperva WAF / SecureSphere

Imperva offers two distinct WAF product lines: **SecureSphere** (on-premises MX appliance managing Web Application Firewall gateway agents) and **Incapsula / Imperva Cloud WAF** (cloud-delivered WAF and CDN sitting in front of web applications). SecureSphere is widely used by banks, insurance companies, and healthcare organisations to protect web applications and database servers on-premises. The cloud WAF (Imperva Cloud Security Platform) proxies traffic through Imperva POPs globally and is used by thousands of websites. Both are security controls, not just network infrastructure — a misconfigured or bypassed Imperva WAF directly exposes the protected application to attack.

From an offensive perspective, two surfaces matter: the **management plane** (SecureSphere MX management server on port 8083/8085, with a SOAP/REST API and Java-based management console) and the **WAF bypass** angle (cloud WAF mitigation evasion by finding the origin IP behind the CDN, then hitting it directly). CVE-2019-7483 is a pre-auth path traversal in SecureSphere's management server. CVE-2021-45477 is a stored XSS in the management console. On the cloud side, the primary risk is origin IP disclosure via DNS records, HTTP response headers, or SSL certificate SANs, which allows an attacker to bypass the WAF entirely.

**Safe-first testing.** Fingerprint cloud Imperva deployments using the `visid_incap`/`incap_ses` cookie names, `X-Iinfo` header, and the `/_Incapsula_Resource` probe path — all are read-only and produce no server-side state change. Use `wafw00f` to confirm WAF vendor. For SecureSphere on-prem, port-scan for the management ports and grab TLS certificate metadata. Origin IP discovery (checking historical DNS, SSL cert SANs for the origin, Shodan/Censys certificate search) is a passive reconnaissance activity that does not touch the target.

**Remediation.** For SecureSphere: patch the MX management server to the current release; restrict management access to administrator networks; use certificate-based management authentication; and harden the management API. For cloud WAF: ensure the origin server has strict IP allowlisting accepting traffic only from Imperva edge IPs; audit DNS history and TLS certificate SAN to ensure no origin IP leakage; and configure SSL certificate pinning in the Imperva portal to prevent certificate transparency enumeration of the origin.
