---
id: panos_ngfw
technology: "Palo Alto PAN-OS Next-Gen Firewall"
domain: IT
category: security
transport: ip
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [3978, 28443]
  banners: ["pan-os", "palo alto networks", "globalprotect", "panorama"]
  markers: ["/php/login.php", "/api/?type=version", "/global-protect/login.esp", "X-FRAME-OPTIONS: SAMEORIGIN"]
quick_wins:
  - { cmd: "curl -sk https://{host}/api/?type=version", safety: safe, note: "Unauthenticated PAN-OS version disclosure via XML API — returns sw-version, model, serial without credentials." }
  - { cmd: "curl -sk -D - https://{host}/php/login.php | grep -i 'pan-os\\|x-pan\\|server\\|set-cookie'", safety: safe, note: "HTTP header grab to confirm PAN-OS management plane presence and infer version generation." }
  - { cmd: "nmap -Pn -sT -p443,4443,28443 --script ssl-cert,http-title,http-auth-finder {host}", safety: safe, note: "TLS certificate CN/SAN + HTTP title reveal hostname, management URL, and certificate-based fingerprinting." }
  - { cmd: "curl -sk 'https://{host}/api/?type=op&cmd=<show><system><info></info></system></show>&key=APIKEY'", safety: intrusive, note: "Authenticated system-info pull via XML API — read-only but requires a harvested or low-privilege API key." }
  - { cmd: "curl -sk -X POST 'https://{host}/api/?type=op&cmd=<show><config><running></running></config></show>&key=APIKEY'", safety: intrusive, note: "Pull running config — gated; requires key. Never modify config without explicit scope authorisation." }
references:
  - "CVE-2024-3400"
  - "CVE-2022-0028"
  - "CVE-2021-3064"
  - "CVE-2020-2021"
  - "CVE-2019-1579"
  - "CISA KEV 2024-04-12 (PAN-OS GlobalProtect OS Command Injection)"
  - "CISA KEV 2021-11-03 (PAN-OS GlobalProtect RCE)"
mitre: "T1190"
---
# Palo Alto PAN-OS Next-Gen Firewall

Palo Alto Networks PAN-OS is the operating system powering the industry-leading PA-Series hardware firewalls and VM-Series virtual appliances. PAN-OS firewalls sit at network perimeters in enterprises, data centres, and government environments worldwide, performing application-layer inspection, URL filtering, WildFire threat prevention, and SSL decryption. The management web UI runs on port 443 (or a custom management port), and an XML API endpoint at `/api/` is used by Panorama orchestration and scripting integrations. Both surfaces have been the target of critical pre-authentication vulnerabilities.

The most impactful recent vulnerability is CVE-2024-3400, a pre-authentication OS command injection in the GlobalProtect Gateway feature exploited as a zero-day by nation-state actors (UTA0218). Prior critical exposures include CVE-2021-3064 (GlobalProtect buffer overflow RCE, CVSS 9.8), CVE-2020-2021 (authentication bypass when SAML is enabled, CVSS 10), and CVE-2019-1579 (pre-auth RCE against the GlobalProtect portal). All are on CISA KEV. The XML API endpoint `/api/?type=version` discloses the exact PAN-OS software version without any authentication, making version triage trivial from the internet.

**Safe-first testing.** Begin with the unauthenticated `/api/?type=version` call to pin the software version, then cross-reference against the PAN-OS security advisory list and CISA KEV. TLS certificate metadata and HTTP response headers also reliably fingerprint PAN-OS versus competing vendors. Only escalate to API-key-based intrusive queries under explicit written scope authorisation. Never issue configuration write operations (`type=config&action=set`) in any assessment without a formal change control window — a misconfigured security policy can drop legitimate traffic.

**Remediation.** Apply the latest PAN-OS maintenance release immediately; restrict management plane access (port 443/4443/28443) to out-of-band management networks via allowed-IPs; disable GlobalProtect portal and gateway interfaces that are not in active use; enable certificate-based admin authentication; and subscribe to the Palo Alto PSIRT advisory feed. Panorama-managed estates should be audited for shared API keys and over-privileged service accounts.
