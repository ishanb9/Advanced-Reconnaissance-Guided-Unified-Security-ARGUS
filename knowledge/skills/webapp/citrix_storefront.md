---
id: citrix_storefront
technology: "Citrix StoreFront / NetScaler Gateway"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["Citrix", "NetScaler"]
  markers: ["/Citrix/StoreWeb/", "/vpn/index.html", "X-Citrix-Application", "NSC_AAAC", "NSC_TMAS", "CitrixAGBasic", "/logon/LogonPoint/", "Citrix.Authentication"]
quick_wins:
  - { cmd: "curl -s -I 'https://{host}/Citrix/StoreWeb/' | grep -i 'server\\|x-citrix\\|citrix-version'", safety: safe, note: "StoreFront headers — version and component identification; read-only." }
  - { cmd: "curl -s 'https://{host}/vpn/index.html' | grep -o 'Citrix [A-Za-z ]*[0-9.]*'", safety: safe, note: "NetScaler/ADC Gateway login page version fingerprint — read-only." }
  - { cmd: "nmap -Pn -sT -p443 --script http-citrix-storefront-login {host}", safety: safe, note: "Citrix StoreFront login page probe — confirms StoreFront presence and version from login page response." }
  - { cmd: "curl -s -X GET 'https://{host}/oauth/v0/token' -H 'NSC_AAAC: ../../../../etc/passwd'", safety: intrusive, note: "GATED — CVE-2023-3519 unauthenticated RCE / path traversal probe pattern; only against explicitly authorized target." }
references: ["CVE-2023-3519","CVE-2023-4966","CVE-2019-19781","CVE-2022-27510","CVE-2022-27518","KEV CISA AA23-201A"]
mitre: "T1190"
---
# Citrix StoreFront / NetScaler Gateway

Citrix StoreFront and NetScaler (Citrix ADC) Gateway are the remote access and application delivery
components of most large enterprise and healthcare networks — they provide the HTTPS portal through
which employees and contractors reach internal desktops, applications, and VDI sessions.
CVE-2019-19781 (Citrix ADC path traversal / RCE) was one of the most widely exploited enterprise
vulnerabilities of 2020, actively targeted by ransomware, APT33, and initial-access brokers.
CVE-2023-4966 ("Citrix Bleed") — unauthenticated memory disclosure leaking session tokens — was
mass-exploited in late 2023 against healthcare, financial services, and government targets.

**Key attack surfaces.** CVE-2019-19781 exploited a path traversal in the VPN endpoint
(`/vpn/../vpns/cfg/smb.conf`) to write a Perl script and achieve RCE without authentication.
CVE-2023-3519 (unauthenticated RCE on NetScaler ADC/Gateway) achieved a CVSS 9.8 and was added
to CISA KEV with evidence of widespread exploitation within 24 hours of advisory publication.
CVE-2023-4966 (Citrix Bleed) allowed unauthenticated memory read of the NetScaler buffer, leaking
session tokens for authenticated sessions — enabling full session hijacking without credentials.
CVE-2022-27510 and CVE-2022-27518 add further authentication bypass and RCE vectors.
StoreFront XML broker service misconfigurations can expose internal infrastructure.

**Safe-first testing.** Fingerprint the product and version from the login page and response
headers. Check for the NetScaler VPN path (`/vpn/index.html`) and StoreFront path
(`/Citrix/StoreWeb/`). Enumerate published applications and published desktops from the StoreFront
SOAP/REST API if anonymous enumeration is allowed. Compare the identified version against CISA KEV
and Citrix CTX advisories. Do NOT send path traversal payloads, session token probes, or any
active exploit attempts without explicit authorization.

**Remediation.** Apply Citrix security updates immediately on release — ADC/Gateway vulnerabilities
are mass-exploited within hours of disclosure. Restrict management access (SSH, NSIP) to the
management VLAN. Enable ADC application firewall (AppFW) with default deny policy. Force
re-authentication after patching CVE-2023-4966 — all active sessions must be invalidated as leaked
tokens remain valid after patching. Deploy NetScaler Intelligence or Citrix Analytics for anomaly
detection. For StoreFront: restrict the Delivery Controller communication channel to internal IPs.
