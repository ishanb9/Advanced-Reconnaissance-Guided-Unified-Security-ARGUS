---
id: aruba_clearpass_nac
technology: "Aruba ClearPass Policy Manager (NAC)"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1812, 1813]
  banners: ["aruba", "clearpass", "aruba networks", "cppm", "arubanetworks"]
  markers: ["/api/", "/tips/", "ClearPass", "/guest/en_US/", "CPPM", "aruba-clearpass"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/ | grep -i 'aruba\\|clearpass\\|CPPM\\|x-powered'", safety: safe, note: "ClearPass web management fingerprinting via HTTP response headers and redirect destination." }
  - { cmd: "curl -sk 'https://{host}/api/version' | python3 -m json.tool 2>/dev/null", safety: safe, note: "ClearPass REST API version endpoint — may return product version and API build without authentication on some releases." }
  - { cmd: "nmap -Pn -sT -p443,8443 --script ssl-cert,http-title {host}", safety: safe, note: "TLS cert SAN and HTTP title distinguish ClearPass management vs guest portal; cert often contains CPPM hostname." }
  - { cmd: "curl -sk 'https://{host}/guest/en_US/login.php' | grep -i 'aruba\\|clearpass\\|version\\|build'", safety: safe, note: "Guest self-registration portal fingerprint — version information sometimes present in page source." }
  - { cmd: "curl -sk -X POST 'https://{host}/api/oauth' -d 'grant_type=password&username=admin&password=admin&client_id=cpsdk'", safety: intrusive, note: "ClearPass REST OAuth default credential probe — produces authentication log on ClearPass. Gate with scope authorisation." }
references:
  - "CVE-2023-25589"
  - "CVE-2022-23659"
  - "CVE-2022-23657"
  - "CVE-2023-25594"
  - "CISA KEV 2023-05-12 (Aruba ClearPass Policy Manager Auth Bypass)"
mitre: "T1078"
---
# Aruba ClearPass Policy Manager (NAC)

Aruba ClearPass Policy Manager (CPPM) is Hewlett Packard Enterprise's enterprise network access control (NAC) and policy management platform, competing directly with Cisco ISE. ClearPass is widely deployed in higher education, healthcare, hospitality, and large enterprise environments managing 802.1X RADIUS authentication, guest Wi-Fi onboarding, device profiling, and posture assessment. ClearPass is a privileged platform — it controls which devices can access which network segments and integrates with Active Directory, LDAP, MDM platforms, and the Aruba wireless infrastructure. The management web interface and REST API run on HTTPS (443/8443), and RADIUS operates on standard 1812/1813 UDP.

ClearPass has been the subject of a cluster of critical vulnerabilities in 2022-2023. CVE-2023-25589 is an unauthenticated privilege escalation in the web management interface (CVSS 9.8) allowing a remote attacker to gain root access without credentials. CVE-2022-23659 and CVE-2022-23657 are additional authentication bypass and SQL injection vulnerabilities in the management API. CVE-2023-25594 is a reflected XSS in the guest portal. Multiple of these are on CISA KEV. ClearPass's guest portal is intentionally accessible from untrusted networks, making it an attractive unauthenticated attack surface against the underlying application server.

**Safe-first testing.** Fingerprint ClearPass via HTTP response headers and TLS certificate CN/SAN (certificates typically contain the CPPM hostname). The REST API `/api/version` endpoint may return version information without authentication on older releases. Confirm the presence of the guest portal versus the management interface based on URL paths (`/guest/` vs `/admin/`). Cross-reference the exact ClearPass version against the Aruba PSIRT advisory list before escalating. Only attempt credential or exploit probes under explicit written authorisation.

**Remediation.** Apply HPE Aruba PSIRT patches immediately — the 2022-2023 cluster of vulnerabilities is severe and has confirmed exploitability. Restrict the ClearPass management interface (admin portal and REST API) to administrator networks with no direct internet exposure; segment the guest portal on a separate VLAN accessible only from the guest network; enforce MFA for ClearPass administrator accounts; audit REST API OAuth clients for excessive permissions; and regularly rotate service account credentials used for AD/LDAP integration.
