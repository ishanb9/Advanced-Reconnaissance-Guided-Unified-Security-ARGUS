---
id: cisco_ise_nac
technology: "Cisco Identity Services Engine (ISE) NAC"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1812, 1813, 9060, 9443, 9444]
  banners: ["cisco identity services engine", "cisco ise", "ise-pic", "radius"]
  markers: ["/admin/login.jsp", "/guestportal/", "/api/v1/deployment/node", "ise-mgmt", "ERS-API"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}:9443/admin/login.jsp | grep -i 'cisco\\|ise\\|identity services'", safety: safe, note: "ISE admin portal login page fingerprinting — confirms ISE presence and may reveal version from page source." }
  - { cmd: "curl -sk -D - https://{host}:9060/ers/config/endpoint -H 'Accept: application/json' 2>/dev/null | head -10", safety: safe, note: "ISE ERS API unauthenticated probe — header response reveals API presence and may disclose version without credentials." }
  - { cmd: "nmap -Pn -sU -sT -p1812,1813,9060,9443,9444 --script radius-domain {host}", safety: safe, note: "RADIUS ports (1812/1813 UDP) + ERS API (9060) port scan confirms ISE role; radius-domain NSE probes for domain info." }
  - { cmd: "curl -sk 'https://{host}:9443/admin/login.jsp' | grep -i 'version\\|build\\|release'", safety: safe, note: "Version string extraction from ISE admin portal HTML source — read-only, no authentication required." }
  - { cmd: "curl -sk -X GET 'https://{host}:9060/ers/config/networkdevice' -u admin:Admin1234 -H 'Accept: application/json'", safety: intrusive, note: "ERS API network device list — if authenticated, reveals all NAC-managed network devices. Gate with authorisation." }
references:
  - "CVE-2022-20822"
  - "CVE-2022-20959"
  - "CVE-2023-20025"
  - "CVE-2023-20195"
  - "Cisco PSIRT Advisory cisco-sa-ise-path-trav-Dz5dpzyM"
  - "CISA KEV 2022-11-03 (Cisco ISE Path Traversal)"
mitre: "T1078"
---
# Cisco Identity Services Engine (ISE) NAC

Cisco Identity Services Engine (ISE) is the dominant enterprise Network Access Control (NAC) and policy engine, deployed in large enterprise, government, and healthcare networks worldwide. ISE authenticates users and devices via 802.1X RADIUS (ports 1812/1813 UDP), enforces posture compliance (checking endpoint AV, patch level, and OS), provides guest portal services, and integrates with Active Directory for identity context. The admin console runs on port 9443 (HTTPS), and the External RESTful Services (ERS) API is on port 9060. ISE is a crown-jewel asset — compromise gives an attacker the ability to grant or revoke network access for the entire enterprise.

Critical vulnerabilities include CVE-2022-20822 and CVE-2022-20959 (XML external entity injection and reflected XSS in the admin portal), and CVE-2023-20195 (privilege escalation). ISE's ERS API has historically required TLS but not always strong authentication, and default or weak ERS admin credentials (`ersadmin`) have been found in real-world deployments. The guest portal (accessible to unauthenticated users by design) has a separate attack surface. ISE nodes often run with excessive domain privileges for AD authentication, making them an attractive target for credential harvesting and lateral movement into AD.

**Safe-first testing.** Fingerprint ISE via HTTPS probe on port 9443 (admin portal) and port 9060 (ERS API). The login page source and HTTP headers often contain version and build information without authentication. RADIUS port presence (1812/1813 UDP) confirms NAC role. Cross-reference the ISE software version against Cisco PSIRT advisories. Only attempt ERS API authentication under explicit written scope — even read-only API calls enumerate sensitive device and identity data. Never modify RADIUS policies or access rules during assessment.

**Remediation.** Apply current Cisco ISE software patches; restrict the admin console (9443) and ERS API (9060) to management hosts; change default ERS admin credentials; enforce TLS mutual authentication for admin API access; harden ISE's AD service account to the minimum required permissions; enable ISE admin activity logging; segment the ISE Policy Administration Node (PAN) and Policy Service Nodes (PSNs) onto a dedicated management VLAN; and review guest portal exposure to ensure it is limited to the guest network segment only.
