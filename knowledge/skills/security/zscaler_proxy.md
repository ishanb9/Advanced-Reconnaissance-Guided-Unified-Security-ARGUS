---
id: zscaler_proxy
technology: "Zscaler Internet Access / Cloud Proxy"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [9480, 9443]
  banners: ["zscaler", "zscalerone", "zscalertwo", "zscalerthree", "zscloud"]
  markers: ["X-Zscaler-Auth", "X-Zscaler-Client-IP", "zscaler.net", "Z-Tunnel", "ZIA Admin", "/admin/login"]
quick_wins:
  - { cmd: "curl -sk -D - https://gateway.zscalerone.net/ | grep -i 'zscaler\\|server\\|x-zscaler'", safety: safe, note: "Probe Zscaler cloud gateway domain — confirms Zscaler cloud proxy and data centre region from response headers." }
  - { cmd: "curl -sk http://{host}:9480/ | head -20", safety: safe, note: "Zscaler connector management port (9480) probe — may reveal connector version and cloud tenant association." }
  - { cmd: "nmap -Pn -sT -p9480,9443,443 --script http-title,ssl-cert {host}", safety: safe, note: "Zscaler Private Access connector port scan — TLS cert SAN reveals cloud tenant domain and connector ID." }
  - { cmd: "curl -sk 'https://{host}/api/v1/status' -H 'auth-token: TOKEN'", safety: safe, note: "ZIA REST API status endpoint — returns connector health and version info with a valid API token." }
  - { cmd: "dig +short {host}.zscaler.net TXT", safety: safe, note: "DNS TXT record lookup for Zscaler cloud organisation — passive enumeration of cloud tenant configuration." }
references:
  - "CVE-2023-28800"
  - "CVE-2024-23462"
  - "Zscaler Security Advisory ZSA-2023-001"
mitre: "T1090"
---
# Zscaler Internet Access / Cloud Proxy

Zscaler Internet Access (ZIA) is the world's largest cloud-delivered secure web proxy and security service edge (SSE) platform, used by thousands of enterprises globally as their perimeter-less internet security control. Zscaler Private Access (ZPA) provides zero-trust application access replacing traditional VPNs. Zscaler operates as an inline cloud proxy — corporate traffic is tunnel-forwarded to Zscaler's cloud points of presence (POPs) via the Zscaler Client Connector (formerly Z App) on endpoints or via on-premise Connector appliances. The on-premise Connector nodes communicate with the cloud control plane and expose management ports (9480/tcp for health, 9443/tcp for TLS management).

From an offensive perspective, Zscaler presents two distinct attack surfaces: the **cloud control plane** (ZIA admin portal and ZPA customer portal, accessible via browser) and the **on-premise Connector nodes** deployed in customer data centres or cloud environments. CVE-2023-28800 is a stored XSS in the ZIA admin portal. CVE-2024-23462 affects the Zscaler Client Connector endpoint agent. Connector nodes, if misconfigured or running outdated software, can expose unauthenticated management APIs that reveal tenant configuration. A compromised Connector node gives access to the organization's private application routing table in ZPA.

**Safe-first testing.** Identify Zscaler in the environment by examining outbound HTTP response headers (`X-Zscaler-*`), PAC file references, or Connector node port presence (9480/tcp). DNS lookups for `*.zscaler.net` or `*.zscalertwo.net` hostnames reveal the cloud tenant and data centre region passively. The Connector management port probe is a read-only HTTP request. Admin portal testing requires authentication and is firmly in the intrusive category — any policy change or configuration read in ZIA/ZPA requires explicit scope.

**Remediation.** Keep Zscaler Client Connector and Connector node software updated via the Zscaler update management system; restrict Connector node management ports to Zscaler cloud IP ranges; enable Zscaler's Advanced Threat Protection for the ZIA admin portal; enforce MFA on the ZIA and ZPA admin portals; audit ZPA application segments for overly permissive access policies (zero-trust means minimal, role-based app access); and monitor Zscaler administrator audit logs for unauthorised policy changes.
