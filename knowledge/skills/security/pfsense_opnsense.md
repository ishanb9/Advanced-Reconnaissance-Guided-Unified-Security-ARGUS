---
id: pfsense_opnsense
technology: "pfSense / OPNsense Open-Source Firewall"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: []
  banners: ["pfsense", "opnsense", "m0n0wall", "freebsd"]
  markers: ["/index.php", "pfSense", "OPNsense", "/login", "__csrf_magic", "CSRF_TOKEN_KEY", "pfsense-core"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/ | grep -i 'pfsense\\|opnsense\\|csrf\\|freebsd'", safety: safe, note: "pfSense/OPNsense web UI fingerprinting via HTTP response headers and page source — confirms product and may reveal version." }
  - { cmd: "curl -sk https://{host}/index.php | grep -i 'version\\|pfsense\\|opnsense\\|release'", safety: safe, note: "Login page source version string extraction — read-only, no authentication required." }
  - { cmd: "nmap -Pn -sT -p443,80 --script ssl-cert,http-title,http-headers {host}", safety: safe, note: "TLS cert and HTTP title fingerprint pfSense vs OPNsense and reveal hostname from certificate SAN." }
  - { cmd: "curl -sk https://{host}/api/v1/diagnostics/systemInformation -H 'Authorization: Basic YWRtaW46cGZzZW5zZQ=='", safety: intrusive, note: "OPNsense REST API default credential (admin:opnsense) system info check — produces auth log. Gate with authorisation." }
  - { cmd: "curl -sk -X POST https://{host}/index.php -d '__csrf_magic=&usernamefld=admin&passwordfld=pfsense&login=Sign+In'", safety: intrusive, note: "pfSense default credential login attempt (admin:pfsense) — produces authentication log. Requires explicit scope." }
references:
  - "CVE-2023-27253"
  - "CVE-2022-31814"
  - "CVE-2021-41282"
  - "CVE-2020-19212"
  - "CVE-2019-16667"
  - "SA-21_02 pfSense"
mitre: "T1190"
---
# pfSense / OPNsense Open-Source Firewall

pfSense (NetGate) and OPNsense (Deciso) are the two dominant open-source firewall and router platforms, both derived from FreeBSD. They are widely used in SMBs, home labs, ISPs, and even enterprise branch offices as cost-effective alternatives to commercial NGFW appliances. pfSense and OPNsense provide stateful packet filtering, NAT, VPN (OpenVPN, IPsec, WireGuard), IDS/IPS (via Snort or Suricata packages), web proxy (Squid), and DNS filtering (pfBlockerNG). The management web UI is accessible via HTTPS on port 443 (or a configured custom port), and OPNsense also exposes a REST API. Both platforms ship with well-known default credentials (`admin:pfsense` and `admin:opnsense` respectively).

Critical vulnerabilities include CVE-2022-31814 (pfSense CE pfBlockerNG package — remote code execution via unsanitized HTTP headers, actively exploited in the wild), CVE-2023-27253 (OPNsense stored XSS), and CVE-2021-41282 (pfSense reverse proxy group privilege escalation). The packages ecosystem (pfSense packages, OPNsense plugins) extends the attack surface significantly — third-party packages may not receive timely security patches. Default credentials are a perennial finding; many deployments remain on default `admin:pfsense` especially in home and SMB contexts. CSRF vulnerabilities have appeared repeatedly across pfSense releases.

**Safe-first testing.** Fingerprint pfSense/OPNsense via HTTP response headers and login page source. The CSRF magic token field and page branding make detection reliable. TLS certificate CN/SAN (if self-signed) often contains the firewall hostname. For pfBlockerNG (CVE-2022-31814), check package version from the login page metadata or from the package management screen after authentication. Only attempt default credential checks under explicit written scope authorisation — even a failed attempt creates authentication log entries.

**Remediation.** Change default admin credentials immediately on deployment; restrict the web management interface to a dedicated management VLAN with no internet exposure; enable HTTPS with a trusted certificate; disable the web GUI on WAN interfaces; keep the base firmware and all packages updated (especially pfBlockerNG); enable pfSense/OPNsense authentication via RADIUS or LDAP for enterprise deployments; and configure two-factor authentication (TOTP) for the management UI where supported.
