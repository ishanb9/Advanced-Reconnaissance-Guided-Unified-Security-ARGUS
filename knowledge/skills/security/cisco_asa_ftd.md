---
id: cisco_asa_ftd
technology: "Cisco ASA / Firepower Threat Defense (FTD)"
domain: IT
category: security
transport: ip
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [4444, 50000]
  banners: ["cisco adaptive security", "cisco asa", "cisco firepower", "cisco ftd", "firepower management center"]
  markers: ["/+CSCOE+/logon.html", "/+webvpn+/", "/admin/public/index.html", "webvpnlogin", "CSCO_WEBVPN_OTP_FORM"]
quick_wins:
  - { cmd: "curl -sk https://{host}/+CSCOE+/logon.html | grep -i 'cisco\\|webvpn\\|VERSION\\|ASA'", safety: safe, note: "ASA AnyConnect portal fingerprint — version sometimes disclosed in page source or HTTP response headers." }
  - { cmd: "curl -sk -D - https://{host}/+webvpn+/ | head -40", safety: safe, note: "WebVPN portal header grab confirms Cisco ASA SSL-VPN and may reveal software train from cookie/header patterns." }
  - { cmd: "nmap -Pn -sT -p443,4444,8443 --script ssl-cert,http-title,http-headers {host}", safety: safe, note: "TLS certificate SAN and HTTP response title fingerprint ASA management vs FMC vs FTD management console." }
  - { cmd: "snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1", safety: safe, note: "SNMP sysDescr/sysObjectID — ASA often exposes exact software version via SNMP if community string is default." }
  - { cmd: "curl -sk -X POST 'https://{host}/+webvpn+/index.html' --data 'username=admin&password=cisco123&Login=Login' -D -", safety: intrusive, note: "Default credential probe against WebVPN portal — gated; produces authentication log entries on target." }
references:
  - "CVE-2023-20269"
  - "CVE-2020-3452"
  - "CVE-2018-0296"
  - "CVE-2016-6366"
  - "CVE-2014-3393"
  - "CISA KEV 2023-09-07 (Cisco ASA/FTD Unauthorized Access)"
  - "CISA KEV 2020-11-03 (Cisco ASA Path Traversal)"
mitre: "T1190"
---
# Cisco ASA / Firepower Threat Defense (FTD)

Cisco Adaptive Security Appliance (ASA) and its successor Firepower Threat Defense (FTD) are among the most widely deployed perimeter firewalls and VPN concentrators in the world, found in enterprise, government, and carrier environments. ASA runs the proprietary ASA OS; FTD runs on Firepower hardware and integrates with Firepower Management Center (FMC) for centralised policy. Both expose an AnyConnect SSL-VPN portal (typically on 443 or 8443), a management HTTPS console, and optionally SNMP and SSH for operational access. The WebVPN service on Cisco ASA has been a long-standing exploitation target due to high internet exposure.

The vulnerability record spans years of critical exposures. CVE-2016-6366 (EXTRABACON, NSA/Shadow Brokers; SNMP buffer overflow enabling RCE) and CVE-2014-3393 (WebVPN arbitrary file read) are legacy risks on unmaintained installs. CVE-2018-0296 (pre-auth directory traversal on management interface) and CVE-2020-3452 (pre-auth file read via WebVPN, CVSS 7.5) were heavily exploited and remain present on unpatched appliances. Most recently, CVE-2023-20269 is a zero-day brute-force / credential spray weakness in AnyConnect and SSL-VPN — exploited by ransomware groups (Akira, LockBit) to gain initial access with valid credentials.

**Safe-first testing.** Fingerprint the portal via the `/+CSCOE+/logon.html` and `/+webvpn+/` marker paths; extract version information from HTTP headers, page source, and TLS certificate metadata. SNMP sysDescr can return the exact ASA software version if community strings are default. Cross-reference against Cisco PSIRT advisories and CISA KEV. Any brute-force or credential probe (CVE-2023-20269 angle) requires explicit written authorisation, is intrusive, and will produce authentication failure logs on the target.

**Remediation.** Apply current Cisco PSIRT patches for ASA OS and FTD; disable legacy SSL-VPN profiles where AnyConnect/IKEv2 with multi-factor authentication can be enforced; change SNMP community strings from defaults and restrict SNMP to management hosts; restrict the ASDM and management interface to out-of-band networks; and monitor for credential spray activity against AnyConnect. FMC-managed environments should audit role-based access control and API credentials.
