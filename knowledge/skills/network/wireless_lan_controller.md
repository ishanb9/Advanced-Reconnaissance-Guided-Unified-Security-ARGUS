---
id: wireless_lan_controller
technology: "Wireless LAN Controllers (Cisco WLC / AireOS)"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [5246, 5247]
  banners: ["Cisco WLC", "AireOS", "Wireless LAN Controller", "CAPWAP", "cisco wireless"]
  markers: ["cisco-wlc", "aireos", "capwap", "WLC", "Cisco Wireless LAN Controller"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,443,5246,5247 --script=ssh-hostkey,http-title,ssl-cert {host}", safety: safe, note: "SSH hostkey + HTTPS management UI + CAPWAP ports (5246/5247 UDP) fingerprint — reveals AireOS version and controller model." }
  - { cmd: "nmap -Pn -p5246 -sU {host}", safety: safe, note: "CAPWAP control channel probe (UDP 5246) — confirms WLC reachability; responses include controller version in CAPWAP discovery reply." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr,snmp-info {host}", safety: safe, note: "SNMP sysDescr — leaks AireOS version, WLC platform (5520, 8540, C9800), and AP count with default community string." }
  - { cmd: "curl -sk https://{host}/screens/frameset.html -I 2>/dev/null | head -20", safety: safe, note: "Cisco WLC web management interface probe — HTTP headers and response reveal AireOS or IOS-XE (C9800) software version." }
references: ["CVE-2022-20695", "CVE-2023-20056", "CVE-2022-20760", "CVE-2021-1419"]
mitre: "T1190"
---
# Wireless LAN Controllers (Cisco WLC / AireOS)

Wireless LAN Controllers (WLCs) centralize management of enterprise Wi-Fi access points using
the CAPWAP (Control and Provisioning of Wireless Access Points) protocol on UDP ports 5246/5247.
Cisco is the dominant vendor (WLC 5520/8540 running AireOS, Catalyst 9800 running IOS-XE Wireless);
the controller manages RF policies, SSID configuration, client authentication (802.1X/PSK), and
roaming for all associated lightweight APs. A compromised WLC grants full visibility into wireless
client behavior, RADIUS secrets used for 802.1X, PSK values, and the ability to deauthenticate
or intercept all wireless traffic site-wide.

**Why it matters.** CVE-2022-20695 (CVSS 10.0) allowed unauthenticated remote access to the
Cisco WLC management interface by sending a crafted authentication bypass request — affecting
AireOS WLCs running 8.10.151.0 specifically. CVE-2022-20760 and CVE-2023-20056 caused denial-of-
service via malformed CAPWAP or mDNS packets, triggering AP disassociation. CVE-2021-1419 allowed
privilege escalation from a guest operator account to admin on AireOS. Controllers often store
802.1X EAP supplicant credentials, PSK values, and RADIUS shared secrets in recoverable form.

**Safe-first testing.** Banner-grab the management HTTPS interface and SSH service to determine
version. Use SNMP sysDescr to confirm AireOS vs IOS-XE WLC (C9800) and retrieve AP count.
Probe CAPWAP discovery on UDP 5246 with a discovery request to obtain the controller's version in
the response without establishing a full CAPWAP tunnel. Do not send malformed or crafted CAPWAP
packets that could trigger AP disconnects — this disrupts live wireless clients network-wide.

**Remediation.** Apply Cisco Security Advisories for WLC; restrict WLC management to an OOB
management VLAN; disable HTTP management (enforce HTTPS only); enforce SNMPv3 with authPriv;
rotate RADIUS shared secrets; audit operator accounts for privilege levels; and upgrade from
AireOS to IOS-XE C9800 where possible for a more modern security posture.
