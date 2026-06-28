---
id: ecdis
technology: "ECDIS (Electronic Chart Display and Information System)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [4001, 4002]
  banners: ["ECDIS", "S-57", "S-63", "ENC", "IHO", "chartworld", "transas", "furuno nav"]
  markers: ["S-57", "S-63", "ENC update", "navionics", "jeppesen"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p4001,4002 --script banner {host}", safety: safe, note: "Identify ECDIS vendor, software version, and ENC update service from banner — read-only enumeration." }
  - { cmd: "nmap -Pn -sV -p135,139,445,3389,4001,4002,10110 {host}", safety: safe, note: "ECDIS runs on Windows; enumerate all exposed services to assess OS patch level and remote-access exposure." }
  - { cmd: "nmap -Pn -p445 --script smb-security-mode,smb2-security-mode,smb-os-discovery {host}", safety: safe, note: "Assess Windows SMB configuration — ECDIS hosts are frequently unpatched Windows XP/7/10 embedded systems with SMBv1 enabled." }
  - { cmd: "<exploit EternalBlue / MS17-010 or install unapproved ENC update file on {host}>", safety: disruptive, note: "GATED — compromising the chart display system directly impacts voyage safety and situational awareness. Requires written authorization and vessel at berth." }
references: ["CVE-2017-0144", "BIMCO Cyber Security Guidelines 2019", "IMO MSC-FAL.1/Circ.3", "US-CERT TA17-132A"]
mitre: "T0853 / ICS T0866"
---
# ECDIS (Electronic Chart Display and Information System)

ECDIS is the IMO-mandated replacement for paper nautical charts aboard SOLAS vessels, displaying
Electronic Navigation Charts (ENCs, IHO S-57 format, encrypted with S-63) fused with real-time
navigation data — GPS position, AIS targets, radar overlays, depth contours, and route planning.
Nearly all ECDIS units run on **embedded Windows** (XP, 7, 10) from vendors including Transas
(Wärtsilä), JRC, Furuno, Kongsberg, and Raytheon Anschütz. The Windows host communicates with
navigation instruments over **10110/tcp (NMEA)** and may expose proprietary update services on
**4001-4002/tcp** for ENC chart delivery. Because the IMO type-approval process locks software
versions, ECDIS hosts are routinely years behind on OS and application patches — an unpatched
Windows host at the heart of the vessel's navigation picture.

**Safety-of-life scope.** The ECDIS is the primary navigation display and route-monitoring system.
A compromised or degraded ECDIS — displaying a wrong position, missing a shoal, or crashing during
a passage — can lead to grounding, allision, or collision. This asset is therefore `life_safety: true`.
Documented incidents include the 2019 BIMCO survey finding that ECDIS systems were among the most
commonly compromised IT assets aboard vessels, frequently via infected USB chart-update sticks and
remote-access ports left open for vendor support.

**Safe-first testing.** Begin with read-only OS and service enumeration: SMB security mode, RDP
exposure, open ports, and OS version fingerprinting. Check whether Windows Firewall and automatic
updates are enabled — they frequently are not due to type-approval constraints. Enumerate shared
directories over SMB that might accept unsigned ENC update files. Verify whether USB autorun is
disabled. **Do not** interact with the chart display application, inject NMEA data, or modify
any ENC files without explicit scoped authorization and a vessel-at-berth precondition. The window
between a malicious ENC installation and a passage where it causes harm may be hours or days.

**Remediation.** Isolate ECDIS on a dedicated navigation VLAN with no inbound internet access;
disable USB autorun and enforce signed chart updates; apply Windows OS patches within type-approval
constraints (coordinate with OEM for approved patch bundles); disable SMBv1; enforce MFA on any
remote-access session; document firmware and software versions against IMO and flag-state ECDIS
performance standards (IEC 61174). Reference BIMCO Cyber Security Guidelines and IMO
MSC-FAL.1/Circ.3 for fleet policy.
