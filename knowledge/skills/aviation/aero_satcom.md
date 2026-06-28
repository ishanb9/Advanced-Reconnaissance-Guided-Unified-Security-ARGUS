---
id: aero_satcom
technology: "Aero SATCOM (Inmarsat SwiftBroadband / SBB)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [5500, 5501, 5502, 9876]
  banners: ["SwiftBroadband", "SBB", "Inmarsat", "Cobham AVIATOR", "Honeywell MCS", "Satcom Direct"]
  markers: ["SBB", "SwiftBroadband", "inmarsat-aero", "AVIATOR", "HGA", "satcom-aero"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p 5500,5501,5502,9876 --script banner,http-title {host}", safety: safe, note: "Banner grab on SATCOM terminal management interface — identify vendor/firmware." }
  - { cmd: "curl -sk http://{host}:5500/config/status | python3 -m json.tool", safety: safe, note: "Probe SATCOM SDU management API for unauthenticated status/config disclosure." }
  - { cmd: "nmap -Pn -sT -p 5500-5510 --script http-auth-finder,http-methods {host}", safety: safe, note: "Enumerate SATCOM terminal HTTP management — check for missing authentication." }
references: ["CVE-2019-9527", "CVE-2019-9529", "CVE-2019-9532", "Pen Test Partners Research 2019", "IMO MSC.428(98)"]
mitre: "T1190 / T0856"
---
# Aero SATCOM — Inmarsat SwiftBroadband (SBB)

Aeronautical SATCOM provides broadband connectivity to commercial and business aircraft over the Inmarsat I-4 geostationary satellite network. **SwiftBroadband (SBB)** is the dominant service, providing up to 432 kbps (Classic Aero) or multi-megabit (SB-S, SwiftBroadband-Safety) IP connectivity for cockpit datalink (CPDLC, ADS-C), cabin Wi-Fi, and airline operational communications. The aircraft-side hardware is the **Satellite Data Unit (SDU)** (Cobham AVIATOR, Honeywell MCS-series, Collins HGA-series) which connects to a High Gain Antenna (HGA) and presents an IP interface to the aircraft network via Ethernet. Ground-side, Inmarsat's Satellite Access Station (SAS) provides internet connectivity through the Core Network.

**Why it matters.** Pen Test Partners (2019) disclosed critical vulnerabilities in multiple SDU implementations — Cobham AVIATOR 200/300/700, Honeywell MCS 4200/7200, Collins Aerospace HGA-7001 — including unauthenticated configuration interfaces, hardcoded credentials, remote code execution vulnerabilities, and unencrypted management channels. An attacker who compromises the SDU can: (1) intercept all aircraft IP traffic (CPDLC, ADS-C, airline ops, passenger data), (2) shut down SATCOM connectivity (impacting safety services), (3) pivot to the aircraft IP network if the SDU is improperly segmented, or (4) manipulate ADS-C position reporting. CVE-2019-9527 through CVE-2019-9532 cover the Cobham AVIATOR family specifically.

**Safe-first testing approach.** Ground-based assessment of SATCOM terminals should be conducted in a lab with the SDU powered and configured but not connected to live Inmarsat satellites (use a satellite simulator or disable RF transmission). Connect via the SDU's Ethernet management port and perform HTTP/HTTPS service enumeration. Check for: unauthenticated web management, default credentials (vendor-specific, documented in maintenance manuals), exposed diagnostic/debug APIs, and unencrypted configuration channels. Review firmware version against vendor security bulletins. **Do not interact with live satellite links or attempt to access the Inmarsat Core Network** — this constitutes unauthorized use of a licensed satellite service. Do not modify SDU configuration on any airworthy aircraft without airline authorization.

**Key risks and remediation.** Primary risks: unauthenticated SDU web management (replace with certificate-based mutual auth), hardcoded credentials in firmware (require vendor firmware updates), plaintext SATCOM management traffic (enforce TLS 1.2+ on all management channels), and missing network segmentation between the SDU Ethernet interface and avionics networks (enforce firewall with deny-all-except-required rules). Airlines should configure SDUs with minimum necessary IP routing — the SDU should not have routes to avionics VLANs. Follow Inmarsat's SBB Security Guidelines and map all aircraft IP network addresses for anomaly detection.
