---
id: marine_satcom
technology: "Marine VSAT / Inmarsat / Iridium Satcom"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: []
  banners: ["VSAT", "Inmarsat", "Iridium", "KVH", "Cobham SATCOM", "Intellian", "iDirect", "SpeedCast", "Marlink"]
  markers: ["iDirect", "kvh-tracvision", "intellian", "cobham", "inmarsat-c", "fleet broadband", "fleet one"]
quick_wins:
  - { cmd: "nmap -Pn -sV --open {host} --script banner", safety: safe, note: "Full port scan with banner grab — VSAT modems (iDirect, KVH, Intellian, Cobham) expose management on vendor-specific ports; match banners against 'iDirect','KVH','Intellian','Cobham','Marlink','SpeedCast'. Read-only." }
  - { cmd: "nmap -Pn -sV --script http-title,http-auth-finder {host}", safety: safe, note: "Fingerprint all HTTP/HTTPS management interfaces for VSAT vendor and model — identify login pages to cross-reference known-default credentials (iDirect admin/admin, KVH TracVision admin/admin1234)." }
  - { cmd: "nmap -Pn -sV --script http-default-accounts --script-args http-default-accounts.fingerprintfile=fingerprints.lua {host}", safety: safe, note: "Check all discovered VSAT management web interfaces for default credentials — iDirect, KVH TracVision, and Intellian units have documented factory defaults." }
  - { cmd: "<modify VSAT modem routing, firewall ACLs, or beam configuration on {host} to expose vessel LAN to internet or redirect traffic>", safety: disruptive, note: "GATED — altering satellite link configuration can disconnect GMDSS safety communications and expose OT network segments. Requires explicit authorization." }
references: ["CVE-2020-7580", "Pen Test Partners VSAT Research 2020-2022", "BIMCO Cyber Security Guidelines", "USCG MSIB 01-20", "ITU Radio Regulations Article 51"]
mitre: "T0869 / ICS T0846"
---
# Marine VSAT / Inmarsat / Iridium Satcom

Marine satellite communications (satcom) provides the sole IP uplink for vessels at sea.
**VSAT** (Very Small Aperture Terminal) systems from vendors including iDirect (ST Engineering),
KVH Industries, Intellian, Cobham SATCOM, Marlink, and SpeedCast offer Ku/Ka-band broadband
(1–50 Mbps) managed through a belowdecks modem/router (iDirect Evolution/X series, KVH V-series)
and an above-deck stabilized antenna. **Inmarsat Fleet Broadband / FleetOne** (L-band, lower
bandwidth) and **Iridium Certus/OpenPort** (LEO, 700 kbps–1.4 Mbps) serve as backup and GMDSS
links. The belowdecks modem exposes a web management interface (typically HTTP on 8080 or HTTPS
on 8443) and often an SSH or Telnet management port. The VSAT link is typically the only path
between the vessel LAN and the ship-owner's shoreside NOC, making it both the external attack
ingress and the monitoring egress.

**Why it matters offensively.** Pen Test Partners research (2020–2022) demonstrated that KVH
TracVision, Cobham Sailor, Intellian, and iDirect modems are frequently reachable with default
factory credentials from internet-facing satellite IP addresses, which are discoverable via Shodan.
From the modem management interface, an attacker can modify internal routing to reach the vessel
OT LAN (navigation, engine monitoring), alter firewall rules, or bridge the satcom link directly
to otherwise-isolated vessel segments. A compromised VSAT link also enables man-in-the-middle
interception of all vessel IP traffic and exfiltration of OT sensor data.

**Safe-first testing.** Start with unauthenticated service enumeration: identify the modem vendor
and firmware version from HTTP banners, check for default credential exposure (documented for
all major VSAT vendors), and verify whether management interfaces are internet-reachable or
segmented behind the vessel internal network. Confirm whether GMDSS safety traffic (Inmarsat-C
or DSC) shares the same modem or is on a dedicated independent link. **Do not** alter modem
configuration, firewall ACLs, or routing tables — doing so may sever GMDSS communications,
which are mandatory distress and safety communications required by SOLAS; disrupting them
creates a life-safety hazard even if the vessel is not itself in distress.

**Remediation.** Change all default VSAT management credentials; restrict management interfaces
to a dedicated onboard management VLAN with no crew internet access; ensure GMDSS communications
use a physically separate Inmarsat-C or VHF DSC installation independent of the broadband VSAT
link; apply firmware updates per vendor schedule; enforce MFA on all shoreside NOC access to
vessel modems; segment the VSAT router so vessel OT/navigation networks are not bridged to the
satellite IP segment. Consult BIMCO Cyber Security Guidelines and Pen Test Partners maritime
satcom advisories for fleet-wide policy.
