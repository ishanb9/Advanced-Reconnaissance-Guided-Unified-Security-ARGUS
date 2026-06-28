---
id: cpdlc
technology: "CPDLC (Controller-Pilot Data Link Communications)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: critical
life_safety: true
match:
  ports: []
  banners: ["CPDLC", "ATN", "ACARS/CPDLC", "FANS-1/A", "ATN B1"]
  markers: ["CPDLC", "FANS-1", "ATN-B1", "ADS-C", "LOGON"]
quick_wins:
  - { cmd: "acarsdec -r 0 -o 4 129.125 2>/dev/null | python3 -c \"import sys,json; [print(l) for l in sys.stdin if 'CPDLC' in l or '/DM' in l or '/UM' in l]\"", safety: safe, note: "Passive SDR + grep for CPDLC uplink/downlink messages on VHF ACARS subnetwork — read-only." }
  - { cmd: "nmap -Pn -sT -p 5001 --script banner,http-title {host}", safety: safe, note: "Banner grab on ATN-B2 ground system port — identify CPDLC ground station software. Read-only." }
references: ["CVE-2016-2183", "ICAO Doc 9694 Part II", "RTCA DO-258A", "EUROCAE ED-100A", "FAA SAFO 15010"]
mitre: "T0856 / ICS T0830"
---
# CPDLC — Controller-Pilot Data Link Communications

CPDLC (Controller-Pilot Data Link Communications) is a text-based ATC datalink system that allows air traffic controllers to send clearances, instructions, and information to flight crews digitally, replacing voice radio for routine communications. It operates over multiple subnetworks: **VHF ACARS** (VHF Data Link Mode 2 / VDL-2 at 136.9 MHz), **Inmarsat SATCOM** (for oceanic/remote areas), and the evolving **ATN B1/B2** (Aeronautical Telecommunication Network). Messages follow ICAO Doc 9694 format — uplinks (UM codes, controller to pilot) and downlinks (DM codes, pilot to controller) with structured free-text elements.

**Why it matters.** CPDLC messages carry safety-critical ATC clearances: altitude changes, route amendments, speed restrictions, and frequency changes. The protocol has **no cryptographic authentication** on legacy FANS-1/A implementations — messages are transported over ACARS which itself is unauthenticated plaintext. A threat actor who can inject ACARS frames (via SDR transmitter) can craft fake CPDLC uplinks that appear to come from ATC. Research (Hugo Teso, 2013; subsequent SEC research) demonstrated this attack vector in ground simulators. Even on VDL-2 (which has AVLC framing with ICAO addresses), the ICAO address is unverified. ATN B2 adds ACARS Message Security (AMS / ARINC 823) with PKI, but legacy FANS-1/A remains widely deployed.

**Safe-first testing approach.** Passive monitoring is the only safe over-the-air technique: use acarsdec or JAERO to capture VHF ACARS/VDL-2 frames and filter for CPDLC message type codes (DM/UM prefixes, ATN addresses). For ground-system assessment, focus on the **ATSU (Air Traffic Services Unit) server** — probe for unauthenticated TCP access on ATN ground stack ports, test for replay attack acceptance (duplicate sequence numbers), and review TLS certificate validation in CPDLC gateway software. **Never transmit on aviation frequencies or attempt to inject CPDLC messages** — doing so constitutes interference with ATC communications, a felony in most jurisdictions, and a direct flight safety threat.

**Key risks and remediation.** Legacy FANS-1/A is vulnerable to message injection and replay due to absent authentication. ATN B2 with AMS (ARINC 823 Part 1) provides RSA/ECDSA message authentication — airlines and ANSPs should migrate to ATN B2 and enforce AMS on all CPDLC sessions. Ground-side ATSU systems should enforce sequence number validation, timeout stale logon sessions, and rate-limit logon attempts. Flight crew training should include awareness of CPDLC spoofing indicators (unexpected clearances, unusual formatting, absence of expected ATC callsign). ICAO Annex 10 amendments are driving cryptographic protection mandates for new CPDLC implementations.
