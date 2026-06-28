---
id: acars
technology: "ACARS (Aircraft Communications Addressing and Reporting System)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: ["ACARS", "SITA", "ARINC", "VHF-ACARS", "Hf-ACARS"]
  markers: ["ACARS", ".VHF.", "M16A", "2B3"]
quick_wins:
  - { cmd: "acarsdec -r 0 131.550 130.025 129.125 131.725 2>/dev/null", safety: safe, note: "Passive SDR capture on common VHF ACARS frequencies — decodes airline ops, ATC clearances, ATIS. Read-only." }
  - { cmd: "python3 -c \"import pyacars; msg=pyacars.decode('{raw_frame}'); print(msg)\"", safety: safe, note: "Offline decode of captured ACARS frame — extract flight number, position, engine data. No RF." }
  - { cmd: "acarsdec -r 0 -v -o 4 129.125 2>/dev/null | tee /tmp/acars_capture.json", safety: safe, note: "Verbose JSON decode of ACARS traffic for offline analysis — purely passive receive." }
references: ["CVE-2016-2183", "FAA Order 8400.13D", "ARINC 618", "ARINC 619"]
mitre: "T0856 / ICS T0830"
---
# ACARS — Aircraft Communications Addressing and Reporting System

ACARS is a digital datalink protocol used since 1978 to exchange short messages between aircraft and airline operations/maintenance centres. It operates over **VHF (118–137 MHz)**, HF, and via satellite (Inmarsat, Iridium) subnetworks. Messages carry operational data — clearances, departure/arrival times (OUT/OFF/ON/IN), engine health data (ACMS/QAR downlinks), weather, loadsheets, and ATC routing updates (OCL, DCL). All VHF ACARS is transmitted in **plaintext with no authentication**.

**Why it matters.** Anyone with an SDR (RTL-SDR) and acarsdec can passively receive all VHF ACARS within ~200 NM. Captured messages expose: (1) real-time aircraft position and fuel state, (2) engine ACMS parameters useful for pre-attack reconnaissance against a specific tail, (3) pre-departure clearances (PDC/DCL) that reveal routing and altitude, and (4) company operational security data (crew rostering, cargo manifests). More critically, unauthenticated VHF ACARS injection — possible with an SDR transmitter — can deliver fake clearances or ATC instructions that a pilot may act on. ACARS-over-SATCOM links (SwiftBroadband) add an IP layer and introduce network-layer attack vectors against the SATCOM terminal.

**Safe-first testing approach.** Restrict work to **passive monitoring and offline analysis**. Use acarsdec or JAERO (for SATCOM ACARS on L-band) to collect plaintext frames; decode with pyacars or ACARS decoders in JAERO. When assessing an airline's ACARS server (ARINC 597 / SITA OPF gateway), treat it as a plaintext UDP/TCP service and probe for unauthenticated message injection, replay attacks, and parser vulnerabilities against malformed ACARS frames. **Do not transmit on aviation VHF** — violates FCC Part 87 and ICAO Annex 10. If assessing ground-side ACARS infrastructure, look for exposed ARINC 542 MU simulator ports, cleartext airline-ops telnet consoles, and unauthenticated REST APIs wrapping ACARS gateways.

**Key risks and remediation.** ACARS lacks any cryptographic authentication by design. Airlines should implement ACARS Message Security (AMS — ARINC 823 Part 1) with PKI-based authentication for safety-critical messages (ATC datalink, PDC). Ground systems should validate message source codes against known ICAO addresses, rate-limit inbound ACARS from untrusted VHF subnetworks, and log all received ACARS for anomaly detection. Receivers running open-source decoders should be kept patched — malformed ACARS frames have triggered crashes in several decoder implementations.
