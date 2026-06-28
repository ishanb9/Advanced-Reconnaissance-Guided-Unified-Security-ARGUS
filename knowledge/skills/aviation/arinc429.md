---
id: arinc429
technology: "ARINC 429 (Avionics Digital Information Transfer System)"
domain: OT
category: aviation
transport: arinc
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: ["ARINC 429", "DITS", "ARINC429", "label 377"]
  markers: ["ARINC429", "DITS", "avionics bus", "label word"]
quick_wins:
  - { cmd: "python3 -c \"import arinc429; bus=arinc429.Bus('{device}'); frames=bus.read_all(); [print(f) for f in frames]\"", safety: safe, note: "Read-only bus monitor using Python ARINC 429 library — captures label words without writing." }
  - { cmd: "python3 -c \"import arinc429; w=0x3A02FF80; print(arinc429.decode_label(w), arinc429.get_ssm(w), arinc429.get_data(w))\"", safety: safe, note: "Offline decode of ARINC 429 word — extract label, SSM, BNR/BCD data value. No bus interaction." }
references: ["DO-178C", "ARINC 429 Part 1-17", "FAA AC 25.1309", "RTCA DO-254"]
mitre: "ICS T0800 / T0856"
---
# ARINC 429 — Avionics Digital Information Transfer System (DITS)

ARINC 429 is the dominant avionics serial bus in commercial aviation, used in nearly every commercial aircraft manufactured since the 1970s. It operates as a **unidirectional, point-to-multi-point bus** at 12.5 kbps (low speed) or 100 kbps (high speed) using a twisted-pair differential signal. Each 32-bit word carries an 8-bit label (parameter type), a 2-bit Source/Destination Matrix (SDM) or Sign/Status Matrix (SSM), 19 bits of data, a parity bit, and status. Typical bus users include flight management computers (FMC), inertial reference systems (IRS), air data computers (ADC), autopilot computers, and engine FADEC units.

**Why it matters.** ARINC 429's unidirectional topology is a safety feature — a transmitter bus cannot receive responses, making bus-borne injection by a passive sniffer impossible by design. However, attack vectors exist at: (1) **LRU internal interfaces** — firmware in an FMC or ADC that processes ARINC 429 inputs can be compromised via a maintenance loader (ARINC 615A, ARINC 827 USB); (2) **ARINC 429-to-IP bridges** — many modern avionics gateway boxes translate ARINC 429 to Ethernet/UDP for health monitoring, creating a bidirectional path; (3) **supply chain** — counterfeit or tampered LRUs can transmit malformed label words that cause downstream ARINC 429 receivers to miscalculate safety-critical values (altitude, airspeed, heading). Label 277 (GPS position) and label 203 (altitude) are particularly sensitive.

**Safe-first testing approach.** Assessment must be conducted in a **lab or Iron Bird** environment only — never on a live aircraft. Use a certified ARINC 429 bus analyzer (AIM, Astronics, DDC) or a hardware interface card with vendor SDK to passively monitor all labels on a bus. Decode captured words offline: identify all active labels, verify SSM/parity validity, and check for label collisions (two transmitters on the same bus violating the standard). Review ARINC 429-to-IP gateway configurations for unauthenticated read/write access to bus labels. **Do not inject words onto a live avionics bus** — writing to a bus shared with flight computers can corrupt navigation, autopilot, or thrust data, creating an immediate safety hazard.

**Key risks and remediation.** Key risks include counterfeit LRUs broadcasting malformed label words, unauthorized access to ARINC 429-to-Ethernet gateways, and inadequate validation of inbound 429 words in receiving LRU firmware. Remediation: enforce DO-178C/DO-254 supply chain traceability for all LRUs, segment ARINC 429-to-IP gateways behind authenticated firewalls with one-way (receive-only) data flows, conduct fuzz testing of LRU firmware against malformed 429 word sequences (bad parity, invalid SSM codes, out-of-range BNR values), and maintain configuration baselines of all installed LRU part numbers and software versions.
