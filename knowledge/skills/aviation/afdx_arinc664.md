---
id: afdx_arinc664
technology: "AFDX / ARINC 664 (Avionics Full-Duplex Switched Ethernet)"
domain: OT
category: aviation
transport: arinc
safety_class: safe
severity: critical
life_safety: true
match:
  ports: []
  banners: ["AFDX", "ARINC 664", "VL", "virtual link", "End System"]
  markers: ["AFDX", "ARINC664", "avionics ethernet", "A429 over AFDX"]
quick_wins:
  - { cmd: "tcpdump -i {iface} -n -e ether proto 0x8100 -w /tmp/afdx_capture.pcap", safety: safe, note: "Passive capture of AFDX traffic on 802.1Q VLAN — read-only; do NOT inject frames." }
  - { cmd: "tshark -r /tmp/afdx_capture.pcap -T json -e afdx.vl_id -e afdx.sequence_number -e afdx.payload 2>/dev/null", safety: safe, note: "Offline decode of captured PCAP — extract Virtual Link IDs, sequence numbers, payloads. No live interaction." }
  - { cmd: "nmap -Pn -sn --script broadcast-dhcp-discover {host}/24 -e {iface}", safety: safe, note: "Passive network discovery on AFDX segment — identify End Systems without sending avionics-layer traffic." }
references: ["CVE-2020-9059", "DO-178C", "ARINC 664 Part 7", "EASA AMC 20-42"]
mitre: "T0856 / ICS T0800"
---
# AFDX / ARINC 664 — Avionics Full-Duplex Switched Ethernet

AFDX (Avionics Full-Duplex Switched Ethernet), standardized as ARINC 664 Part 7, is the deterministic avionics Ethernet network used in Airbus A380, A350, Boeing 787, and other modern commercial aircraft. It carries flight-critical data between Line-Replaceable Units (LRUs): flight management computers, flight control computers, engine control units, and sensors. AFDX uses standard 100BASE-TX Ethernet hardware but imposes strict determinism through **Virtual Links (VL)** — unidirectional, bandwidth-limited logical channels with fixed source/destination pairs. Each End System (ES) enforces a Bandwidth Allocation Gap (BAG) to prevent one LRU from flooding the network.

**Why it matters.** AFDX carries flight-safety-critical data — flight control surface positions, engine thrust commands, fuel quantity, navigation data. A compromised End System on an AFDX network (e.g., via a maintenance laptop or IFE-to-avionics boundary breach) could: (1) inject malformed frames that crash avionics software (DO-178C safety failures), (2) replay frames to spoof sensor readings, (3) violate BAG constraints to cause network congestion and drop safety-critical messages, or (4) enumerate VL topology to map the avionics architecture for further exploitation. The segregation between IFE and AFDX is a primary architecture control — breaches of this boundary have been cited in Boeing 787 and Airbus connectivity advisories.

**Safe-first testing approach.** AFDX assessment should be conducted only in a **laboratory or maintenance environment** (Iron Bird, Systems Integration Lab), never on a live aircraft. Use a passive tap or SPAN port on the AFDX switch to capture traffic — decode offline with Wireshark (AFDX dissector plugin available) or tshark. Enumerate Virtual Link IDs, BAG values, and max frame sizes to map the network topology. Review End System configuration files (XML/AFDX partitioning tables) for VL misconfiguration (overlapping IDs, missing integrity period checks). **Never inject frames on a live AFDX network** — this constitutes unauthorized interference with aircraft systems and can trigger safety failures.

**Key risks and remediation.** Key attack surfaces include: (1) the IFE-to-avionics gateway — validate one-way data flows with hardware data diodes where required; (2) maintenance laptop interfaces (ARINC 615A loader ports that share the AFDX backbone); (3) End System firmware — update path should follow DO-178C change impact analysis. Operators should enforce strict VLAN isolation, monitor for BAG violations, and validate ES partitioning tables against certified configuration baselines.
