---
id: nmea_maritime
technology: "Maritime NMEA-over-IP"
domain: OT
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [10110]
  banners: ["$GPGGA", "$GPRMC", "$GPVTG", "$AIVDM", "$AIVDO", "$GPGLL", "$AITXT"]
  markers: ["$GP", "$AI", "$HC", "$II", "$IN"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p10110 --script banner {host}", safety: safe, note: "Grab raw NMEA sentence stream — identifies talker IDs ($GP*, $AI*, $HC*) and sentence types without writing any data." }
  - { cmd: "python3 -c \"import socket,time; s=socket.socket(); s.connect(('{host}',10110)); s.settimeout(5);\n[print(s.recv(4096).decode(errors='replace')) for _ in range(10)]\"", safety: safe, note: "Passive read-only capture of live NMEA 0183 stream — GPS position, heading, AIS traffic. No state change." }
  - { cmd: "nmap -Pn -sU -p10110 {host}", safety: safe, note: "Check for UDP NMEA multicast or unicast feed (some AIS multiplexers also use UDP on 10110)." }
  - { cmd: "<inject crafted $GPRMC or $GPGGA sentence with spoofed lat/lon/COG/SOG via TCP write to {host}:10110>", safety: disruptive, note: "GATED — writes fabricated GPS fix to the vessel's navigation bus; downstream chart plotters, autopilot, and ECDIS may act on spoofed position. Requires explicit authorization and a human safety gate." }
references: ["CVE-2021-45114", "CVE-2022-26892", "ICSA-22-172-01", "ICSMA-22-202-01"]
mitre: "T0830 / ICS T0839"
---
# Maritime NMEA-over-IP

NMEA 0183 is the dominant sentence-based serial protocol for marine navigation instruments —
GPS receivers, AIS transponders, gyrocompasses, depth sounders, and autopilots all speak it.
When bridged to IP networks (multiplexers, ship LANs, VSAT uplinks) the stream is typically
served raw on **10110/tcp or /udp** with **no authentication and no encryption**. Sentences are
ASCII lines beginning with a talker/sentence prefix: `$GPGGA` (GPS fix), `$GPRMC` (recommended
minimum), `$GPVTG` (course/speed over ground), `$AIVDM`/`$AIVDO` (AIS decoded), `$HCHDG`
(gyrocompass heading). Any host that can reach the port receives the full navigation picture
in real time — position, speed, heading, and surrounding vessel traffic.

**Safety-of-life scope.** Navigation data feeds ECDIS (electronic chart display), autopilot
steering, collision-avoidance (ARPA/AIS), and sometimes dynamic-positioning systems on offshore
vessels. Disruption, spoofing, or injection is not an availability issue — it is a potential
grounding, collision, or man-overboard event. This asset is therefore flagged `life_safety: true`.
Treat every accessible NMEA endpoint aboard a vessel underway as a safety-critical system.

**Safe-first testing.** Begin with a passive banner grab or a short-lived read-only socket
capture. A five-second socket read reveals talker IDs, sentence types, and update rates without
altering any state. Enumerate whether the feed is TCP unicast, UDP unicast, or UDP multicast
(some multiplexers — Yacht Devices, Actisense, Digital Yacht — use 10110 UDP multicast on
224.0.0.1). Document sentence types and cross-check GPS accuracy fields (fix quality, HDOP,
satellite count) for anomalies that indicate an already-degraded or spoofed feed. **Never**
write to the port or inject sentences without scoped, written authorization, a vessel-at-berth
precondition, and a human gate — even a single `$GPRMC` with a fabricated position may be
acted upon by a connected autopilot within seconds.

**Remediation.** Isolate the NMEA multiplexer on a dedicated OT VLAN with no external
reachability; apply firewall ACLs so only authorized navigation workstations receive the
10110 feed; where the multiplexer supports it enable allowlist-based client filtering; for
VSAT-connected vessels restrict NMEA exposure to the vessel-side LAN only. Transition to
NMEA 2000 (CAN-bus, signed-PGN) or NMEA OneNet (IEC 61162-450) with authentication where
equipment supports it. Map findings against USCG Navigation Center AIS security advisories
and BIMCO cyber-security guidance rather than relying on CVSS scores alone, which do not
capture maritime collision-risk impact.
