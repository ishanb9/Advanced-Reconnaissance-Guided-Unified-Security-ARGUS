---
id: modes_transponder
technology: "Mode-S Transponder (Secondary Surveillance Radar)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: ["Mode-S", "SSR", "transponder", "squawk", "DF11", "DF17", "DF20", "DF21"]
  markers: ["Mode-S", "SSR", "ATC radar", "transponder", "ICAO24"]
quick_wins:
  - { cmd: "dump1090-fa --net --only-addr --quiet 2>/dev/null | sort -u | head -50", safety: safe, note: "Passive capture — enumerate unique ICAO 24-bit addresses of all Mode-S transponders in range. Read-only." }
  - { cmd: "python3 -c \"import pyModeS as pms; df=pms.df('{msg}'); print('DF:', df, 'ICAO:', pms.icao('{msg}'), 'Alt:', pms.altcode('{msg}'))\"", safety: safe, note: "Offline decode of Mode-S frame — extract downlink format, ICAO address, altitude encoding." }
  - { cmd: "python3 -c \"import pyModeS as pms; msg='{bds_frame}'; print(pms.bds.infer(msg), pms.commb.selected_altitude(msg))\"", safety: safe, note: "Decode Mode-S Comm-B data selector (BDS) fields — extract FMS selected altitude, vertical rate, FMS target. Offline." }
references: ["ICAO Annex 10 Vol III", "RTCA DO-181F", "FAA Order 6365.31", "EUROCAE ED-112B"]
mitre: "T0856 / ICS T0840"
---
# Mode-S Transponder — Secondary Surveillance Radar

Mode-S (Mode Select) is the globally mandated secondary surveillance radar (SSR) transponder standard that allows ATC ground radars to selectively interrogate individual aircraft on **1030 MHz**, receiving replies on **1090 MHz**. Unlike older Mode-A/C transponders, Mode-S assigns each aircraft a unique **24-bit ICAO address** (hex code), enabling selective interrogation. Mode-S supports multiple downlink formats (DFs) and uplink formats (UFs): DF17 carries ADS-B Extended Squitter (position, velocity, callsign); DF20/21 carry Comm-B messages (BDS registers) with richer data including selected FMS altitude, target heading, autopilot modes, and meteorological data; DF11 is all-call reply.

**Why it matters.** Mode-S BDS (Comm-B Data Selector) registers expose a surprisingly rich picture of aircraft systems state: BDS 4,0 contains selected altitude and autopilot mode; BDS 5,0 contains track angle and roll; BDS 6,0 contains magnetic heading, IAS, Mach, and vertical rate; BDS 4,4 contains meteorological data. This constitutes a passive intelligence feed about every aircraft's autopilot state and FMS selections — valuable for targeting specific aircraft or operations. More critically, Mode-S interrogation/reply has **no authentication**: an attacker with 1030 MHz interrogation capability can elicit replies from specific ICAO addresses, map transponder capabilities, and fingerprint avionics vendors from DF reply characteristics. Suppression attacks (wideband 1090 MHz jamming or fruit injection) can prevent ATC from tracking specific aircraft.

**Safe-first testing approach.** Passive receive is entirely safe and legal. Use dump1090-fa or a commercial Mode-S receiver to capture DF17/DF20/DF21 frames; decode offline with pyModeS to extract all BDS register values, ICAO addresses, and transponder capabilities. For ground-system assessment (ATC radar decoder software, SSR data fusion systems), focus on the software stack: fuzz BDS frame parsers with malformed Comm-B payloads, check for unauthenticated management interfaces on the radar processor, and review data integrity controls on the Mode-S data feed between radar head and ATCS display system. **Never transmit on 1030 or 1090 MHz** — these are protected aeronautical frequencies; unlicensed transmission is illegal and constitutes an immediate ATC surveillance threat.

**Key risks and remediation.** Key risks include: passive intelligence collection via BDS register decoding (no practical mitigation within current standards), ATC surveillance disruption via 1090 MHz fruit injection (requires RF domain awareness and anomaly detection at radar receivers), and SSR software vulnerabilities in ATC data fusion systems (patch cycles and input validation). Long-term, the aviation community is moving toward authenticated surveillance with ADS-B+ (RTCA DO-385) and Mode-5 IFF-derived approaches for military. Civil ATC operators should monitor for anomalous Mode-S reply rates, ICAO24 collisions, and frame format deviations indicative of spoofed transponders.
