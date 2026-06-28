---
id: adsb_1090es
technology: "ADS-B 1090ES (Automatic Dependent Surveillance-Broadcast)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: []
  markers: ["ADS-B", "1090ES", "DF17", "DF18", "squitter"]
quick_wins:
  - { cmd: "dump1090-fa --net --quiet --lat {lat} --lon {lon} 2>/dev/null & sleep 30 && kill %1", safety: safe, note: "Passive SDR capture on 1090 MHz — reads DF17/DF18 squitters; no transmission; read-only." }
  - { cmd: "python3 -c \"import pyModeS as pms; msg='8D40621D58C382D690C8AC2863A7'; print(pms.adsb.icao(msg), pms.adsb.position_with_ref(msg,52.0,4.7))\"", safety: safe, note: "Decode raw Mode-S frame — extract ICAO24, callsign, lat/lon, altitude. Offline decode only." }
  - { cmd: "gr_adsb --freq 1090e6 --sample-rate 2e6 --gain 40 --output-file /tmp/adsb.bin", safety: safe, note: "GNU Radio passive capture to file — no RF injection; purely receive." }
references: ["CVE-2019-9555", "CVE-2022-36158", "ICSA-21-257-01", "FAA AC 20-165B"]
mitre: "T0856 / ICS T0840"
---
# ADS-B 1090ES — Automatic Dependent Surveillance-Broadcast

ADS-B (1090 MHz Extended Squitter) is the primary surveillance technology mandated by FAA and EASA for most civil aircraft. Each aircraft broadcasts its ICAO 24-bit address, GPS-derived position, altitude, velocity, and callsign in cleartext on **1090 MHz** every ~0.5 seconds. Ground stations and other aircraft (TCAS) receive these transmissions; there is **no authentication, no encryption, and no source verification** in the legacy 1090ES standard.

**Why it matters offensively.** Any SDR costing under $30 (RTL-SDR) can passively receive every aircraft within ~250 NM line-of-sight. More critically, the protocol has no message authentication — a software-defined radio capable of transmitting (HackRF, USRP) can inject ghost aircraft, spoof position, or suppress real tracks. Ghost injection attacks confuse TCAS logic and can trigger Resolution Advisories (RAs) in real aircraft. Track suppression (high-power jamming of 1090 MHz) can eliminate aircraft from ATC radar displays. Both attack classes are life-safety threats.

**Safe-first testing approach.** Assessment must be **receive-only**. Use RTL-SDR + dump1090-fa/mutability or a commercial receiver (AirNav RadarBox) to collect and decode ADS-B frames passively. Offline analysis with pyModeS can decode all field types — ICAO address, position CPR pairs, velocity, emergency status — without any over-the-air transmission. **Never inject or replay ADS-B frames** — even a test transmission on 1090 MHz constitutes unauthorized use of aviation frequencies (FCC/ITU violation) and constitutes a serious safety hazard. If you are evaluating a ground-station software stack (e.g., OpenSky Network receiver, ForeFlight feed server), focus on the software attack surface: injection via spoofed JSON/SBS feeds, deserialization of malformed Mode-S frames, and privilege escalation in the decoder daemon.

**Key risks and remediation.** The FAA/ICAO are standardizing ADS-B with Authentication (ADS-B+) and LDACS; RTCA DO-385 defines a cryptographic message authentication extension. Ground-system defenders should validate ICAO24 against Mode-S correlation (secondary radar cross-check), deploy multi-lateration (MLAT) consistency checks, and alert on sudden positional jumps. Software decoders should be fuzz-tested against malformed 112-bit frames — several CVEs exist in open-source decoders (buffer overflows in C-based parsers).
