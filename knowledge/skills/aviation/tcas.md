---
id: tcas
technology: "TCAS (Traffic Collision Avoidance System / ACAS II)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: critical
life_safety: true
match:
  ports: []
  banners: ["TCAS", "ACAS", "ACAS II", "RA", "Resolution Advisory", "Honeywell TCAS"]
  markers: ["TCAS", "ACAS", "intruder", "RA advisory", "Mode S"]
quick_wins:
  - { cmd: "dump1090-fa --net --quiet 2>/dev/null | grep -i 'tcas\\|ra\\|acas' | head -40", safety: safe, note: "Passive ADS-B/Mode-S receive — observe TCAS coordination frames (DF16) read-only." }
  - { cmd: "python3 -c \"import pyModeS as pms; msg='{df16_frame}'; print('Alt:', pms.altcode(msg), 'SL:', pms.tcas.sensitivity_level(msg))\"", safety: safe, note: "Offline decode of DF16 TCAS coordination message — extract sensitivity level, altitude encoding." }
references: ["CVE-2019-17558", "ICAO Annex 10 Vol IV", "RTCA DO-185B", "EUROCAE ED-143", "Schafer et al. NDSS 2023"]
mitre: "T0856 / ICS T0840"
---
# TCAS — Traffic Collision Avoidance System (ACAS II)

TCAS (Traffic Collision Avoidance System), mandated globally as ACAS II (Airborne Collision Avoidance System), is the onboard safety system that detects nearby aircraft via **Mode-S transponder interrogations** on 1030 MHz (uplink) and 1090 MHz (downlink), computes collision threats, and issues **Resolution Advisories (RAs)** directing pilots to climb or descend. TCAS II Version 7.1 coordinates RAs between two aircraft using **TCAS/ACAS coordination messages (DF16)** transmitted on 1090 MHz — one aircraft tells the other which maneuver it will perform so they maneuver in complementary directions. RAs are mandatory — flight crews are trained to follow them immediately, overriding ATC instructions.

**Why it matters.** TCAS's mandatory RA compliance makes it a high-value target. A 2023 research paper (Schafer et al., NDSS 2023) demonstrated that **ghost aircraft injection via ADS-B spoofing** can trigger false TCAS RAs in real aircraft, commanding real crews to maneuver based on phantom threats. The attack requires only a Software Defined Radio (SDR) capable of transmitting 1090 MHz ADS-B frames — tools like HackRF and a directional antenna can generate convincing ghost traffic. Ghost RAs can also be triggered by injecting fake Mode-S replies on 1090 MHz to a TCAS interrogation. Both attacks require proximity to the target aircraft but are demonstrably feasible at airport perimeters.

**Safe-first testing approach.** Passive receive-only work is safe: use dump1090-fa to capture DF16 TCAS coordination frames and pyModeS to decode them offline — this reveals TCAS sensitivity levels, intruder tracking, and RA logic without any transmission. For ground-system assessments (TCAS simulator software used for training, TCAS emulators in airline/ATC simulators), treat them as standard embedded Linux applications: probe for unauthenticated management interfaces, outdated software stacks, and unsanitized input in DF16 frame parsers. **Never transmit Mode-S or ADS-B signals to test TCAS** — doing so on or near an aerodrome is a criminal offense and a direct life-safety threat to aircraft in approach or departure phases.

**Key risks and remediation.** TCAS has no cryptographic authentication — the vulnerability is fundamental to the 1090 MHz protocol stack. Near-term mitigations include: multilateration (MLAT) cross-validation of ADS-B tracks at ground level to detect ghost injection, ATC alerting when TCAS RAs are observed on radar without corresponding traffic, and aircraft manufacturer guidance to flight crews about abnormal RA sequences. Long-term, ACAS X (the ICAO-approved next-generation standard) incorporates more robust track management and will eventually support authenticated surveillance inputs from ADS-B+. Airlines and regulators should also ensure TCAS software is maintained at the latest certified version to address known DF16 processing defects.
