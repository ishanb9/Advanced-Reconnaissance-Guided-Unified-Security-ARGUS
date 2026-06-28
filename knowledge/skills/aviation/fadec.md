---
id: fadec
technology: "FADEC (Full Authority Digital Engine Control)"
domain: OT
category: aviation
transport: arinc
safety_class: safe
severity: critical
life_safety: true
match:
  ports: []
  banners: ["FADEC", "EEC", "ECU", "engine controller", "DECU", "EECU"]
  markers: ["FADEC", "EEC", "ARINC429-engine", "N1-control", "fuel-metering"]
quick_wins:
  - { cmd: "python3 -c \"import arinc429; bus=arinc429.Bus('{device}'); labels=[0xE5,0xE6,0xE7,0xE8]; [print(hex(l), bus.read_label(l)) for l in labels]\"", safety: safe, note: "Read ARINC 429 engine parameter labels (N1, N2, EGT, fuel flow) from FADEC bus — passive read-only." }
  - { cmd: "python3 -c \"import arinc429; w=arinc429.Bus('{dev}').read_label(0xE5); print('N1:', arinc429.bnr_value(w, 11, 0, 199.99), '%')\"", safety: safe, note: "Decode N1 fan speed (label 0xE5 BNR) from ARINC 429 capture — offline calculation, no write." }
references: ["DO-178C Level A", "DO-254 Level A", "FAA AC 33.28-3", "ARP4761", "SAE ARP4754A"]
mitre: "ICS T0800 / T0856 / T0835"
---
# FADEC — Full Authority Digital Engine Control

FADEC (Full Authority Digital Engine Control) is the embedded flight-safety-critical computer that has complete authority over engine fuel metering, variable geometry actuation, bleed air valves, and engine starting — replacing all manual engine controls. FADEC systems (GE FADEC, Rolls-Royce EEC, Pratt & Whitney EECU, CFM FADEC on LEAP and CFM56 engines) run **DO-178C Level A** certified software (the highest criticality level — zero tolerated failure rate) and communicate via **ARINC 429** with the flight management system, autothrottle, and cockpit displays. Modern FADEC units include dual-redundant lanes with cross-channel monitoring; neither lane can be overridden manually. Maintenance access uses **ARINC 615A** data loaders for software updates and BITE (Built-In Test Equipment) data download.

**Why it matters.** FADEC controls engine thrust directly — a compromised FADEC that commands incorrect fuel flow can cause engine over-temperature (EGT exceedance), surge, flameout, or uncontained failure. Attack vectors are not trivial but exist: (1) **supply chain and maintenance loader** — ARINC 615A software loads delivered via corrupted maintenance laptop or media can replace FADEC software with a modified image; (2) **ARINC 429 input manipulation** — FADEC receives thrust lever position, altitude, and airspeed from cockpit and air data systems via ARINC 429; a compromised upstream LRU (ADC, FMC) could feed false inputs to the FADEC that trigger incorrect thrust commands; (3) **BITE data exfiltration** — maintenance BITE downloads contain detailed engine health data (temperatures, pressures, vibration signatures) that constitute sensitive operational intelligence about an airline's fleet condition.

**Safe-first testing approach.** FADEC assessment is exclusively a **laboratory and maintenance environment** activity — no assessment work on an installed, operational engine. In a controlled lab: connect a certified ARINC 429 analyzer to the FADEC bus (read-only tap, no injection) and monitor all label values; download BITE data via ARINC 615A using the approved maintenance data loader; review software part numbers against the Aircraft Software Configuration List (ASCL). If evaluating the software supply chain, review the software loader workstation for: unprotected USB ports, unsigned update packages, network connectivity during loading operations, and inadequate media integrity verification. **Never inject ARINC 429 words onto a FADEC bus** — this constitutes unauthorized interference with a DO-178C Level A safety system and can cause engine damage or catastrophic failure.

**Key risks and remediation.** Primary risks: (1) maintenance loader workstation compromise (harden with endpoint protection, enforce signed software packages, air-gap from internet during loading); (2) upstream ARINC 429 LRU compromise feeding false data to FADEC (FADEC internal plausibility checks are the primary defense — validate these during certification testing); (3) BITE data sensitivity (treat engine health data as proprietary/sensitive, encrypt BITE downloads in transit and at rest). Regulatory: all FADEC software changes require FAA/EASA STC or Type Certificate amendment — the regulatory process itself is a supply chain security control. Airlines should maintain strict software configuration management and verify FADEC software part numbers after every maintenance event.
