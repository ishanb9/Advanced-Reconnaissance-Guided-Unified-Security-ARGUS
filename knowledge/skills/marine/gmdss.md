---
id: gmdss
technology: "GMDSS (Global Maritime Distress and Safety System)"
domain: OT
category: marine
transport: rf
safety_class: safe
severity: high
life_safety: true
match:
  ports: [4045]
  banners: ["GMDSS", "DSC", "NAVTEX", "Inmarsat-C", "EPIRB", "SART", "MF/HF DSC", "SAILOR", "Furuno FS"]
  markers: ["dsc-controller", "navtex-rcvr", "inmarsat-c", "sailor-6300", "furuno-fs"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p4045 --script banner {host}", safety: safe, note: "Enumerate GMDSS controller on NAVTEX/DSC management port 4045 — identify SAILOR/Furuno/JRC model and firmware version from banner. Read-only." }
  - { cmd: "curl -sk http://{host}:4045/ 2>/dev/null | grep -iE 'GMDSS|DSC|NAVTEX|SAILOR|FURUNO|EPIRB|distress' | head -20", safety: safe, note: "Fingerprint GMDSS controller web UI on port 4045 for vendor (Furuno FS-series, JRC JSS-series, Cobham SAILOR) and model." }
  - { cmd: "nmap -Pn -p4045 --script http-title,http-auth-finder {host}", safety: safe, note: "Check for unauthenticated GMDSS management access on proprietary port — default credentials documented for Furuno FS-series (admin/1234), SAILOR 6300 (admin/admin), JRC JSS-series." }
  - { cmd: "<transmit false DSC distress alert, trigger EPIRB, or disable GMDSS watch-keeping receiver via management interface>", safety: disruptive, note: "GATED — false distress alerts trigger SAR response and are a criminal offence under SOLAS and national maritime law; disabling GMDSS removes mandatory distress watch. Requires explicit authorization under controlled test conditions." }
references: ["SOLAS Chapter IV", "IMO Resolution A.801(19)", "ITU Radio Regulations Appendix 15", "USCG MSIB 04-19", "IEC 61097 series"]
mitre: "T0814 / ICS T0814"
---
# GMDSS (Global Maritime Distress and Safety System)

GMDSS is an IMO/ITU-mandated distress and safety communication framework under SOLAS Chapter IV,
replacing the legacy Morse code watch and manual distress procedures. It integrates multiple radio
technologies: **MF/HF DSC** (Digital Selective Calling, ITU Appendix 15) on 2187.5 kHz / 8414.5 kHz,
**VHF DSC** on channel 70 (156.525 MHz), **Inmarsat-C** satellite messaging for distress alerts,
**NAVTEX** (518 kHz) for broadcast navigational warnings and weather, **EPIRBs** (406 MHz
satellite beacons), and **SARTs** (9 GHz radar transponders). Aboard ship, a GMDSS controller
(Furuno FS-series, JRC JSS-series, Cobham SAILOR 6300 MF/HF) manages all these elements through
a unified interface that increasingly exposes a web management port (HTTP/HTTPS) for configuration
and remote maintenance.

**Safety-of-life scope.** GMDSS is the vessel's sole mandatory distress communication system.
A successfully compromised GMDSS controller can be used to: (1) transmit false DSC distress
alerts that trigger Search and Rescue (SAR) responses — a criminal offence wasting rescue
resources; (2) disable the GMDSS watch-keeping receiver, removing the vessel's ability to receive
distress alerts from nearby ships or urgent navigational warnings (URGENCY, SAFETY messages);
(3) delete or corrupt voyage-critical NAVTEX messages such as mine warnings or traffic separation
scheme updates. This is `life_safety: true`. The GMDSS installation must also remain independent
of the broadband VSAT link — using a broadband link as the sole GMDSS path is a SOLAS violation.

**Safe-first testing.** Enumerate the GMDSS management web interface passively — version strings,
authentication mechanisms, and exposed configuration pages. Cross-reference the identified vendor
and firmware against known default credentials (Furuno FS-5070 default: admin/1234; SAILOR
6300 default: admin/admin; JRC JSS-series: varies). Verify whether the management port is
reachable from crew network or VSAT segment — it must be isolated. **Never** trigger a DSC
distress alert, activate an EPIRB test signal outside designated test modes, or modify VHF/MF/HF
operating frequencies — any transmission on distress frequencies is monitored by coast guard
stations globally and may trigger SAR activation regardless of intent.

**Remediation.** Change all default management credentials; restrict GMDSS controller web
management to a dedicated safety LAN with no general crew or VSAT access; keep GMDSS
infrastructure (MF/HF radios, Inmarsat-C terminal, NAVTEX receiver) physically separate from
the broadband satcom system; ensure EPIRB registration is current in the national MMSI database
(NOAA, MCA); apply vendor firmware updates during scheduled port maintenance; and verify GMDSS
functionality through the required annual radio survey under SOLAS Chapter IV. Map findings to
ITU Radio Regulations and IEC 61097 series standards.
