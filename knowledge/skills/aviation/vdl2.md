---
id: vdl2
technology: "VDL Mode 2 (VHF Digital Link Mode 2)"
domain: OT
category: aviation
transport: rf
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: ["VDL", "VDL-2", "VDL Mode 2", "AVLC", "CM logon", "VHF datalink"]
  markers: ["VDL2", "AVLC", "CM-logon", "subnetwork", "136.900"]
quick_wins:
  - { cmd: "rtl_fm -f 136.900M -s 48k -g 40 - 2>/dev/null | vdlm2dec -f 136.900 -A -j", safety: safe, note: "Passive SDR demodulation of VDL-2 on 136.900 MHz — decode AVLC frames, extract ICAO addresses. Read-only." }
  - { cmd: "vdlm2dec -f 136.900 -f 136.975 -A -j 2>/dev/null | python3 -c \"import sys,json; [print(json.loads(l)) for l in sys.stdin if l.strip()]\"", safety: safe, note: "Multi-frequency VDL-2 passive capture and JSON decode — aircraft address, ATN SN, message content." }
references: ["ICAO Doc 9776 (VDL Mode 2 SARPs)", "RTCA DO-224B", "EUROCAE ED-92A", "ICAO Annex 10 Vol III"]
mitre: "T0856 / ICS T0830"
---
# VDL Mode 2 — VHF Digital Link Mode 2

VDL Mode 2 (VHF Digital Link Mode 2) is the primary datalink subnetwork for **CPDLC** (controller-pilot datalink) communications in European airspace and increasingly worldwide. It operates on the VHF aeronautical band (118–136 MHz) at **31.5 kbps** using D8PSK modulation, with key operational frequencies at 136.900 MHz (Europe) and 136.975 MHz. The link layer is **AVLC (Aviation VHF Link Control)**, an HDLC derivative that provides ICAO 24-bit aircraft addressing, framing, and error detection. VDL-2 transports ACARS, ATN (Aeronautical Telecommunication Network) subnetwork-layer datagrams, and CPDLC messages. It is replacing VHF ACARS for ATC safety services because it provides higher throughput and better spectrum efficiency — but not stronger authentication.

**Why it matters.** Like VHF ACARS, VDL-2 transmits in cleartext with no cryptographic authentication. An SDR capable of D8PSK modulation (USRP, LimeSDR with appropriate software) can theoretically inject AVLC frames with spoofed source ICAO addresses, delivering fabricated CPDLC uplinks to aircraft. VDL-2 ground stations (VDL-2 radio base stations / Subnetwork Access Facilities) are IP-networked and may present network attack surfaces. Additionally, passive VDL-2 monitoring reveals all datalink traffic including ATC clearances, route amendments, weather uplinks, and airline operational messages — a comprehensive intelligence feed for any aircraft operating in VDL-2 coverage.

**Safe-first testing approach.** Passive receive is safe and straightforward: RTL-SDR + rtl_fm + vdlm2dec (open source) decodes VDL-2 frames in real time. Output includes AVLC source/destination addresses, ATN subnetwork details, and ACARS/CPDLC message content. Capture and analyse for: ICAO address patterns, message types (CM logon, X.25 PAD, ACARS type A), and ATN subnetwork structure. For ground-station assessment, treat the VDL-2 Subnetwork Access Facility as an embedded Linux telecom system: enumerate management ports, check for default credentials, review software versions against CVE databases, and probe for injection interfaces. **Never transmit on VHF aeronautical frequencies** without appropriate licensing and ATC coordination — even a test D8PSK signal on 136.900 MHz can disrupt operational CPDLC in a wide geographic area.

**Key risks and remediation.** VDL-2 ground station equipment (deployed by SITA, DFS, NATS, Airservices Australia) runs Linux-based software that may not receive timely security patches. Assess ground station management interfaces for authentication, TLS versions, and software currency. For the aviation community, the long-term fix is ACARS Message Security (AMS, ARINC 823 Part 1) layered on top of VDL-2, providing PKI-based authentication of CPDLC messages independent of the transport layer. ANSPs should also monitor for anomalous AVLC frame rates and ICAO address spoofing indicators at ground station level.
