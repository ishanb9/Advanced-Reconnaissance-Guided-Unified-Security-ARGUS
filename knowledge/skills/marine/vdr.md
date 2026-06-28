---
id: vdr
technology: "VDR / S-VDR (Voyage Data Recorder)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [4041, 4042]
  banners: ["VDR", "S-VDR", "voyage data recorder", "JRC VDR", "Furuno VR", "Danelec", "Kelvin Hughes"]
  markers: ["vdr-download", "voyage data", "danelec", "kelvin hughes", "furuno vr-"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p4041,4042 --script banner {host}", safety: safe, note: "Enumerate VDR proprietary management ports and software version — identify vendor (Furuno VR, Danelec, JRC, Kelvin Hughes) and firmware from banner. Read-only." }
  - { cmd: "curl -sk http://{host}:4041/status 2>/dev/null | head -80", safety: safe, note: "Check for unauthenticated VDR status page on proprietary port 4041 — expose recording status, capsule health, and firmware version." }
  - { cmd: "nmap -Pn -p4041,4042 --script http-title,http-auth-finder,http-methods {host}", safety: safe, note: "Enumerate VDR management interface on proprietary ports — detect default credential pages, authentication bypass, and exposed recording archives." }
  - { cmd: "<download or modify VDR archived recordings, disable recording function, or alter sensor inputs via management interface on {host}>", safety: disruptive, note: "GATED — tampering with VDR data is a maritime offence under SOLAS; disabling recording removes the accident investigation record. Requires explicit written authorization." }
references: ["IEC 61996-1", "SOLAS Reg V/20", "IMO Resolution A.861(20)", "DNV-GL VDR Cyber Advisory 2020", "CVE-2019-12840"]
mitre: "T0828 / ICS T0851"
---
# VDR / S-VDR (Voyage Data Recorder)

The Voyage Data Recorder is the maritime equivalent of an aircraft flight data recorder, mandated
by SOLAS Regulation V/20 for ships over 3,000 GT built after 2002. It continuously records a
12-parameter data set including bridge audio, VHF communications, radar imagery, ECDIS chart state,
AIS data, NMEA navigation sensors (position, heading, speed), engine orders, hull openings, fire
alarms, and acceleration. Data is stored in a capsule designed to survive post-casualty retrieval
(IMO Resolution A.861(20)). The recording system itself is typically a dedicated Windows or Linux
embedded host with a web management interface on HTTP/HTTPS and proprietary download ports
(4041-4042/tcp). Simplified-VDR (S-VDR, IEC 61996-2) for smaller vessels records fewer parameters
but uses similar network-accessible management.

**Safety-of-life scope.** While the VDR itself does not directly control navigation, tampering with
it — altering archived sensor data, disabling the recording function, or exfiltrating bridge audio —
constitutes interference with a mandatory safety system and an accident-investigation record. Under
SOLAS and many national maritime regulations, deliberate tampering is a criminal offence. Furthermore,
the VDR typically receives live NMEA feeds from the same navigation bus as the IBS; a compromised
VDR could be a pivot point into the bridge LAN. This asset is `life_safety: true`.

**Safe-first testing.** Enumerate the management web interface passively: title, authentication
method, version strings, and exposed status endpoints. Check for default OEM credentials (Furuno,
Danelec, JRC, and Kelvin Hughes all ship VDRs with documented default passwords). Verify that
download access to archived recordings requires authentication — unauthenticated access to voyage
recordings is a privacy and regulatory exposure. Confirm the recording system's network segment;
it should not be reachable from the crew internet or port network. **Do not** attempt to stop,
corrupt, or download recordings without explicit written authorization from vessel owner and
master — unauthorized access to VDR archives may violate national and international maritime law.

**Remediation.** Change default OEM management credentials; restrict port 4041-4042 and web
management to a dedicated VDR maintenance VLAN; disable remote management ports when not
performing scheduled download; log all access to the management interface; verify capsule integrity
annually per IEC 61996-1 performance standards; align access controls with flag-state requirements
and class society VDR cyber advisory guidance (e.g., DNV-GL 2020 VDR advisory).
