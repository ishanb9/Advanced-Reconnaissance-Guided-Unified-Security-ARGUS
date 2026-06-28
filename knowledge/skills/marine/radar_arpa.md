---
id: radar_arpa
technology: "Marine Radar / ARPA"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [4000, 4003, 7878]
  banners: ["ARPA", "radar", "JRC JMA", "Furuno FAR", "Raytheon Anschutz", "Kongsberg radar", "SIMRAD"]
  markers: ["arpa-target", "jrc-jma", "furuno-far", "nav-radar", "radar-overlay"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p4000,4003,7878,80,443,22 {host}", safety: safe, note: "Enumerate radar processor network interface — identify vendor (JRC, Furuno, Kongsberg), firmware version, and exposed management ports." }
  - { cmd: "nmap -Pn -p445 --script smb-os-discovery,smb-security-mode {host}", safety: safe, note: "Many radar processors run Windows; assess OS patch level and SMB configuration — critical for vendors using Windows-based radar signal processors." }
  - { cmd: "curl -sk http://{host}/ 2>/dev/null | grep -iE 'radar|ARPA|furuno|JRC|kongsberg|anschutz' | head -20", safety: safe, note: "Fingerprint radar processor web interface for vendor model and firmware version." }
  - { cmd: "<inject false ARPA target tracks or suppress returns via radar processor API or NMEA $RATTM injection on {host}>", safety: disruptive, note: "GATED — false ARPA targets or suppressed radar returns directly create collision risk. Requires explicit authorization and vessel at berth with all navigation secured." }
references: ["IEC 62388 (Marine Radar)", "IEC 62923-1 (ARPA)", "BIMCO Cyber Security Guidelines", "IMO MSC.192(79)", "Pen Test Partners Radar Research 2021"]
mitre: "T0830 / ICS T0839"
---
# Marine Radar / ARPA

Marine radar is the primary sensor for all-weather collision avoidance and navigation in restricted
visibility. Modern X-band (9 GHz, 3 cm) and S-band (3 GHz, 10 cm) radars from vendors including
JRC (JMA series), Furuno (FAR series), Raytheon Anschütz, Kongsberg, and Navico/Simrad process
returns through dedicated signal-processing hardware and software running on embedded Linux or
Windows. **ARPA** (Automatic Radar Plotting Aid, IEC 62923) acquires, tracks, and predicts the
motion of up to 100 radar targets, generating collision avoidance data (CPA — closest point of
approach, TCPA — time to CPA) displayed on the radar PPI and overlaid on ECDIS. The radar
processor exports tracked target data as NMEA 0183 `$RATTM` sentences (Radar-tracked target,
minimum) to the IBS and ECDIS over 10110/tcp, and increasingly exposes a network management
interface on dedicated ports (4000/tcp, 7878/tcp) or a web UI for configuration and software
updates.

**Safety-of-life scope.** ARPA target data feeds the officer of the watch's collision-avoidance
picture. False track injection — either via the radar processor API or by inserting crafted
`$RATTM` sentences into the NMEA feed — can create phantom vessels the OOW will manoeuvre to
avoid (potentially into real hazards) or suppress real targets. Radar systems are also subject
to physical-layer interference (radar jamming or spoofing by reflectors), but the network attack
surface from the processor management interface and NMEA output is the primary cyber concern.
This is `life_safety: true` and subject to IMO MSC.192(79) performance standards.

**Safe-first testing.** Enumerate the radar processor management port passively — identify vendor,
model, and firmware from HTTP banners or Nmap service probes. Check Windows OS patch level if
the processor runs Windows. Verify whether the management port is accessible from the general
vessel LAN or only from an isolated bridge LAN segment. Enumerate exposed NMEA output streams
for `$RATTM` sentence injection opportunities — these are typically on 10110/tcp with no
authentication. **Do not** attempt to interact with radar control, antenna parameters, or ARPA
track management — any active interference with radar operation during a passage constitutes a
navigational hazard. Testing must be conducted at berth with the radar in standby mode and all
navigation systems independently backed up.

**Remediation.** Apply radar processor OS and firmware patches per OEM-approved bundles; restrict
management port access to a dedicated bridge LAN VLAN; disable or firewall the NMEA 10110 output
port from unauthorized client addresses; monitor `$RATTM` sentence rates for anomalous target
counts or update rates indicating injection; and include radar system cyber checks in annual
survey inspections per IEC 62388. Reference Pen Test Partners maritime radar research and
BIMCO Cyber Security Guidelines for fleet-level policy.
