---
id: integrated_bridge
technology: "Integrated Bridge System (IBS)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [4001, 4002, 4500]
  banners: ["Integrated Bridge", "Kongsberg", "Raytheon Anschutz", "Wärtsilä", "Furuno ECDIS", "JRC JAN", "NaviSailor", "IBS"]
  markers: ["navi-sailor", "navisailor", "integrated bridge", "radar-arpa", "bridge system"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p135,445,3389,4001,4002,4500 {host}", safety: safe, note: "Full service scan of IBS workstation — identify OS (Windows fingerprint via SMB/RDP), vendor software version on proprietary ports 4001/4002/4500, and remote-access exposure." }
  - { cmd: "nmap -Pn -p445 --script smb-os-discovery,smb-security-mode,smb-vuln-ms17-010 {host}", safety: safe, note: "Detect unpatched Windows on IBS host — many run Windows XP/7 Embedded Standard with SMBv1; assess EternalBlue exposure." }
  - { cmd: "nmap -Pn -p3389 --script rdp-enum-encryption {host}", safety: safe, note: "Check RDP encryption level and NLA enforcement on IBS remote-access port — vendor support sessions often leave RDP open." }
  - { cmd: "<authenticate to IBS management interface on {host} and modify route plan, alarm thresholds, or sensor fusion weights>", safety: disruptive, note: "GATED — altering bridge system configuration directly affects navigation safety. Requires written authorization and vessel at berth." }
references: ["BIMCO Cyber Security Guidelines 2019", "IMO MSC-FAL.1/Circ.3", "IEC 62288", "DNV-GL Cyber Security Class Notation"]
mitre: "T0866 / ICS T0836"
---
# Integrated Bridge System (IBS)

An Integrated Bridge System fuses ECDIS, radar/ARPA, AIS, autopilot, speed log, gyrocompass,
echo sounder, engine telegraph, and conning display into a unified workstation environment on the
ship's bridge. Major vendors include Kongsberg Maritime (K-Bridge), Wärtsilä / Transas (NaviSailor),
JRC (JAN series), Furuno, and Raytheon Anschütz. The IBS typically runs on a networked cluster of
**Windows-based** workstations (frequently Windows XP, 7, or 10 Embedded) interconnected on a
dedicated bridge LAN with proprietary middleware. Sensor inputs arrive via NMEA 0183 (RS-422 serial
or 10110/tcp) and NMEA 2000 (CAN); proprietary IP protocols on ports such as 4001–4002 and 4500
carry inter-station synchronization and alarm distribution. Remote-access ports (RDP 3389, vendor
SSH/HTTPS, or proprietary admin) are routinely left open for OEM technical support.

**Safety-of-life scope.** The IBS is the single pane of glass for the officer of the watch during
all navigation phases, including restricted waters, harbour approach, and heavy weather. A
compromised or crashed IBS removes situational awareness at the exact moment it is most needed.
Attack surface includes the Windows OS layer (EternalBlue, PrintNightmare), the vendor middleware
(unauthenticated APIs, hardcoded credentials), the sensor input chain (NMEA injection), and
the remote-access ports used by OEM support. This asset is `life_safety: true` and is subject
to IMO MSC-FAL.1/Circ.3 cyber-risk management requirements as a safety-critical system.

**Safe-first testing.** Lead with passive OS and service enumeration: version banner grabs, SMB
security mode, RDP NLA enforcement, and web interface fingerprinting. Check for default or
hardcoded OEM credentials (common in Kongsberg, Transas, and JRC support accounts). Verify
whether Windows Update is enabled — type-approval constraints often prevent OS patching without
OEM engagement. Review network segmentation to confirm the bridge LAN is not routed to the vessel's
crew or cargo network. **Do not** interact with navigation functions, modify waypoint databases,
or alter alarm configurations without explicit scoped authorization and a vessel-at-berth
precondition with a qualified officer present.

**Remediation.** Apply Windows patches under OEM-approved bundles; disable SMBv1 and enforce
NLA on RDP; replace standing remote-access credentials with time-limited jump-server sessions;
segment the bridge LAN behind a maritime firewall (Ruggedcom, Cisco IE); align patch and
vulnerability management to DNV-GL Cyber Security class notation requirements and BIMCO
Cyber Security Guidelines; establish a change-management process for IBS software updates
coordinated with the flag state and classification society.
