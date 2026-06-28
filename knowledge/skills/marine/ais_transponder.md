---
id: ais_transponder
technology: "AIS Transponder (Class A/B VHF + IP gateway)"
domain: OT
category: marine
transport: rf
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [10110]
  banners: ["$AIVDM", "$AIVDO", "$AIABK", "$AIALR", "$BSVDM", "AIS"]
  markers: ["$AIVDM", "$AIVDO", "MMSI", "!AIVDM", "!AIVDO"]
quick_wins:
  - { cmd: "python3 -c \"import socket; s=socket.socket(); s.connect(('{host}',10110)); s.settimeout(8); data=b''; [(data:=data+s.recv(4096)) for _ in range(20)]; print(data.decode(errors='replace'))\"", safety: safe, note: "Passive read of AIS sentence stream — decode $AIVDM/AIVDO for MMSI, vessel name, position, COG, SOG. No state change." }
  - { cmd: "nmap -Pn -sT -p10110,2000 --script banner {host}", safety: safe, note: "Banner-grab AIS multiplexer or Class A transponder IP gateway — enumerate vendor and firmware." }
  - { cmd: "python3 -m pip install pyais -q && python3 -c \"from pyais.stream import TCPConnection; [print(m.decode()) for m in TCPConnection('{host}', port=10110)]\"", safety: safe, note: "Decode AIS payloads into structured vessel data — IMO, call sign, nav status, heading. Read-only." }
  - { cmd: "<transmit spoofed AIS VDM message with false MMSI/position via RF or inject crafted $AIVDM into {host}:10110>", safety: disruptive, note: "GATED — false AIS targets create phantom vessels on all receiving ECDIS and ARPA systems; collision risk for stand-on vessels. Requires explicit authorization and shoreside coordination." }
references: ["CVE-2020-6994", "USCG MSIB 04-19", "Trend Micro AIS Vulnerabilities Report 2019", "ITU-R M.1371-5"]
mitre: "T0830 / ICS T0839"
---
# AIS Transponder (Class A/B VHF + IP gateway)

The Automatic Identification System (AIS) is a VHF broadcast protocol (161.975 MHz / 162.025 MHz)
mandated by SOLAS for vessels over 300 GT. Class A transponders (ship-borne) transmit dynamic data
(position, SOG, COG, heading, navigational status) every 2–10 seconds and static data (MMSI, IMO,
vessel name, call sign, dimensions, cargo type) every 6 minutes using ITU-R M.1371 TDMA encoding.
Modern transponders include an Ethernet gateway that bridges decoded NMEA 0183 sentences
(`$AIVDM`, `$AIVDO`) onto the vessel LAN — typically on **10110/tcp** with no authentication.
Shodan and public AIS aggregators (MarineTraffic, VesselFinder) expose the global vessel picture,
but the shipboard receiver and its IP bridge are the local attack surface.

**Safety-of-life scope.** AIS data feeds ECDIS collision-avoidance displays, ARPA radar overlays,
port VTS (vessel traffic service) systems, and ship-to-ship situational awareness. False or missing
AIS targets have been implicated in near-miss incidents. Spoofing — either over RF or by injecting
crafted sentences into the LAN-side gateway — can create phantom vessels, move a real vessel's
reported position, or silence a target entirely, all of which create collision risk for navigating
officers relying on the display. This asset is `life_safety: true`.

**Safe-first testing.** Passively read the AIS sentence stream from the IP gateway: capture
`$AIVDM`/`$AIVDO` sentences and decode with `pyais` or `gpsd` to enumerate nearby vessel traffic,
the host vessel's own transmitted data, and sentence timing. Check whether the IP gateway
requires any authentication (virtually none do). Verify that the AIS unit firmware is current
(vendor portals publish update histories). **Do not** transmit on VHF AIS frequencies — that
requires maritime radio licensing and directly affects all vessels in VHF range. **Do not** inject
crafted sentences into the LAN gateway without scoped, written authorization, a vessel at berth,
and coordination with port authority and nearby vessel traffic.

**Remediation.** Restrict the AIS Ethernet port to a dedicated navigation VLAN; firewall the
10110 feed so only authorized navigation workstations and ECDIS displays receive it; apply
transponder firmware updates per vendor schedule; monitor for anomalous `$AIVDM` sentence rates
or unexpected MMSI identifiers appearing on the LAN feed; and cross-reference transmitted versus
received position with an independent GPS source. Reference USCG Marine Safety Information
Bulletins and ITU-R M.1371-5 for protocol standards.
