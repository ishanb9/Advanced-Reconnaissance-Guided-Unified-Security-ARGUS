---
id: goose_sv
technology: "IEC 61850 GOOSE / SV"
domain: OT
transport: l2
safety_class: intrusive
severity: critical
life_safety: true
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "tcpdump -i <SPAN-iface> -nn 'ether proto 0x88b8 or ether proto 0x88ba' -w goose_sv.pcap", safety: intrusive, note: "Passive SPAN capture of raw GOOSE (0x88B8) and SV (0x88BA) frames. Requires a SPAN/mirror port or TAP on the substation LAN — no injection." }
  - { cmd: "tshark -r goose_sv.pcap -Y 'goose || sv' -T fields -e goose.appid -e goose.gocbRef -e goose.stNum -e goose.sqNum -e goose.allData", safety: intrusive, note: "Decode captured PCAP offline; enumerate AppIDs, GOOSE control-block references, state numbers. Read-only analysis step." }
  - { cmd: "python3 -c \"from scapy.all import *; sniff(iface='<SPAN-iface>', filter='ether proto 0x88b8', prn=lambda p: p.summary(), store=0, count=200)\"", safety: intrusive, note: "Live decode of GOOSE multicast frames via Scapy on a SPAN interface. Requires Scapy with IEC 61850 layer or custom dissector." }
  - { cmd: "<REPLAY/SPOOF — e.g. scapy sendp() with crafted GOOSE trip bit set>", safety: disruptive, note: "GATED — spoofed GOOSE with Trip=True causes immediate breaker operation. Ultra-destructive; causes physical disconnection of live HV equipment. Requires explicit operator authorization, live-line crew standing by, and grid-impact assessment." }
references: ["CVE-2019-13946", "ICS-CERT ICSA-19-253-04", "DEF CON 22 - Leveraging IEC 61850", "Black Hat USA 2015 - Attacking IEC 61850", "NERC CIP-005", "IEC 62351-6"]
mitre: "T0855"
---
# IEC 61850 GOOSE / SV guidance

**IEC 61850 Generic Object Oriented Substation Event (GOOSE)** and **Sampled Values (SV)** are Layer-2
multicast protocols used in power substation automation. GOOSE (Ethertype **0x88B8**) carries
protection and control signals — including breaker trip commands — between Intelligent Electronic
Devices (IEDs) such as relays, merging units, and bay controllers. Sampled Values (Ethertype
**0x88BA**) stream real-time current and voltage measurements from merging units to protection relays
at rates up to 80 samples per power-cycle. Both protocols are **unauthenticated by default** in
IEC 61850 editions prior to Amendment 1 (2020) with IEC 62351-6 HMAC extensions. Neither protocol
uses IP or TCP/UDP — frames are delivered directly over Ethernet and therefore cannot be blocked by
standard IP firewalls. ARGUS surfaces this technology as guidance; execution of any active technique
requires physical hardware access to the substation process-bus or station-bus LAN.

**Hardware required.** Passive capture requires a **network TAP or SPAN/mirror port** on a managed
substation switch (typically IEC 61850 process-bus or station-bus) and a laptop with a promiscuous-
mode NIC running Wireshark/tshark, tcpdump, or Scapy. There is no RF component — GOOSE/SV run over
dedicated fiber or copper Ethernet segments. Active spoofing additionally requires a second NIC or
the same SPAN port if the switch allows injected frames back onto the bus; commercial tools such as
**Achilles IEC 61850 Protocol Test Tool**, **OMICRON IEDScout**, or custom Scapy scripts have been
used in documented research. Unauthorized physical access to a substation control house is itself a
significant barrier and a criminal offence in most jurisdictions.

**Safe-first approach — passive SPAN capture only.** ARGUS will only ever recommend read-only
observation: mirror the process-bus or station-bus VLAN to a capture interface, collect GOOSE and SV
frames in a PCAP, and decode them offline. Key observables include AppIDs, GoCBRef (control-block
reference), stNum/sqNum counters (which increment on state changes), and the allData payload
containing actual protection outputs. Monitoring sqNum gaps or stNum regressions can detect replay
or injection by a third party without any active probing. **Do not inject GOOSE frames.** A spoofed
GOOSE with the Trip bit asserted is indistinguishable at the IED from a legitimate protection
operation — the receiving relay will open the circuit breaker within 4 ms. On a live substation this
causes an immediate, unplanned outage of high-voltage equipment, potential arc-flash events, and may
disconnect power to life-safety loads (hospitals, water treatment, rail). This is classified as
ultra-destructive and requires an explicit written authorization, a safety plan, and coordination
with the asset owner's network operations center before any active testing.

**Remediation.** Implement IEC 62351-6 HMAC message authentication on all GOOSE publishers and
subscribers — this cryptographically binds each frame to its source IED and prevents spoofing.
Segregate the process bus onto dedicated VLANs with MAC-based access control and port security;
disable unused switch ports; log all GOOSE AppID anomalies via a substation SIEM or IDS (e.g.,
Claroty, Dragos, Nozomi). Apply NERC CIP-005 electronic security perimeter controls to deny
unmanaged devices physical access to substation LAN ports. Where IEC 62351-6 is not yet deployed,
deploy IED-level role-based access control and audit firmware integrity against vendor baselines.
Map findings to **MITRE ATT&CK for ICS T0855 (Unauthorized Command Message)** and report to the
asset owner's ICS incident response team and relevant national CISA/CERT before any disclosure.
