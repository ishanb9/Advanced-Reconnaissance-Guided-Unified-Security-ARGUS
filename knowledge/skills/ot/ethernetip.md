---
id: ethernetip
technology: "EtherNet/IP + CIP"
domain: OT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [44818]
  banners: ["ethernet/ip", "cip", "rockwell", "allen-bradley", "controllogix", "compactlogix", "micrologix", "enip", "EtherNet/IP ListIdentity", "CIP identity response"]
  markers: ["ListIdentity", "ListServices", "ListInterfaces"]
quick_wins:
  - { cmd: "nmap -p 44818 --script enip-info {host}", safety: safe, note: "Read-only EtherNet/IP ListIdentity — retrieves vendor, product name, serial, firmware, and device type without touching PLC state." }
  - { cmd: "nmap -p 44818,2222 -sV --script enip-info,cip-info {host}", safety: safe, note: "Extended banner grab combining EtherNet/IP identity and CIP service enumeration; no writes performed." }
  - { cmd: "python3 -m cpppo.server.enip.client --print {host}", safety: safe, note: "cpppo client reads EtherNet/IP identity object attributes from the target; read-only." }
  - { cmd: "python3 -c \"from pycomm3 import LogixDriver; plc = LogixDriver('{host}'); plc.open(); print(plc.get_tag_list()); plc.close()\"", safety: intrusive, note: "Enumerates all controller tag names via CIP; touches the PLC communication stack but makes no writes." }
  - { cmd: "python3 -c \"from pycomm3 import LogixDriver; plc = LogixDriver('{host}'); plc.open(); plc.write(('Program_Mode', 0)); plc.close()\"", safety: disruptive, note: "Issues a CIP Forward Open + CPU-STOP sequence — halts the PLC scan. GATED: requires explicit operator approval on active production systems." }
references:
  - "CVE-2012-6435"
  - "CVE-2012-6436"
  - "CVE-2022-1161"
  - "CVE-2022-1159"
  - "ICSA-12-249-01"
  - "ICSA-22-090-05"
  - "CISA KEV CVE-2022-1161"
mitre: "T0855"
---
# EtherNet/IP + CIP guidance

EtherNet/IP (Ethernet Industrial Protocol) is the application-layer wrapper around the Common Industrial Protocol (CIP) used by Allen-Bradley / Rockwell Automation controllers — ControlLogix, CompactLogix, MicroLogix, PowerFlex drives, and a large share of Siemens, Omron, and Schneider devices. Port 44818/tcp carries the explicit-messaging channel (ListIdentity, Forward Open, read/write tag data); port 2222/udp carries implicit I/O. Because CIP rides standard TCP/IP, it is routinely reachable from IT networks and internet-facing OT DMZs, making it a high-value target for reconnaissance and manipulation.

During an authorized engagement the first step is always a read-only ListIdentity query (nmap `enip-info` NSE script or cpppo). This yields the device's vendor ID, product type, product name, serial number, revision, and IP configuration without modifying any controller state. These values uniquely identify the firmware version, allowing rapid cross-reference against CISA ICS advisories and the CISA KEV catalog before any further interaction.

Active tag enumeration via pycomm3 `get_tag_list()` maps every accessible symbol in the controller — program routines, global tags, and I/O aliases. This is intrusive (it opens a CIP Forward Open session and queries the symbol object) but non-destructive if write calls are avoided. The resulting tag list directly informs which process variables can be read or influenced. Proceed to tag reads only with explicit scope authorization; treat any `write()` or mode-change command as disruptive and gate it behind a change-control window or a safe simulation environment.

The most dangerous CIP capability is the unauthenticated CPU stop/run transition (CIP service 0x17 to the program-controller object). CVE-2022-1161 and ICSA-22-090-05 document how Logix firmware accepted mode-change commands from any network peer without challenge. An attacker who can reach port 44818 can halt a production line, cause a physical process to fail safe (or fail dangerously), or inject ladder-logic modifications. Remediation: segment PLCs behind a unidirectional gateway or industrial firewall, enable Rockwell's FactoryTalk Security / CIP Security authentication (TLS + certificates), enforce allow-listing by source IP, and apply all available firmware patches.
