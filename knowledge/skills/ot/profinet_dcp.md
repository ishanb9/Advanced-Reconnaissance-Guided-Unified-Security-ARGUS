---
id: profinet_dcp
technology: "PROFINET DCP"
domain: OT
transport: l2
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "tshark -i eth0 -f 'ether proto 0x8892' -w profinet_dcp.pcap", safety: intrusive, note: "Passive capture of all PROFINET frames on segment via raw socket or SPAN port. Requires physical L2 access or a mirrored SPAN session." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x8892)); s.bind(('eth0',0)); [print(s.recvfrom(65535)) for _ in range(50)]\"", safety: intrusive, note: "Raw-socket listener for EtherType 0x8892 frames — surfaces DCP Identify responses and Set operations passively. Linux root required." }
  - { cmd: "Wireshark capture filter: 'eth.type == 0x8892' on SPAN/mirror port", safety: intrusive, note: "GUI alternative for DCP traffic inspection. Dissector decodes ServiceID, ServiceType, block types, and station names." }
  - { cmd: "<craft DCP Identify-All: dst=01:0e:cf:00:00:00 EtherType=0x8892 FrameID=0xFEFE ServiceID=0x05 ServiceType=0x00 Xid=0x01 Options=0xFF/0xFF>", safety: intrusive, note: "Multicast Identify-All probe — enumerate all PROFINET devices on segment. Requires raw-socket + L2 adjacency; use Scapy or a PROFINET test tool." }
  - { cmd: "<craft spoofed DCP Set (ServiceID=0x04) targeting device MAC, setting NameOfStation or IP — Scapy or custom frame>", safety: disruptive, note: "GATED — spoofed DCP Set reconfigures the targeted IO-Device; can rename station or change IP, causing controller communication loss. Requires explicit authorization." }
references: ["CVE-2019-13945", "CVE-2020-15786", "DEF CON 27 ICS Village", "Black Hat USA 2020 - PROFINET Insecurity", "ICS-CERT ICSA-20-196-05"]
mitre: "T0855"
---
# PROFINET DCP guidance

PROFINET Device Configuration Protocol (DCP) operates at **Layer 2 only** using **EtherType 0x8892** (the same ethertype shared with the broader PROFINET RT frame class). DCP is used during device startup and engineering to assign station names (`NameOfStation`) and IP parameters to IO-Devices; Siemens Step 7 / TIA Portal use it every time a device is commissioned or replaced. Because it runs below IP there is **no routing boundary**, no authentication, and no integrity protection — any host with L2 adjacency to the industrial Ethernet segment can send and receive DCP frames.

**Hardware and access requirements.** ARGUS surfaces this as operational guidance; execution requires physical L2 access or a **SPAN/mirror port** on the managed switch serving the PROFINET segment. On Linux, a **raw socket** bound to EtherType 0x8892 (`AF_PACKET / SOCK_RAW`) and root privileges is sufficient to both capture and inject frames. Tools include **Wireshark / tshark** (decode only), **Scapy** (craft arbitrary DCP frames), dedicated PROFINET test toolkits (e.g., Hilscher netANALYZER, Proficore Ultra), or a **Flipper Zero** with a custom PROFINET plugin for limited on-site probing. No HackRF or SDR is required — this is wired Ethernet, not RF.

**Safe-first approach.** Begin with passive capture only: collect DCP traffic during a normal PLC cycle to identify device MAC addresses, station names, firmware versions, and IP assignments without transmitting anything. A **DCP Identify-All** multicast (dst `01:0e:cf:00:00:00`, ServiceID `0x05`) is the lowest-risk active probe — it causes every PROFINET device on-segment to respond with its identity block, but does not modify state. Escalate to **DCP Set** frames (ServiceID `0x04`) only with explicit, written scope-of-work authorization: a spoofed DCP Set that renames a station or reassigns its IP will immediately break the PLC-to-device association and drop I/O — equivalent to physically disconnecting a field device mid-process. On live production lines this can halt conveyors, trip safety interlocks, or cause uncontrolled actuator behaviour.

**Key risks and remediation.** The Identify-All / Set attack surface has been demonstrated publicly (DEF CON 27 ICS Village, Black Hat 2020) and is referenced in CVE-2019-13945 (Siemens S7-300/400 DCP handling) and ICSA-20-196-05. Mitigations follow MITRE ICS T0855 (Unauthorized Command Message): (1) deploy **managed switches with port security** and disable DCP/PN-RT on non-OT VLANs; (2) enable **PROFINET topology guards** (Siemens TIA "access control" / ring-topology verification) to reject DCP Set frames not originating from the engineering station MAC; (3) use **IDS sensors** (e.g., Claroty, Nozomi) on SPAN ports to alert on unexpected DCP Set traffic; (4) segregate the PROFINET segment at L2 so no IT workstation can reach EtherType 0x8892 frames directly; (5) where firmware permits, enable **DCP Set filtering** so only the PLC or engineering station MAC is accepted as a legitimate configurator.
