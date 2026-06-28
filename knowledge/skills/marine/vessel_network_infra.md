---
id: vessel_network_infra
technology: "Vessel Network Infrastructure (Ship LAN / OT-IT convergence)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [179, 161, 162, 4786]
  banners: ["Cisco IE", "Moxa", "Ruggedcom", "Hirschmann", "Westermo", "ship LAN", "vessel network"]
  markers: ["cisco-ie", "ruggedcom", "hirschmann", "westermo", "moxa-switch"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,23,80,161,443,4786 {host}", safety: safe, note: "Enumerate vessel network switch/router management interfaces — identify vendor (Cisco IE, Moxa, Ruggedcom, Hirschmann), firmware version, and exposed management protocols." }
  - { cmd: "nmap -Pn -sU -p161 --script snmp-info,snmp-sysdescr {host}", safety: safe, note: "SNMP community string enumeration and system description — identifies switch type, firmware, port count. Public community read." }
  - { cmd: "nmap -Pn -p23 --script telnet-info {host}", safety: safe, note: "Check for Telnet management exposure on vessel switches — many maritime-grade switches default to Telnet enabled with default credentials (admin/admin, admin/1234)." }
  - { cmd: "<modify VLAN configuration, disable ACLs, or bridge OT navigation network to crew network on {host}>", safety: disruptive, note: "GATED — removing VLAN segmentation exposes navigation and propulsion OT systems to crew internet traffic. Requires explicit authorization and all navigation/propulsion systems offline." }
references: ["BIMCO Cyber Security Guidelines 2019", "IEC 62443-3-3", "IMO MSC-FAL.1/Circ.3", "IACS UR E26/E27", "USCG MSIB 01-20"]
mitre: "T0869 / ICS T0846"
---
# Vessel Network Infrastructure (Ship LAN / OT-IT convergence)

Modern vessels operate a converged IP network carrying both information technology (crew internet,
administrative systems, cargo documentation) and operational technology (ECDIS, AIS, engine
monitoring, GMDSS management) traffic. The physical layer typically consists of maritime-grade
managed Ethernet switches — Cisco IE (Industrial Ethernet), Moxa EDS/IKS, Ruggedcom RS/RX
(Siemens), Hirschmann (Belden), and Westermo — deployed in a ring or star topology connecting the
bridge, engine control room, cargo control room, and communication room. VLAN segmentation is
the primary isolation mechanism: navigation, engineering OT, GMDSS, and crew internet should
be on separate VLANs with ACL-enforced inter-VLAN routing. In practice, VLAN configuration
errors, flat network architectures, and default SNMP community strings (public/private) are
extremely common. The VSAT modem is typically the default gateway for all VLANs, creating a
common internet ingress for both OT and IT traffic.

**Why it matters.** The vessel network backbone is the lateral movement path between the crew
internet, VSAT link, and safety-critical OT systems. The 2017 NotPetya incident affected
multiple shipping companies via their vessel network infrastructure; A.P. Møller-Maersk suffered
an estimated $300 million impact partly because their vessel and port IT/OT networks were
insufficiently segmented. Cisco IE and Ruggedcom switches are routinely deployed with default
SNMP community strings, Telnet enabled (unencrypted management), default credentials, and outdated
firmware — providing an attacker with switch-level control, VLAN reconfiguration capability,
and a pivot into all vessel network segments.

**Safe-first testing.** Enumerate management interfaces passively: SNMP system description (OID
1.3.6.1.2.1.1.1.0) with public community, HTTP/HTTPS banner for firmware version, and Telnet
prompt. Map the switch topology using CDP/LLDP (`nmap --script cdp-info,lldp-info`). Verify
VLAN configuration by querying SNMP VLAN table (Q-Bridge MIB). Check for Cisco Smart Install
exposure (port 4786 — a well-known RCE vector on unpatched IOS). **Do not** alter VLAN
configuration, ACL rules, or routing tables — doing so can bridge OT safety systems to
untrusted networks, creating an immediate lateral movement path. Do not disable switch ports
serving navigation or propulsion equipment.

**Remediation.** Replace default SNMP community strings; disable Telnet (use SSHv2); apply
switch firmware updates per vendor schedule; implement strict VLAN segmentation with denied
inter-VLAN routing between crew, navigation OT, engineering OT, and GMDSS VLANs; disable Cisco
Smart Install; restrict management access to an out-of-band management VLAN; and conduct
network architecture review against IEC 62443-3-3 zone and conduit model. Reference IACS UR
E26/E27 cyber resilience requirements for new-build vessel network architecture.
