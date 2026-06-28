---
id: airport_dcs
technology: "Airport DCS / Baggage Handling System (BHS / DCS)"
domain: OT
category: aviation
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [102, 4840, 9600, 44818]
  banners: ["Vanderlande", "Siemens Logistics", "BEUMER", "BHS", "DCS", "baggage", "SITA BagManager"]
  markers: ["vanderlande", "beumer", "siemens-logistics", "sita-baggage", "BHS", "DCS-BHS"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p 102,502,4840,9600,44818 --script s7-info,modbus-discover,opcua-info {host}", safety: safe, note: "Identify PLC/OPC-UA/Modbus services on BHS network — read-only enumeration of industrial control layer." }
  - { cmd: "nmap -Pn -sT -p 9600,44818 --script ethernetip-info {host}", safety: safe, note: "EtherNet/IP discovery against BHS PLC/conveyor controllers — vendor and firmware enumeration." }
  - { cmd: "curl -sk http://{host}/api/baggage/flights | python3 -m json.tool", safety: safe, note: "Probe DCS REST API for unauthenticated flight/baggage data — read-only enumeration." }
references: ["CVE-2020-10987", "CISA ICS Advisory ICSA-20-280-01", "TSA SD 1542-21-01C", "IATA DCS Standards"]
mitre: "T1190 / T0845 / T0859"
---
# Airport DCS / Baggage Handling System (BHS / DCS)

Airport **Departure Control Systems (DCS)** and **Baggage Handling Systems (BHS)** are the OT/IT hybrid infrastructure that manage passenger check-in, boarding pass issuance, seat assignments, and automated baggage sorting/routing. DCS is typically a distributed software platform (SITA, Amadeus, airline-proprietary) that communicates with airline reservation systems, weight & balance, and the Common Use Terminal Equipment (CUTE) at check-in counters. BHS is a complex OT network of PLCs (Siemens S7, Allen-Bradley), SCADA servers, conveyor belt drives, baggage screening integration (explosive detection), and sortation systems — all networked over industrial Ethernet with Modbus/TCP, EtherNet/IP, OPC-UA, and S7comm protocols.

**Why it matters.** BHS/DCS systems are high-value targets for several threat actor categories: (1) **disruption** — ransomware campaigns against airport OT systems can halt all baggage handling operations (Atlanta Hartsfield, Brussels, Frankfurt incidents); (2) **terrorism enablement** — unauthorized access to explosive detection integration or baggage routing could potentially allow unscreened bags to bypass security; (3) **data exfiltration** — DCS systems hold PII for millions of passengers (passport numbers, biometrics, payment data, travel itineraries); (4) **espionage** — flight manifests in DCS expose government/military travellers. TSA Security Directive 1542-21-01C mandates cybersecurity controls at U.S. airports specifically in response to demonstrated BHS/DCS vulnerabilities.

**Safe-first testing approach.** BHS/DCS assessments should start with network architecture review and passive enumeration. Use nmap to identify industrial protocol ports (S7: 102/tcp, Modbus: 502/tcp, EtherNet/IP: 44818/tcp, OPC-UA: 4840/tcp) on the OT segment; use read-only protocol queries (S7 info, Modbus device ID, OPC-UA browse) to inventory PLCs and SCADA servers. On the IT/DCS side, enumerate REST APIs, CUTE middleware interfaces, and SITA CUTE connection manager ports for unauthenticated access. **Never send write commands to BHS PLCs** — stopping a conveyor belt during operations causes baggage jams and can trigger safety interlocks; more critically, any interaction with explosive detection integration must be treated as out-of-scope and requires specialized TSA/regulatory authorization.

**Key risks and remediation.** Common findings include: flat OT networks (BHS PLCs directly reachable from airport corporate LAN), default PLC credentials (Siemens S7-300/400 default), unpatched SCADA servers (many running Windows XP/2003), DCS REST APIs with broken object-level authorization, and inadequate segmentation between baggage screening systems and general BHS network. Remediation: enforce Purdue model segmentation with unidirectional gateways between BHS OT and airport IT, implement role-based authentication on all DCS APIs, maintain OT patching cycles per CISA ICS advisories, and conduct regular tabletop exercises for BHS ransomware scenarios aligned with TSA SD requirements.
