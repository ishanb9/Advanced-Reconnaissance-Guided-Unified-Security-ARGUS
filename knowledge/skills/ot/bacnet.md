---
id: bacnet
technology: "BACnet/IP"
domain: OT
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [47808]
  banners: ["bacnet", "bacnet/ip", "building automation"]
  markers: ["bacnet-if", "BACnet Protocol"]
quick_wins:
  - { cmd: "nmap -sU -p 47808 --script bacnet-info {host}", safety: safe, note: "Read-only BACnet device discovery: retrieves vendor, model, firmware, and object list via Who-Is/I-Am exchange" }
  - { cmd: "nmap -sU -p 47808 --script bacnet-discover {host}", safety: safe, note: "Enumerate all BACnet devices on subnet using broadcast Who-Is; logs device IDs and network addresses" }
  - { cmd: "python3 -m bacpypes.consolecmd --address {host} read <instance> analogInput 1 presentValue", safety: safe, note: "ReadProperty on a known object to confirm unauthenticated read access to sensor values (BACpypes)" }
  - { cmd: "python3 -m bacpypes.consolecmd --address {host} rpm <instance> analogInput 1 all", safety: intrusive, note: "ReadPropertyMultiple to bulk-read all properties of an object; causes moderate device load" }
  - { cmd: "python3 -m bacpypes.consolecmd --address {host} write <instance> binaryOutput 1 presentValue active priority 8", safety: disruptive, note: "WriteProperty to actuate a binary output (e.g. HVAC relay, fan, damper); DO NOT execute without explicit scope approval — causes physical state change" }
references:
  - "CVE-2022-21952"
  - "CVE-2023-28397"
  - "ICSA-20-105-02"
  - "ICSA-22-333-01"
  - "CISA KEV BACnet Stack Buffer Overflow"
mitre: "ICS T0836 (Modify Parameter), T0855 (Unauthorized Command Message)"
---
# BACnet/IP Guidance

BACnet (Building Automation and Control Networks) over IP operates on UDP port 47808 and is the dominant protocol for HVAC, lighting, fire suppression, access control, and elevator systems in commercial and industrial buildings. Devices expose an object model (Analog/Binary/Multi-state Inputs and Outputs, plus Schedule and Command objects) that can be read and written without authentication in the vast majority of deployed installations. A Who-Is broadcast returns the device ID, vendor ID, firmware revision, and object count of every BACnet node on the segment.

During an authorized engagement, begin with passive enumeration using `nmap --script bacnet-info` against port 47808/udp. This single script performs a compliant Who-Is/I-Am exchange and reads the Device object, revealing vendor name, model number, firmware string, and BACnet address binding — all with zero writes to the device and no operational risk. Follow up with ReadProperty or ReadPropertyMultiple (BACpypes library) to walk the object list and confirm which sensor values and setpoints are exposed. This read-only phase alone is sufficient to demonstrate the attack surface and produces the evidence needed for a finding.

WriteProperty commands are the primary risk vector and must be treated as disruptive operations requiring explicit written authorization before execution. Writing to BinaryOutput, AnalogOutput, or CommandObject instances can directly actuate HVAC dampers, disable chiller units, suppress fire alarm outputs, or unlock egress doors — all of which can cause physical harm or safety incidents. If scope permits controlled testing, limit writes to isolated lab systems or low-priority analog setpoints with an on-site operator present and ready to revert changes via the BMS front-end. Priority array manipulation (writing at priority 8 with a relinquish-default fallback) is the safest write pattern when testing is authorized.

Key exposures include complete lack of authentication or encryption in BACnet/IP (no TLS, no credentials), widespread internet exposure of BAS gateways on UDP 47808 (Shodan indexes tens of thousands), stack and heap vulnerabilities in popular stacks (Delta Controls, Schneider EBO, Siemens Desigo CC), and the life-safety classification of connected systems (fire panels, pressurization). Remediation: segment BACnet devices behind an application-layer firewall or BACnet-aware gateway that enforces allowlists by device instance and object type; disable the global broadcast Who-Is handler on production controllers; and upgrade to BACnet Secure Connect (BACnet/SC, ASHRAE Addendum bj) which adds TLS 1.3 and certificate-based mutual authentication.
