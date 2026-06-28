---
id: ship_alarm_monitoring
technology: "Ship Alarm and Monitoring System (AMS/IAS)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [502, 4840]
  banners: ["K-Chief", "NORIS", "Kongsberg IAS", "Rolls-Royce IAS", "Yokogawa", "Alarm Monitoring", "IAS"]
  markers: ["k-chief", "noris-group", "ias-server", "alarm-panel", "machinery-alarm"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p502,4840 --script banner {host}", safety: safe, note: "Enumerate AMS/IAS server Modbus (502) and OPC UA (4840) services — identify vendor (Kongsberg K-Chief, Noris, Yokogawa) and firmware from service banner. Read-only." }
  - { cmd: "nmap -Pn -p502 --script modbus-discover {host}", safety: safe, note: "Read AMS Modbus gateway device identity — vendor/product/firmware — without altering alarm state. Read-only FC 43." }
  - { cmd: "nmap -Pn -p4840 --script opcua-info {host}", safety: safe, note: "Enumerate OPC UA server node information model on AMS — identify alarm state variables, sensor nodes, and security mode." }
  - { cmd: "<silence, acknowledge, or inhibit safety alarms via AMS management interface or Modbus write on {host}>", safety: disruptive, note: "GATED — disabling machinery alarms removes protection for high-temperature, high-pressure, or flooding events. Requires explicit authorization and machinery offline." }
references: ["IEC 60092-504", "BIMCO Cyber Security Guidelines", "IMO MSC-FAL.1/Circ.3", "DNV-GL Rules for Ships Pt.4 Ch.9", "IACS UR E22"]
mitre: "T0814 / ICS T0816"
---
# Ship Alarm and Monitoring System (AMS/IAS)

The Alarm and Monitoring System (AMS) — also called the Integrated Alarm System (IAS) or
Integrated Automation System — is the central nervous system of a vessel's machinery spaces.
It monitors thousands of analog and digital sensors covering main engine, auxiliary engines,
boilers, steering gear, ballast systems, fire detection, flooding sensors, tank levels, and
electrical distribution — triggering alarms for out-of-range conditions and providing the duty
engineer with a watchkeeping display. Vendors include Kongsberg (K-Chief 600/700), Noris Group,
Yokogawa, Rolls-Royce (IAS, now Kongsberg), and ABB. Modern AMS systems are IP-networked,
using Modbus/TCP (502/tcp) to poll sensor gateways, OPC UA (4840/tcp) for northbound integration,
and web management interfaces for alarm history, trend displays, and system configuration. These
systems are increasingly interconnected with the vessel's general IT network for remote condition
monitoring by shore-side technical management.

**Safety-of-life scope.** The AMS enforces machinery protection logic and provides the sole
alerting mechanism for flooding, fire, overpressure, and loss-of-cooling events in unmanned
machinery spaces (UMS, allowed by class if AMS meets IEC 60092-504 and DNV-GL rules). Disabling,
flooding with false alarms, or silencing alarm channels removes the protection that prevents
loss of the vessel. Unauthorized write access to alarm inhibit registers can silence groups of
machinery alarms, allowing a developing casualty (fire, flooding, engine overheat) to progress
undetected. This is `life_safety: true` with potential for loss-of-vessel events.

**Safe-first testing.** Enumerate the AMS server passively: identify the vendor and firmware via
Modbus device identity (FC 43), OPC UA server info, and HTTP banner. Verify the OPC UA security
mode — most AMS installations use OPC UA in None/None (no security) mode to simplify OEM
integration. Map available Modbus register ranges against the AMS I/O list to identify writable
alarm inhibit or setpoint registers. Check network segmentation: the AMS server must not be
reachable from crew internet, cargo management systems, or VSAT uplink. **Do not** write to
alarm acknowledge, inhibit, or bypass registers — doing so during normal operations may mask
real casualty precursors and constitutes interference with a mandatory safety system.

**Remediation.** Restrict AMS Modbus and OPC UA interfaces to engineering VLAN clients only,
blocking write function codes at the network boundary; enable OPC UA encryption and signing;
implement alarm management logging with tamper-evident audit trails; segment shore-side
condition monitoring access through a maritime DMZ with MFA; and align with IACS UR E22
(Cyber resilience of onboard systems) and DNV-GL class notation for integrated automation.
