---
id: engine_monitoring
technology: "Marine Engine / Propulsion Monitoring (Modbus/CAN)"
domain: OT
category: marine
transport: can
safety_class: safe
severity: high
life_safety: true
match:
  ports: [502, 4840]
  banners: ["Kongsberg Vessel Insight", "Wärtsilä Online", "engine monitoring", "propulsion", "SCADA marine", "alarm monitoring"]
  markers: ["vessel-insight", "wartsila-online", "engine-control", "propulsion-monitor", "main-engine"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p502 --script modbus-discover {host}", safety: safe, note: "Enumerate Modbus device identity on engine monitoring gateway — read vendor, product, firmware. Read-only FC 43." }
  - { cmd: "python3 -c \"from pymodbus.client import ModbusTcpClient as C; c=C('{host}'); c.connect(); r=c.read_input_registers(0,20); print(r.registers)\"", safety: safe, note: "Read input registers (FC 0x04) from engine monitoring Modbus gateway — RPM, temperature, pressure values. Read-only, non-actuating." }
  - { cmd: "nmap -Pn -p4840 --script opcua-info {host}", safety: safe, note: "Enumerate OPC UA server on engine monitoring platform — identify node tree, server metadata, and session security mode. Read-only." }
  - { cmd: "<write Modbus holding registers or OPC UA variable to alter engine setpoint, fuel valve position, or thruster speed reference on {host}>", safety: disruptive, note: "GATED — write commands can alter propulsion output or trip engine protection interlocks; risk of loss of propulsion, flooding, or fire. Requires explicit authorization, engine offline, classification society notification." }
references: ["CVE-2021-22657", "BIMCO Cyber Security Guidelines", "IMO MSC-FAL.1/Circ.3", "IEC 61162", "DNV-GL OT Security Class Notation"]
mitre: "T0855 / ICS T0836"
---
# Marine Engine / Propulsion Monitoring (Modbus/CAN)

Marine diesel main engines, auxiliary generators, and propulsion systems (fixed-pitch and
controllable-pitch propellers, azimuthing thrusters, pod drives) are monitored and in some
installations controlled through **Modbus/TCP** (502/tcp) or **CAN-bus/J1939** gateways.
Alarm monitoring and control systems (AMCS) from vendors including Kongsberg (Vessel Insight,
K-Chief), Wärtsilä (Online, NACOS), Rolls-Royce (IAS), and Noris Group aggregate engine
parameters — shaft RPM, exhaust temperatures, fuel consumption, bearing temperatures, cooling
water pressures, lube oil pressures — into an OPC UA or Modbus server accessible from the
vessel's engineering network. Engine remote-control (ERC) systems on modern vessels extend this
to bridge-controlled throttle and clutch commands over the same IP infrastructure. The IT/OT
boundary is frequently poorly defined — the engine monitoring server may be reachable from the
vessel's VSAT uplink via the shared ship LAN.

**Safety-of-life scope.** Loss of main engine propulsion in restricted waters, during harbour
approach, or in heavy weather is a life-safety event. Engine protection interlocks (high water
temperature trip, low lube oil pressure shutdown) are implemented in the monitoring system;
unauthorized write access can both disable these protections (causing catastrophic engine damage)
and command unintended propulsion changes. Thruster control systems on DP vessels share the same
OT network and protocol stack. This is `life_safety: true`. BIMCO and IMO MSC-FAL.1/Circ.3
both identify propulsion and engineering systems as critical cyber assets.

**Safe-first testing.** Begin with read-only Modbus enumeration: FC 43 (device identity) and FC
0x04 (read input registers) to identify the monitoring system vendor, firmware, and measured
parameters. On OPC UA endpoints (port 4840), enumerate the server information model with
`opcua-info` (Nmap NSE) to map available nodes — identify whether writable nodes are exposed
unauthenticated. Verify whether the Modbus gateway enforces a read-only mode by examining
function code availability. Check network segmentation: the engine monitoring VLAN should not
be bridged to the general vessel network or VSAT segment. **Do not** issue write function codes
(Modbus FC 0x05/0x06/0x10 or OPC UA Write service) to any register or node that corresponds
to an engine setpoint, protection override, or actuator command.

**Remediation.** Segment the engineering OT VLAN with a maritime firewall (Cisco IE, Moxa,
Ruggedcom) blocking write function codes from any non-authorized source; enable OPC UA security
(encryption and signing) where the server supports it; change Modbus gateway default credentials;
apply vendor firmware patches; implement anomaly detection on Modbus traffic (unexpected function
codes, write attempts, register ranges); and align with DNV-GL OT Security class notation
requirements for engineering systems. Reference IEC 62443 for defense-in-depth architecture.
