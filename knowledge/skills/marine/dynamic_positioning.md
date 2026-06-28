---
id: dynamic_positioning
technology: "Dynamic Positioning (DP) System"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [4001, 4500, 502, 102]
  banners: ["Kongsberg DP", "Navis DP", "L3 DP", "dynamic positioning", "AutoDP", "SDP", "DP2", "DP3"]
  markers: ["kongsberg-dp", "navis-dp", "l3-dp", "dynamic-position", "thruster-control", "dp-operator"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p502,102,4001,4500,22,80,443 {host}", safety: safe, note: "Enumerate DP workstation services — identify Modbus/S7 sensor inputs, proprietary control ports, and management interfaces. Read-only." }
  - { cmd: "nmap -Pn -p502 --script modbus-discover {host}", safety: safe, note: "If DP uses Modbus for sensor inputs, enumerate Modbus device identity and available function codes. Read-only." }
  - { cmd: "nmap -Pn -p445 --script smb-os-discovery,smb-security-mode {host}", safety: safe, note: "DP controllers run Windows; assess OS patch level and SMB security mode — unpatched Windows is common in type-approved systems." }
  - { cmd: "<inject false position/heading sensor data or issue thruster command to DP controller on {host}>", safety: disruptive, note: "GATED — DP loss of position while connected to a drill riser or during SPS offloading is a Tier 3 marine incident; thruster command injection is immediately life-threatening. Requires explicit authorization, vessel not in DP operation." }
references: ["IMCA M 232 Cyber Security for DP", "IMO MSC-FAL.1/Circ.3", "BIMCO Cyber Security Guidelines", "DNV-GL DP FMEA", "OTC 28710 DP Cyber Risk 2018"]
mitre: "T0855 / ICS T0836"
---
# Dynamic Positioning (DP) System

Dynamic Positioning automatically maintains a vessel's position and heading using its own
propulsion system — thrusters, azimuthing drives, and main propellers — without anchoring.
DP is critical for offshore drilling vessels, FPSO offloading, cable-lay ships, pipe-lay vessels,
dive support vessels, and wind-farm installation ships. The DP controller (Kongsberg K-Pos,
ABB Azipod DP, L3 NTCS, Navis) aggregates sensor inputs — multiple GPS/DGNSS units, gyrocompasses,
wind sensors, motion reference units (MRU), acoustic position reference (HIPAP/HPR), and taut-wire
systems — applies mathematical vessel model calculations, and outputs thruster set-points every
100–200 ms. The controller is a Windows or Linux workstation connected to the vessel OT network
via Modbus (502/tcp), serial RS-422, or proprietary IP protocols.

**Safety-of-life scope.** IMO classifies DP operations as among the highest-risk marine activities.
Loss of position (LOP) while connected to a subsea drill riser can cause a blow-out, while LOP
during FPSO offloading can cause a collision and large oil spill. DP systems are triply redundant
on class DP-3 vessels (separate compartments, separate power, separate control), but the shared
IP network connecting redundant systems is often a single-fault point. Sensor input spoofing —
feeding false GPS or gyro data to the DP controller — causes the vessel to actively drive off
position while the operator sees apparent stability. This is `life_safety: true` with potential
for mass-casualty and environmental catastrophe. IMCA M 232 specifically addresses cyber security
for DP systems.

**Safe-first testing.** Lead with entirely passive enumeration of the DP workstation's OS and
service inventory. Verify network segmentation: the DP controller should be on a dedicated,
isolated VLAN unreachable from crew internet or VSAT uplink. Check for Modbus or S7 sensor-input
ports accessible from adjacent vessel network segments. Review whether maintenance access uses
time-limited, logged sessions or standing remote-access credentials. **Do not** interact with
sensor inputs, send any data to the DP controller's control ports, or attempt to enumerate
thruster command interfaces — even a read of live control registers under some DP implementations
causes a watchdog re-arm that the controller logs as a fault event. Never conduct active testing
on a vessel in DP operation.

**Remediation.** Implement IMCA M 232 recommendations: physically separate DP control LAN from
general vessel network; conduct DP FMEA (failure mode and effects analysis) to include cyber
scenarios; restrict all remote access to a jump-server with MFA, session recording, and automatic
time-out; apply Windows patches under OEM-approved bundles; verify cyber resilience as part of
the annual DP trials and class notation renewal. Reference DNV-GL DP class notation documentation
for cyber-specific requirements.
