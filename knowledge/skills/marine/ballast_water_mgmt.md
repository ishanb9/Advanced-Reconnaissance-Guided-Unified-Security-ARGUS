---
id: ballast_water_mgmt
technology: "Ballast Water Management System (BWMS)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: medium
life_safety: true
match:
  ports: [502, 4840]
  banners: ["ballast water", "BWMS", "Alfa Laval PureBallast", "Wartsila Aquarius", "Wärtsilä", "OceanSaver", "JFE Engineering"]
  markers: ["pure-ballast", "aquarius-ec", "oceansaver", "bwms-controller", "ballast-system"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p502,4840 --script banner {host}", safety: safe, note: "Enumerate BWMS controller Modbus (502) and OPC UA (4840) services — identify vendor (Alfa Laval PureBallast, Wärtsilä Aquarius, OceanSaver) and firmware. Read-only." }
  - { cmd: "nmap -Pn -p502 --script modbus-discover {host}", safety: safe, note: "Read Modbus device identity from BWMS pump/UV controller gateway — vendor, product, firmware. Read-only FC 43." }
  - { cmd: "nmap -Pn -sV --open --script http-title,http-auth-finder {host}", safety: safe, note: "Discover and fingerprint BWMS web management interface on any exposed port — check for unauthenticated access to treatment logs (Alfa Laval PureBallast, Wärtsilä Aquarius service defaults)." }
  - { cmd: "<disable UV treatment unit, alter flow rate setpoints, or bypass IMO D-2 treatment logging on {host}>", safety: disruptive, note: "GATED — bypassing ballast water treatment may cause environmental harm and regulatory non-compliance; altering flow setpoints affects stability. Requires explicit authorization." }
references: ["IMO BWM Convention D-2 Standard", "USCG 33 CFR Part 151", "IEC 60092-504", "Alfa Laval PureBallast Security Advisory 2020"]
mitre: "T0855 / ICS T0836"
---
# Ballast Water Management System (BWMS)

The Ballast Water Management System treats ballast water during uptake and discharge to comply
with the IMO Ballast Water Management Convention (D-2 standard, in force September 2017) and
USCG regulations (33 CFR Part 151). Treatment methods include UV irradiation (Alfa Laval
PureBallast, Wartsila Aquarius UV), electrochlorination (OceanSaver, JFE Engineering), and
filtration plus UV combinations. The BWMS controller (typically a dedicated PLC or embedded
Linux/Windows system) monitors UV intensity, flow rates, filter differential pressure, chemical
dosing rates, and treatment effectiveness indicators. It communicates with the ship's alarm
monitoring system via Modbus/TCP (502/tcp) or a serial gateway, and may expose a web management
interface (8080/tcp) for operational dashboards, treatment logs, and regulatory compliance
reporting under IMO Form E (Ballast Water Record Book).

**Safety-of-life scope.** While primarily an environmental compliance system, the BWMS has
indirect life-safety implications: the UV treatment unit operates at high electrical power, and
electrochlorination units produce sodium hypochlorite and hydrogen gas (explosion risk if
ventilation fails). Additionally, the ballast pumps controlled by the BWMS are part of the
vessel's stability management system — interfering with ballast pump operation during port
loading or at sea can affect trim and stability calculations fed to the loading computer. This
is `life_safety: true` with secondary safety implications. Bypassing treatment logging also
creates regulatory non-compliance exposure (MARPOL violations, USCG enforcement, port state
control detention).

**Safe-first testing.** Enumerate BWMS management interfaces passively: Modbus device identity
(FC 43), HTTP banner fingerprint, and web management login page. Check for default credentials
(Alfa Laval PureBallast and Wärtsilä Aquarius systems have documented service account defaults).
Verify whether the treatment log (regulatory compliance record) is accessible without authentication
— exfiltration of false treatment records would have regulatory implications. Assess whether the
BWMS Modbus gateway is reachable from the general vessel LAN. **Do not** alter UV setpoints,
flow rate limits, or treatment bypass states — the system may be running an active treatment
cycle with open sea chests, and interruption can affect compliance status.

**Remediation.** Change default BWMS management credentials; restrict Modbus and web management
interfaces to the engineering VLAN only; enable HTTPS on web management; verify that regulatory
treatment logs are stored in a tamper-evident format and backed up to a shore-side system;
apply vendor firmware patches per type-approval requirements; and include BWMS in the vessel's
IMO cyber risk management plan per MSC-FAL.1/Circ.3. Cross-reference USCG and flag-state BWMS
type-approval certificates for software version compliance.
