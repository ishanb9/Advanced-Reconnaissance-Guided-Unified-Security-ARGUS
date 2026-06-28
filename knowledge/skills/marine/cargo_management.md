---
id: cargo_management
technology: "Cargo Management System (CMS / LCMS)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [502]
  banners: ["cargo management", "LCMS", "loading computer", "Napa Loading", "Transas Loading", "Saab Tank Radar", "Emerson Rosemount"]
  markers: ["napa-loading", "lcms", "loading-computer", "tank-level", "cargo-control"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p502 --script banner,modbus-discover {host}", safety: safe, note: "Enumerate CMS Modbus gateway — identify vendor (NAPA, Transas/Wärtsilä, Saab Tank Control, Emerson) and firmware via device identity FC 43. Read-only." }
  - { cmd: "nmap -Pn -p502 --script modbus-discover {host}", safety: safe, note: "Read Modbus device identity on tank level / cargo pump gateway — vendor, product, firmware. Read-only FC 43." }
  - { cmd: "nmap -Pn -sV --open --script banner {host}", safety: safe, note: "Full service scan with banner grab — locate CMS web management interface on any port and fingerprint for vendor strings (NAPA, LCMS, Transas, Saab) to check for default credential exposure." }
  - { cmd: "<modify tank level inputs, cargo pump valve states, or stability calculation parameters in CMS on {host}>", safety: disruptive, note: "GATED — false tank data produces incorrect stability calculation; cargo shift or overloading can result in capsize. Requires explicit authorization and cargo operations suspended." }
references: ["IMO MARPOL Annex I", "SOLAS Chapter II-1", "ICS Tanker Safety Guide", "OCIMF SIRE 2.0", "CVE-2021-22657"]
mitre: "T0855 / ICS T0806"
---
# Cargo Management System (CMS / LCMS)

The Cargo Management System (CMS) — also called the Loading Computer and Management System (LCMS)
— controls, monitors, and calculates stability for cargo operations on tankers (oil, chemical, LNG),
bulk carriers, container ships, and RoRo ferries. It integrates tank level gauging (radar, float,
pressure), cargo temperature and pressure sensors, inert gas systems, cargo pump and valve status,
and draft sensors to compute real-time ship stability (GM, GZ curve, shear forces, bending moments)
against class-approved loading conditions. Vendors include NAPA, Transas (Wärtsilä), Saab Tank
Control, Emerson Rosemount, and Yokogawa. Modern CMS platforms run on Windows workstations with
Modbus/TCP (502/tcp) connections to sensor gateways and expose web dashboards (8080, 3000/tcp)
for remote monitoring by cargo superintendents — often accessible via VSAT uplink with minimal
authentication.

**Safety-of-life scope.** An incorrect stability picture — whether from sensor manipulation,
software fault, or malicious input — can result in cargo shift during heavy weather, loss of
positive metacentric height (capsizing), or structural failure from excessive hogging/sagging
moments. This is not a theoretical risk: incorrect ballasting and loading calculation failures
have contributed to several major vessel losses. On tankers, the CMS also controls inert gas
systems and cargo pump sequencing; unauthorized write access to valve states can cause overpressure,
underpressure (tank collapse), or cargo mixing leading to explosion risk. This is `life_safety: true`.

**Safe-first testing.** Enumerate CMS services passively: identify the loading computer vendor
from Modbus device identity and web UI fingerprinting. Verify whether the web dashboard requires
authentication — NAPA and Transas systems are frequently deployed with default credentials for
ship-to-shore connectivity. Check whether the Modbus gateway exposes writable registers for
tank level override or pump valve commands. Assess VSAT segmentation: the CMS should not be
directly reachable from the shore-side internet without a maritime DMZ and MFA. **Do not**
write to tank level registers, valve positions, or stability parameters — incorrect values
fed to the loading computer may be acted upon by the cargo officer without realizing the data
is compromised, especially during a busy cargo operation.

**Remediation.** Change all default CMS credentials; segment the CMS onto an engineering VLAN
with firewall restrictions on Modbus writes from unauthorized sources; provide shore-side access
only through a maritime DMZ with MFA and session recording; validate sensor inputs against
physical draft survey readings at start of cargo; apply vendor patches; and ensure the loading
computer type-approval (class-approved loading conditions) is current. Reference OCIMF SIRE 2.0
inspection criteria for tanker CMS cyber controls and ICS Tanker Safety Guide.
