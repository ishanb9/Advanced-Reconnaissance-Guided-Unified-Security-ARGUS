---
id: factorytalk-view
technology: "Rockwell Automation FactoryTalk View"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [44818, 2222, 4840]
  banners: ["FactoryTalk", "Rockwell", "Allen-Bradley", "RSLinx"]
  markers: ["RSLinx", "FactoryTalk/", "ftld", "ftaevent"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p44818 -sV --script enip-info {host}", safety: safe, note: "EtherNet/IP CIP identity object on 44818/tcp; returns vendor, product name, firmware — Rockwell-specific fields identify FactoryTalk/RSLinx gateway." }
  - { cmd: "nmap -Pn -sU -p44818 --script enip-info {host}", safety: safe, note: "EtherNet/IP UDP list-identity; passive discovery of connected Allen-Bradley devices managed by FactoryTalk." }
  - { cmd: "nmap -Pn -sT -p4840 -sV --script opcua-info {host}", safety: safe, note: "FactoryTalk Linx exposes OPC-UA; enumerate endpoints and server info read-only." }
  - { cmd: "<CIP read attribute service against live PLC tags>", safety: intrusive, note: "GATED — reading CIP tag values is active; any write service can command the PLC." }
references: ["CVE-2022-1161", "CVE-2022-46670", "CVE-2021-27469", "ICSA-22-090-05", "ICSA-21-040-03"]
mitre: "T0817 / ICS T0836"
---
# Rockwell Automation FactoryTalk View

Rockwell Automation FactoryTalk View (FTV) is the dominant SCADA/HMI platform in North American
discrete manufacturing, automotive, and food & beverage plants. It includes FactoryTalk View
Site Edition (SE) for large distributed systems and Machine Edition (ME) for panel-level HMIs.
The underlying communication infrastructure is **RSLinx Classic / FactoryTalk Linx**, which
bridges HMI clients to Allen-Bradley PLCs (ControlLogix, CompactLogix, MicroLogix) over
**EtherNet/IP (44818/tcp+udp)** and CIP. FactoryTalk Services Platform provides a shared
directory and alarm service consumed by all FactoryTalk-family products on the same Windows host.

**Attack surface.** RSLinx Classic exposes EtherNet/IP on 44818 without authentication for list-
identity and basic attribute read services, which leaks device inventory and firmware versions.
CVE-2022-1161 (FactoryTalk Linx) allows unauthenticated remote code execution via a crafted CIP
request. FactoryTalk View SE uses a shared directory service (DCOM-based) that is accessible to
any authenticated domain user. FactoryTalk Alarms and Events logs are stored in SQL Server, often
with broad network access. The HMI scripting environment (VBA macros in display files) can execute
OS commands if an attacker can upload or modify `.med`/`.apa` display files.

**Safe-first testing.** Begin with EtherNet/IP CIP list-identity on 44818/tcp and /udp — this is
read-only enumeration and does not affect PLC state. Enumerate RSLinx Classic using the CIP
identity object to gather product name and firmware. Review the FactoryTalk directory service
(DCOM) for unauthenticated access. Do not issue any CIP write services (Set_Attribute_Single,
Output, etc.) against live controllers — this directly commands the process. FactoryTalk View
deployments often control life-safety-critical equipment including presses, conveyors, and
bottling lines.

**Remediation.** Apply Rockwell PCSD advisories and patch RSLinx Classic to the latest version.
Disable RSLinx Classic's DDE/OPC-DA interface if not required. Segment EtherNet/IP traffic
to a dedicated OT VLAN. Remove FactoryTalk Services Platform from internet-routable hosts.
Audit FactoryTalk display files for unauthorized VBA macros and enable code signing for display
packages.
