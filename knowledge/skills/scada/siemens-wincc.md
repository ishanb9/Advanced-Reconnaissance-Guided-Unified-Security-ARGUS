---
id: siemens-wincc
technology: "Siemens WinCC SCADA/HMI"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [102, 4840]
  banners: ["WinCC", "SIMATIC", "Siemens"]
  markers: ["WinCC/", "CC-AD", "simatic wincc", "/WinCC/"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p4840 -sV --script opcua-info {host}", safety: safe, note: "WinCC 7.x+ exposes OPC-UA on 4840/tcp; enumerate endpoints and security policies read-only." }
  - { cmd: "nmap -Pn -sT -p102 -sV --script s7-info {host}", safety: safe, note: "Identify underlying S7 PLC or WinCC Comfort Panel over S7comm (ISO-TSAP 102/tcp)." }
  - { cmd: "nmap -Pn -sT -p1433 --script ms-sql-info,ms-sql-empty-password {host}", safety: safe, note: "WinCC stores tag, alarm, and historian data in SQL Server; check for default/blank SA password (historical WinCC default)." }
  - { cmd: "<SQL query against WinCCRuntime database>", safety: intrusive, note: "GATED — reading WinCCRuntime DB reveals real-time tag values and operator actions." }
references: ["CVE-2014-2908", "CVE-2011-4515", "CVE-2012-3015", "ICS-CERT ICSA-12-195-01", "Stuxnet (WinCC DB exploit)"]
mitre: "T0817 / ICS T0856"
---
# Siemens WinCC SCADA/HMI

Siemens SIMATIC WinCC is a widely deployed SCADA/HMI platform used in power generation,
automotive, pharmaceuticals, and critical infrastructure worldwide. WinCC stores all runtime
data — tag values, alarms, audit trails — in a **Microsoft SQL Server** database
(`WinCCRuntime`), accessed by local and remote clients. It communicates with Siemens PLCs
over **S7comm (ISO-TSAP, 102/tcp)** and supports OPC-DA and OPC-UA for third-party integration.
WinCC gained notoriety as the target of the **Stuxnet** worm (2010), which exploited a hardcoded
WinCC SQL Server password to access process data and inject code into Step 7 projects.

**Attack surface.** The historical default SA password for the WinCC SQL Server instance
(`2WSXcder`) remains in legacy deployments and is well-documented in public advisories. SQL
access to `WinCCRuntime` yields real-time process tags, operator action logs, and alarm history.
WinCC scripting (VBScript/C-scripting) runs inside the runtime with OS-level access. OPC-DA
endpoints may be accessible without authentication via DCOM with permissive launch/activation
permissions. Siemens ICS-CERT advisories document multiple RCE, path-traversal, and privilege-
escalation vulnerabilities across WinCC 7.x versions.

**Safe-first testing.** Fingerprint the platform via OPC-UA endpoint enumeration on 4840/tcp
(read-only, no authentication for discovery) and S7comm banner on 102/tcp. Check the SQL Server
instance for blank/default passwords using `ms-sql-empty-password` NSE before any manual SQL
command. Never issue S7 write commands against a live PLC/WinCC system without explicit, scoped
authorization — this directly actuates process equipment. WinCC deployments in power and
manufacturing are life-safety systems.

**Remediation.** Change the SQL Server SA password from the WinCC default immediately. Apply all
Siemens ProductCERT advisories for the installed WinCC version. Restrict SQL Server access to
localhost and known engineering workstations. Isolate 102/tcp to PLC-to-WinCC traffic only.
Migrate from OPC-DA/DCOM to OPC-UA with security mode `SignAndEncrypt`. Review WinCC script
editor permissions and disable unnecessary script execution.
