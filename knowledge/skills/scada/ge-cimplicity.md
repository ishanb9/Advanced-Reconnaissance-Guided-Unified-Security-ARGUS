---
id: ge-cimplicity
technology: "GE CIMPLICITY HMI/SCADA"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [5159, 5160]
  banners: ["CIMPLICITY", "Proficy", "GE Vernova"]
  markers: ["cimplicity", "proficy-cimplicity", "CIMPLICITY Server"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p5159,5160 -sV {host}", safety: safe, note: "Identify CIMPLICITY Server Manager ports; banner reveals product version." }
  - { cmd: "nmap -Pn -sT -p135 --script msrpc-enum {host}", safety: safe, note: "Enumerate RPC/DCOM endpoints — CIMPLICITY uses DCOM for OPC-DA and inter-server communication." }
  - { cmd: "nmap -Pn -sT -p445 --script smb-enum-shares {host}", safety: safe, note: "CIMPLICITY project files (.cim) are stored on SMB shares; enumerate accessible shares for project exposure." }
  - { cmd: "<CIMPLICITY CimView file analysis for embedded scripts>", safety: safe, note: "Read-only analysis of .cim CimView display files for embedded Basic Control Engine (BCE) scripts." }
references: ["CVE-2023-3463", "CVE-2022-37300", "CVE-2014-0751", "ICSA-23-199-03", "ICSA-14-058-01"]
mitre: "T0817 / ICS T0856"
---
# GE CIMPLICITY HMI/SCADA

GE CIMPLICITY (now Proficy CIMPLICITY under GE Vernova) is a mature HMI/SCADA platform widely
deployed in power generation, aerospace, and defense manufacturing. Unlike iFIX (point-based),
CIMPLICITY uses an object-oriented point database and a CimView display environment built on the
Windows COM/ActiveX stack. Projects are stored as collections of `.cim` files on shared file
systems, and the CIMPLICITY Server Manager coordinates communication between the project server,
point management, and viewer clients over TCP 5159/5160 and DCOM.

**Attack surface.** The CIMPLICITY Basic Control Engine (BCE) scripting language embedded in
CimView display files can read/write points and execute Windows shell commands. CVE-2014-0751 —
a path-traversal vulnerability allowing unauthenticated remote file write to the CIMPLICITY
directory — was exploited in real-world ICS attacks and was noted in the Havex/Dragonfly
campaign analysis. CVE-2023-3463 (stack-based buffer overflow in a CIMPLICITY service) allows
RCE as the service account. DCOM activation permissions for CIMPLICITY COM classes are
historically over-permissive.

**Safe-first testing.** Enumerate open ports passively (5159/5160 and 135/445). Check for SMB-
accessible project directories that expose `.cim` files — examining CimView files is a safe,
read-only exercise that reveals scripted logic, point names, and network topology. Do not
connect to the CIMPLICITY Server Manager with write intent or modify project files — CIMPLICITY
points are directly wired to PLCs and field devices. In aerospace and power plant deployments,
unexpected point writes constitute a life-safety risk.

**Remediation.** Apply GE Proficy security patches (Proficy eFix updates). Restrict SMB access
to CIMPLICITY project directories to named service accounts. Harden DCOM permissions for
CIMPLICITY COM classes. Review BCE scripts in CimView files for unauthorized shell command
calls. Segment CIMPLICITY Server Manager ports (5159/5160) to the OT VLAN. Implement application
allowlisting on all CIMPLICITY nodes.
