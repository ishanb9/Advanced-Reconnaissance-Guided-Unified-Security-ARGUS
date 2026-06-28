---
id: ge-ifix
technology: "GE iFIX SCADA/HMI"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [5135, 5136]
  banners: ["iFIX", "Proficy", "GE Vernova", "GE Digital", "iFIX SCADA"]
  markers: ["ifix", "proficy-ifix", "ge-ifix"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p5135,5136 -sV {host}", safety: safe, note: "Identify iFIX SCADAServer and Node Manager ports; version from banner." }
  - { cmd: "nmap -Pn -sT -p135 --script msrpc-enum {host}", safety: safe, note: "Enumerate DCOM/RPC endpoints; iFIX relies heavily on DCOM for inter-node communication." }
  - { cmd: "nmap -Pn -sT -p445 --script smb-security-mode,smb2-security-mode {host}", safety: safe, note: "iFIX nodes are Windows-based; SMB security mode reveals patch/configuration posture." }
  - { cmd: "<OPC-DA DCOM connection to read iFIX process database tags>", safety: intrusive, note: "GATED — OPC-DA tag read over DCOM is active; DCOM write calls command the process." }
references: ["CVE-2021-32954", "CVE-2020-6994", "CVE-2020-14479", "ICSA-21-145-02", "ICSA-20-063-02"]
mitre: "T0817 / ICS T0856"
---
# GE iFIX SCADA/HMI

GE iFIX (now under GE Vernova / Proficy brand) is a widely deployed SCADA/HMI platform used in
water/wastewater, power generation, and manufacturing. iFIX is built around a **process database
(PDB)** — a tag store that maps I/O from PLCs and field devices to real-time values used by
graphics, scripts, and historians. Inter-node communication uses proprietary **SCADAServer**
protocols (TCP 5135/5136) and OPC-DA via DCOM for third-party integration. The iFIX scripting
environment (Visual Basic for Applications) runs inside the runtime process and can write tags,
execute OS commands, and access the file system.

**Attack surface.** SCADAServer on 5135/5136 implements minimal authentication, and older
versions allow tag reads from any host in the same Windows network neighborhood by default.
DCOM-based OPC-DA access inherits Windows DCOM permission weaknesses — misconfigured launch/
activation permissions allow unauthenticated COM activation from remote hosts. CVE-2021-32954
(path traversal in iFIX workspace) allows arbitrary file write as the runtime user.
CVE-2020-6994 (buffer overflow in iFIX) allows RCE via crafted SCADAServer messages.
VBA scripts in `.grf` display files execute with the runtime's privileges — malicious display
files are a documented attack vector for ICS/OT malware.

**Safe-first testing.** Enumerate SCADAServer ports passively (banner grab, no protocol
interaction). Check DCOM launch/activation permissions for the iFixScaDAServer COM class
without connecting. Review SMB shares for accessible `.grf` display files or `.ini` node
configuration files. Do not initiate tag writes via SCADAServer or OPC-DA — iFIX tag writes
reach field devices directly and can cause unexpected process state changes in water or power
systems (life-safety risk).

**Remediation.** Apply all GE Proficy security patches. Restrict SCADAServer ports (5135/5136)
to the OT VLAN. Harden DCOM launch/activation permissions to deny remote unauthenticated access.
Disable VBA macro execution in iFIX display files if not operationally required. Implement
application allowlisting on iFIX nodes. Periodically audit `.grf` files for unauthorized script
content.
