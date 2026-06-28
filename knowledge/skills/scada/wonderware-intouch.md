---
id: wonderware-intouch
technology: "AVEVA Wonderware InTouch HMI"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [5413]
  banners: ["Wonderware", "InTouch", "AVEVA"]
  markers: ["SuiteLink", "ArchestrA", "wonderware"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p5413 -sV {host}", safety: safe, note: "Identify SuiteLink (5413/tcp); banner reveals Wonderware/AVEVA InTouch version." }
  - { cmd: "nmap -Pn -sU -p137,138 --script nbstat {host}", safety: safe, note: "NetBIOS enumeration — InTouch relies on legacy Windows networking for node discovery." }
  - { cmd: "nmap -Pn -sT -p135 --script msrpc-enum {host}", safety: safe, note: "Enumerate RPC endpoints exposed by Wonderware/ArchestrA runtime services." }
  - { cmd: "<SuiteLink client connect to read tag values>", safety: intrusive, note: "GATED — SuiteLink API read of real-time tag data is active and leaves log entries." }
references: ["CVE-2021-33010", "CVE-2020-13575", "ICS-CERT ICSA-21-159-02", "AVEVA Security Bulletin AVEVA-2021-002"]
mitre: "T0817 / ICS T0856"
---
# AVEVA Wonderware InTouch HMI

Wonderware InTouch (now AVEVA InTouch) is one of the oldest and most widely deployed HMI
platforms, installed in tens of thousands of plants across oil & gas, pharma, power, and discrete
manufacturing. It communicates with PLCs and historians via **SuiteLink** (TCP 5413), a
proprietary AVEVA protocol, and via OPC-DA or OPC-UA bridges. The runtime and scripting engine
run as a Windows service, typically with elevated privileges, and the application is deeply
integrated with the Windows networking stack (NetBIOS, DCOM/RPC).

**Attack surface.** SuiteLink on 5413/tcp has no authentication by default; any host that can
reach the port can subscribe to real-time tag values and, on older versions, perform DCOM-based
tag writes. The ArchestrA Galaxy Repository (SQL Server back-end) is often on the same host,
expanding the SQL injection/privilege escalation surface. CVE-2020-13575 (heap overflow in
SuiteLink) and CVE-2021-33010 allow denial-of-service or RCE against the runtime process.
InTouch scripts run as VBScript inside the runtime — a compromised session means direct tag
write access to the process.

**Safe-first testing.** Enumerate open ports, particularly 5413/tcp and Windows RPC/SMB ports.
Banner-grab to confirm the InTouch version. Check for unauthenticated SuiteLink access with a
passive connection (subscribe-only) before any write attempt. Do not inject into SuiteLink write
commands or DCOM calls against live systems — InTouch tag writes directly command PLCs, which can
trip safety interlocks. This is a safety-of-life consideration in any process plant.

**Remediation.** Upgrade to AVEVA InTouch 2020 R2 SP1 or later. Firewall-restrict 5413/tcp to
engineering workstations only. Enable Windows Firewall on the HMI node. Disable NetBIOS over
TCP/IP where not required. Apply AVEVA Security Bulletin AVEVA-2021-002 patches. Enforce the
principle of least privilege for the InTouch runtime service account.
