---
id: aveva-system-platform
technology: "AVEVA System Platform (ArchestrA)"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [5413, 5480, 4322]
  banners: ["ArchestrA", "System Platform", "AVEVA", "Galaxy"]
  markers: ["GRAccess", "aaGateway", "ArchestrA.GRService"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p5413,5480,4322,135 -sV {host}", safety: safe, note: "Identify Galaxy Repository, SuiteLink, and ArchestrA platform services by port/banner." }
  - { cmd: "nmap -Pn -sT -p1433 --script ms-sql-info {host}", safety: safe, note: "Fingerprint the SQL Server instance hosting the Galaxy Repository database." }
  - { cmd: "nmap -Pn -sT -p135 --script msrpc-enum {host}", safety: safe, note: "Enumerate RPC/DCOM endpoints used by ArchestrA platform services." }
  - { cmd: "<GRAccess API enumeration of deployed objects>", safety: intrusive, note: "GATED — enumerating the Galaxy Repository object model reveals plant topology and tag names." }
references: ["CVE-2021-33010", "CVE-2020-13575", "ICSA-21-159-02", "AVEVA Security Bulletin AVEVA-2021-002"]
mitre: "T0817 / ICS T0856"
---
# AVEVA System Platform (ArchestrA)

AVEVA System Platform — formerly Wonderware System Platform — is an industrial automation
platform built on the ArchestrA object model. It provides a centralized Galaxy Repository
(SQL Server) that stores all plant objects, graphics, scripts, and I/O assignments. Platform
nodes include the Application Server (Object Server), Historian, and HMI/InTouch clients all
communicating over a proprietary DCOM/RPC stack and SuiteLink (TCP 5413). Large facilities may
run dozens of geographically distributed Object Servers, all synchronized through the Galaxy.

**Attack surface.** The Galaxy Repository (SQL Server, typically TCP 1433) is the crown jewel:
read access reveals the entire plant topology, tag namespace, and scripted logic. The ArchestrA
GRService and aaGateway expose RPC endpoints that allow object import/export — if writable,
an attacker can deploy malicious graphics scripts that execute inside HMI runtime with the
ability to write tags to the PLC. DCOM misconfigurations on the platform nodes are common because
the product requires broad COM/DCOM permissions by design. SuiteLink's lack of authentication
(same as InTouch) extends to all Application Server-bound data subscriptions.

**Safe-first testing.** Enumerate services passively (port scan + banner grab). Identify the
Galaxy Repository SQL instance without authentication. Check whether the SQL Server instance
allows Windows Authentication with the current probe identity. Do not connect to the GRAccess
API for write operations or import objects — modifying the Galaxy Repository during a live
campaign can cause object redeployment to all connected Object Servers, causing a plant-wide
disruption. This is a life-safety risk in continuous process environments.

**Remediation.** Segment the Galaxy Repository SQL Server from all non-engineering networks.
Restrict DCOM permissions to required service accounts only. Apply AVEVA patching advisories
promptly. Enable Windows Defender Credential Guard to mitigate DCOM/Pass-the-Hash paths. Log
and alert on GRService object import events (Windows Event 4688 + ArchestrA audit log).
