---
id: opc-da-classic
technology: "OPC-DA / OPC Classic (DCOM)"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [135]
  banners: ["OPC", "OPC Server", "OPC Data Access"]
  markers: ["OPCEnum", "OPC.SimaticNET", "RSLinx OPC", "Kepware OPC", "Matrikon OPC"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p135 --script msrpc-enum {host}", safety: safe, note: "Enumerate DCOM/RPC endpoints on 135/tcp; OPC-DA servers register here as COM objects." }
  - { cmd: "python3 -m impacket.examples.rpcdump {host}", safety: safe, note: "Dump registered DCOM interfaces; OPC-DA servers appear as UUID-identified COM entries." }
  - { cmd: "nmap -Pn -sT -p135,49152-65535 -sV {host}", safety: safe, note: "DCOM uses dynamic high ports after negotiation on 135; scan to find the allocated OPC server ports." }
  - { cmd: "<OPC-DA DCOM client browse for OPCEnum server list>", safety: safe, note: "Read-only OPCEnum query to list registered OPC servers on the host — no tag interaction." }
  - { cmd: "<OPC-DA IOPCServer::Read call for tag values>", safety: intrusive, note: "GATED — reading OPC-DA item values is active; SyncWrite/AsyncWrite commands actuate the process." }
references: ["CVE-2008-4250", "CVE-2003-0352", "CISA ICS-ALERT-11-343-01", "OPC Foundation Security Advisory 2021"]
mitre: "T0817 / ICS T0852"
---
# OPC-DA / OPC Classic (DCOM)

OPC-DA (Data Access), part of the OPC Classic specification family (OPC DA, OPC HDA, OPC A&E),
is the legacy OPC standard that runs entirely over Microsoft **DCOM** (Distributed COM), using
TCP 135/tcp for endpoint mapping and dynamic high-numbered ports for data transfer. Introduced
in 1996, OPC-DA became the universal data exchange layer between SCADA/HMI software and PLCs,
field devices, and historians across all industrial vendors. Despite OPC-UA superseding it,
OPC-DA remains operational in the majority of installed SCADA systems globally because of the
embedded Windows hosts running HMI software that predates OPC-UA adoption.

**Attack surface.** OPC-DA inherits all DCOM attack surface: DCOM endpoint mapper on 135/tcp
reveals the full list of registered COM servers; misconfigured launch/activation permissions
allow unauthenticated COM activation from remote hosts (allowing unauthenticated OPC server
access); and OPCEnum (the OPC enumeration service) lists all registered OPC-DA servers on the
host without authentication on many Windows configurations. DCOM is a well-known lateral
movement vector — Pass-the-Hash, DCOM object abuse (MMC20.Application, ShellWindows) are
documented in ATT&CK. On OT networks, the DCOM RPC channel reaching the OPC server means
an attacker can subscribe to real-time tag values and — with SyncWrite — write process setpoints
to the underlying PLC. The Windows DCOM vulnerabilities that enabled worms like Blaster
(MS03-026) affected OPC servers running on unpatched Windows embedded systems still found in
many OT environments.

**Safe-first testing.** Use `msrpc-enum` or `impacket rpcdump` to non-intrusively enumerate
all DCOM endpoints on 135/tcp. Identify OPC-DA server CLSIDs from the RPC dump. Query
OPCEnum (if registered) to list OPC servers by display name — this is a safe read-only COM
call. Do not issue `IOPCServer::Read` or browse tag namespaces without explicit authorization.
Never issue any `SyncWrite` or `AsyncWrite` call against a live OPC-DA server — it directly
writes values to field devices. DCOM write access to OPC-DA servers in process plants is
equivalent to direct PLC command authority.

**Remediation.** Migrate OPC-DA integrations to OPC-UA (authenticated, encrypted, no DCOM
dependency). Where OPC-DA is required, harden DCOM: restrict COM launch/activation to named
service accounts in Component Services; enable Windows Firewall to block dynamic DCOM ports
from untrusted source IPs. Disable OPCEnum where not needed. Audit DCOM permissions quarterly.
Apply all Windows/DCOM patches on OT nodes (compensate with network controls where patching
risks process disruption). Monitor 135/tcp for connections from non-OPC-client source IPs.
