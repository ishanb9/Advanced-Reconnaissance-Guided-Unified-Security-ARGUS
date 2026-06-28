---
id: port_terminal_tos
technology: "Port / Terminal Operating System (TOS)"
domain: OT
category: marine
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1433, 5432]
  banners: ["Navis", "Tideworks", "Konecranes", "SPARCS", "TOS", "Port Community", "CargoWise", "Jade Logistics"]
  markers: ["navis-n4", "sparcs-n4", "tideworks", "jade-tos", "terminal-os", "portis"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p1433,5432 --script banner {host}", safety: safe, note: "Enumerate TOS database ports — identify MSSQL (Navis N4/SPARCS) or PostgreSQL (Tideworks) version and authentication state. Read-only." }
  - { cmd: "nmap -Pn -sV --open --script http-title,http-auth-finder {host}", safety: safe, note: "Fingerprint TOS web application on any exposed port — identify Navis N4, SPARCS, Tideworks login page, authentication mechanism, and HTTP method exposure." }
  - { cmd: "nmap -Pn -p1433 --script ms-sql-info,ms-sql-config {host}", safety: safe, note: "Enumerate MSSQL database backing the TOS — identify version, database names, and sa account status. Read-only." }
  - { cmd: "<modify container locations, crane movement orders, or gate release records in TOS on {host}>", safety: intrusive, note: "GATED — false container manifests or crane command injection can disrupt port operations and create physical hazards in the yard. Requires explicit authorization." }
references: ["CVE-2021-44228 (Log4Shell in Navis N4)", "2021 South Africa Transnet Ransomware", "ENISA Port Cybersecurity 2019", "IMO FAL.5/Circ.39-Rev.2"]
mitre: "T0890 / T1190"
---
# Port / Terminal Operating System (TOS)

A Terminal Operating System (TOS) is the central enterprise system managing all operations in
a container terminal, bulk terminal, or ro-ro terminal: vessel planning (stowage, bay plans),
crane allocation and movement orders, yard management (container locations, reefer monitoring),
gate management (truck entry/exit, container release), and rail operations. Major TOS vendors
include Navis (N4/SPARCS, now Cargotec), Tideworks (Carrix), Konecranes (Bromma), CargoWise
(WiseTech), and Jade Logistics. The TOS is an enterprise Java/web application backed by Oracle,
MSSQL, or PostgreSQL, exposed on internal port networks and increasingly cloud-hosted or
SaaS-delivered. Automated crane and vehicle systems (AGVs, ASCs) receive movement orders from
the TOS over proprietary APIs or SPARCS crane booking interfaces.

**Why it matters.** TOS compromise translates directly into port-wide disruption. The 2021
Transnet ransomware attack (believed Cl0p group) crippled South African container port operations
for weeks, requiring manual container tracking. The 2017 NotPetya attack on Maersk destroyed
TOS instances across 76 port terminals globally. TOS systems frequently run outdated Java
versions (Log4Shell — CVE-2021-44228 — affected Navis N4 instances globally) and use shared
service accounts between terminal operator workstations and crane PLC interfaces, making lateral
movement from TOS compromise to crane control a real attack path.

**Safe-first testing.** Enumerate the TOS web application login page for vendor fingerprints
(Navis N4, Tideworks), probe database ports for version and authentication state, and check
the Java application server for Log4j version (HTTP header injection `${jndi:ldap://...}`
in a monitored lab context only). Review whether the TOS API endpoints (crane booking, gate
release) require authentication on all methods — REST/SOAP APIs frequently have unauthenticated
endpoints in older TOS versions. Identify whether AGV/crane controller networks are on the same
subnet as the TOS application tier or isolated. **Do not** modify container records, crane
orders, or gate release authorizations without explicit scoped authorization — false bay plan
data can cause container stack instability and crane incidents in an active yard.

**Remediation.** Apply Log4j and TOS vendor patches immediately; segment TOS application tier
from crane control networks with an OT DMZ; enforce MFA on all TOS user and API accounts;
implement allowlisting on crane booking API callers; conduct annual penetration testing of
TOS web application aligned with ENISA Port Cybersecurity guidelines and IMO FAL.5/Circ.39
maritime cyber risk management framework. Maintain offline backup of container manifests and
bay plans to enable manual operations during TOS unavailability.
