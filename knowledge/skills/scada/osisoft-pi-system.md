---
id: osisoft-pi-system
technology: "OSIsoft / AVEVA PI System (Historian)"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [5450, 5457, 5459]
  banners: ["PI Server", "OSIsoft", "AVEVA PI", "PI Data Archive"]
  markers: ["piserver", "pi-sdk", "PIWebAPI", "/piwebapi/", "PI-Web-API"]
quick_wins:
  - { cmd: "curl -sk https://{host}/piwebapi/ -H 'Accept: application/json'", safety: safe, note: "PI Web API root endpoint; unauthenticated response reveals PI Server version, server name, and available endpoints." }
  - { cmd: "nmap -Pn -sT -p5450,5457,5459 -sV {host}", safety: safe, note: "PI Data Archive native ports; banner identifies PI Server version." }
  - { cmd: "curl -sk https://{host}/piwebapi/servers -H 'Accept: application/json'", safety: safe, note: "Enumerate connected PI Data Archive and Asset Framework servers via PI Web API — often unauthenticated in default config." }
  - { cmd: "<PI Web API /piwebapi/points query for tag enumeration>", safety: safe, note: "Read-only tag list; reveals process variable names, which can expose plant topology." }
  - { cmd: "<pi-sdk or PI OLEDB query to read historical tag values>", safety: intrusive, note: "GATED — reading historical data is non-destructive but active; some configurations require authentication." }
references: ["CVE-2023-31274", "CVE-2021-43894", "CVE-2020-25163", "ICSA-23-304-01", "ICSA-21-026-01"]
mitre: "T0817 / ICS T0852"
---
# OSIsoft / AVEVA PI System (Historian)

The OSIsoft PI System (now AVEVA PI, following the 2021 acquisition) is the de-facto standard
process historian used in power generation, oil & gas, chemical, water, and manufacturing
worldwide — estimated in over 22,000 plants across 140 countries. PI Data Archive stores
time-series process data (tags/points) at high frequency; PI Asset Framework (AF) adds an
object model layer. Access is provided via the native PI Data Archive protocol (TCP 5450, 5457,
5459), the PI Web API (HTTPS/REST), PI OLEDB, and PI SDK/AF SDK for Windows clients.

**Attack surface.** The PI Web API endpoint (`/piwebapi/`) often responds to unauthenticated
HTTP requests, revealing server name, PI Server version, and the full API endpoint tree in
default configurations. CVE-2020-25163 (PI Web API path traversal) allows unauthenticated
file reads. CVE-2021-43894 (PI Web API server-side request forgery) enables internal network
scanning from the PI server. CVE-2023-31274 (PI Data Archive authentication bypass) allows
unauthenticated read of tag values and metadata. PI Data Archive on 5450/tcp historically
allowed anonymous connections, enabling full tag namespace enumeration and bulk historical read.
The data itself — process variable histories — reveals plant operating conditions, production
rates, and maintenance patterns that support targeted physical attacks.

**Safe-first testing.** Start with the PI Web API root at `/piwebapi/` — the response is
typically safe to retrieve and reveals version and server info. Enumerate `/piwebapi/servers`
and `/piwebapi/assetservers` for connected infrastructure. Tag enumeration via
`/piwebapi/points` is read-only but may be sensitive (discloses plant topology). Do not
attempt to write tag values via PI Web API (`PUT /piwebapi/streams/{webId}/value`) — while
PI is a historian and not a control system, some deployments connect PI to real-time control
loops via PI-to-PI interfaces that feed setpoints.

**Remediation.** Enforce Kerberos or Windows Integrated Authentication on PI Web API (disable
anonymous access). Upgrade to PI Server 2018 SP3+ and PI Web API 2023 to address known CVEs.
Restrict native PI Data Archive ports (5450/5457/5459) to PI clients and connectors only.
Enable PI Server audit trails and alert on bulk tag reads. Apply AVEVA security patches and
review PI trust table entries for overly permissive host trusts.
