---
id: hubitat_elevation
technology: "Hubitat Elevation"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["Hubitat"]
  markers: ["/hub/login", "/apps/api/", "X-Hubitat", "/ui2/"]
quick_wins:
  - { cmd: "curl -sk http://{host}:8080/hub/login | grep -i 'hubitat\\|version'", safety: safe, note: "Confirm Hubitat login page and version string — unauthenticated banner grab." }
  - { cmd: "nmap -Pn -sT -p8080,8443 --script http-title,http-headers {host}", safety: safe, note: "Port/banner enumeration — identify hub model and firmware version." }
  - { cmd: "curl -sk 'http://{host}:8080/apps/api/<appId>/devices?access_token=<token>'", safety: safe, note: "Maker API: list all registered devices and capabilities — read-only." }
  - { cmd: "curl -sk 'http://{host}:8080/apps/api/<appId>/devices/<deviceId>/commands?access_token=<token>'", safety: intrusive, note: "Enumerate available commands for a device — discovery step, no state change." }
  - { cmd: "curl -sk 'http://{host}:8080/apps/api/<appId>/devices/<deviceId>/lock?access_token=<token>'", safety: disruptive, note: "GATED — actuates a lock. Requires scoped written authorization." }
references: ["CVE-2020-17057", "Hubitat Security Advisory 2021-03"]
mitre: "T1190 / ICS T0866"
---
# Hubitat Elevation

Hubitat Elevation is a local-processing Z-Wave/Zigbee hub sold as a dedicated appliance
(C-7, C-8 models). Unlike cloud-dependent hubs, all automation logic runs on-device;
however, the built-in web UI and Maker API still expose **8080/tcp** (HTTP) and optionally
**8443/tcp** (HTTPS) to the LAN. The Maker API, enabled by administrators to allow REST
control of devices, accepts an `access_token` query parameter — effectively a bearer token
that grants full device read/write.

**Why it matters offensively.** The Maker API token is frequently hard-coded in dashboards,
scripts, and third-party integrations. A compromised LAN device or SSRF condition in any
integrated app can reach 8080 and enumerate or actuate every paired Z-Wave/Zigbee device
(locks, thermostats, garage doors). The web UI uses HTTP by default, exposing credentials and
session cookies to LAN sniffing. Hubitat also supports app installation from third-party repos
("HPM"), creating a supply-chain risk.

**Safe-first testing.** Use the Maker API with GET calls only: `/apps/api/<id>/devices` lists
all paired devices and their capabilities without triggering any actions. Compare firmware on
`/hub/details` against the vendor release page to identify unpatched devices.

**Key risks.** Unencrypted HTTP session for admin UI; Maker API token exposure in URLs and
logs; unauthenticated local network access when firewall rules are absent; third-party app
supply-chain; lack of rate-limiting on the API. Remediation: enable HTTPS on the hub, rotate
Maker API tokens, restrict 8080/8443 with LAN-segment firewall rules, audit installed apps.
