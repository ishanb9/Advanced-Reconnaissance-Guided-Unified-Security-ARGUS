---
id: samsung_smartthings
technology: "Samsung SmartThings"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["SmartThings"]
  markers: ["api.smartthings.com", "graph.api.smartthings.com", "X-ST-CORRELATION", "smartthings"]
quick_wins:
  - { cmd: "curl -sk https://api.smartthings.com/v1/devices -H 'Authorization: Bearer <PAT>'", safety: safe, note: "List all devices registered to the account — read-only cloud API enumeration." }
  - { cmd: "curl -sk https://api.smartthings.com/v1/locations -H 'Authorization: Bearer <PAT>'", safety: safe, note: "Enumerate locations, rooms, and linked hubs — read-only." }
  - { cmd: "curl -sk https://api.smartthings.com/v1/rules -H 'Authorization: Bearer <PAT>'", safety: safe, note: "List automation rules — exposes logic and schedules without triggering them." }
  - { cmd: "curl -sk https://api.smartthings.com/v1/devices/<deviceId>/status -H 'Authorization: Bearer <PAT>'", safety: safe, note: "Read current device state (lock, switch, sensor) — read-only." }
  - { cmd: "curl -sk -X POST https://api.smartthings.com/v1/devices/<deviceId>/commands -H 'Authorization: Bearer <PAT>' -d '{\"commands\":[{\"component\":\"main\",\"capability\":\"lock\",\"command\":\"unlock\"}]}'", safety: disruptive, note: "GATED — unlocks a door. Requires explicit authorization." }
references: ["CVE-2018-3911", "CVE-2016-6553", "SmartThings Security Bulletin 2020"]
mitre: "T1078.004 / ICS T0866"
---
# Samsung SmartThings

Samsung SmartThings is a cloud-managed home-automation platform using a SaaS API
(`api.smartthings.com`) as its control plane. The SmartThings hub (v2/v3/Aeotec) pairs with
Zigbee, Z-Wave, and LAN devices; all command routing passes through the Samsung cloud even
for local devices. Developers and automations authenticate via Personal Access Tokens (PATs)
or OAuth2 apps issued through the SmartThings Developer Portal.

**Why it matters offensively.** SmartThings PATs scoped to `r:devices:*` and `x:devices:*`
(execute) grant enumeration and full command authority over every paired device. These tokens
appear in GitHub repositories, home-automation blog posts, and `.env` files. The cloud
intermediary means a compromised token works from anywhere on the internet. OAuth2 apps
registered by third parties can request broad device scopes — over-privileged integrations
expand the blast radius. Early SmartThings classic-platform research demonstrated that
third-party SmartApps could escalate privileges beyond declared scopes.

**Safe-first testing.** Enumerate with GET calls: `/v1/devices`, `/v1/locations`,
`/v1/scenes`, `/v1/rules`. None of these trigger device actions. Verify token scope via
`/v1/tokenIntrospect` before any write operation.

**Key risks.** Token leakage in logs and source code; over-permissioned OAuth apps; no
hardware root of trust for hub firmware updates; cloud dependency means a Samsung service
outage removes local control; account takeover cascades to physical devices. Remediation:
use narrowly scoped PATs, rotate tokens, enable MFA on the Samsung account, audit OAuth
app grants, and restrict integrations to vendor-verified apps.
