---
id: google_home_nest
technology: "Google Home / Nest"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["Nest", "Google Home", "cast_receiver"]
  markers: ["smartdevicemanagement.googleapis.com", "X-Goog-Api-Key", "_googlecast._tcp", "Chromecast"]
quick_wins:
  - { cmd: "dns-sd -B _googlecast._tcp local || avahi-browse -t _googlecast._tcp", safety: safe, note: "mDNS browse — enumerate Google/Nest/Chromecast devices on the local LAN." }
  - { cmd: "curl -sk 'https://smartdevicemanagement.googleapis.com/v1/enterprises/<projectId>/devices' -H 'Authorization: Bearer <oauth_token>'", safety: safe, note: "Smart Device Management API: list all Nest devices — read-only cloud enumeration." }
  - { cmd: "curl -sk 'https://smartdevicemanagement.googleapis.com/v1/enterprises/<projectId>/structures' -H 'Authorization: Bearer <oauth_token>'", safety: safe, note: "Enumerate home structures and rooms — read-only." }
  - { cmd: "curl -sk 'https://homegraph.googleapis.com/v1/devices:query' -H 'Authorization: Bearer <oauth_token>' -H 'Content-Type: application/json' -d '{\"agentUserId\":\"<uid>\"}'", safety: safe, note: "Home Graph query — enumerate all Google Home linked devices and states." }
  - { cmd: "curl -sk -X POST 'https://smartdevicemanagement.googleapis.com/v1/<deviceName>:executeCommand' -H 'Authorization: Bearer <oauth_token>' -d '{\"command\":\"sdm.devices.commands.ThermostatTemperatureSetpoint.SetHeat\",\"params\":{\"heatCelsius\":30}}'", safety: disruptive, note: "GATED — sets thermostat. Requires scoped OAuth and written authorization." }
references: ["CVE-2019-5765", "CVE-2020-9338", "Google Nest Security Advisory 2022"]
mitre: "T1078.004 / ICS T0866"
---
# Google Home / Nest

Google Home and Nest represent Google's consumer smart-home ecosystem, spanning Nest
thermostats, cameras, doorbells, speakers (Google Home/Mini/Hub), and Chromecast. The
control plane runs on the Google Smart Device Management (SDM) API and the Home Graph API,
both hosted at `*.googleapis.com`. Local device discovery uses mDNS (`_googlecast._tcp.local`).
Device control from third-party integrations requires OAuth2 with explicitly declared scopes.

**Why it matters offensively.** Google account compromise cascades to physical device control:
thermostats, door locks (via linked Yale/Nest x Yale), cameras, and alarms. OAuth tokens
issued to home-automation platforms (Home Assistant, SmartThings) with broad scopes
(`https://www.googleapis.com/auth/sdm.service`) are stored in config files and cloud secrets
— token exfiltration yields persistent access. Historically, Nest cameras have had
authentication weaknesses (CVE-2019-5765) allowing unauthorized livestream access.
Chromecast devices (`8008/tcp`, `8009/tcp`) have exposed video-cast and media-control
APIs to LAN attackers.

**Safe-first testing.** mDNS enumeration passively reveals all Nest/Google devices and their
friendly names. Cloud API GET calls (SDM `/devices`, `/structures`) enumerate the estate
without triggering device actions. Verify OAuth token scopes before any command issuance.

**Key risks.** Google account takeover → full device control; over-scoped third-party OAuth
tokens; Chromecast local API accessible without authentication on LAN; Nest camera firmware
vulnerabilities; cloud-dependency means no local fallback during Google outages. Remediation:
enforce 2-Step Verification on Google accounts, use minimally scoped OAuth, isolate Nest/Cast
devices on an IoT VLAN, and audit third-party app connections in Google Account settings.
