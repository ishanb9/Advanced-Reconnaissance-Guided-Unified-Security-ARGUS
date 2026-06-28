---
id: ring_arlo_cameras
technology: "Ring / Arlo IP Cameras"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["Ring", "Arlo", "netgear-arlo"]
  markers: ["api.ring.com", "api.arlo.com", "my.arlo.com", "X-Ring-", "Ring-Session", "arloq", "ringdoorbell"]
quick_wins:
  - { cmd: "curl -sk -X POST 'https://oauth.ring.com/oauth/token' -d 'grant_type=password&username=<email>&password=<pass>&client_id=ring_official_android&scope=client'", safety: safe, note: "Ring OAuth token probe — confirms credential validity; no camera access until token is used." }
  - { cmd: "curl -sk 'https://api.ring.com/clients_api/ring_devices' -H 'Authorization: Bearer <token>'", safety: safe, note: "Enumerate all Ring devices (doorbells, cameras, alarms) on the account — read-only." }
  - { cmd: "curl -sk 'https://api.ring.com/clients_api/locations' -H 'Authorization: Bearer <token>'", safety: safe, note: "List Ring locations with address, geofence, and linked device IDs — read-only." }
  - { cmd: "curl -sk 'https://myapi.arlo.com/hmsweb/login/v2' -X POST -d '{\"email\":\"<email>\",\"password\":\"<pass>\"}'", safety: safe, note: "Arlo session probe — confirms cred validity; enumerates linked camera count in response." }
  - { cmd: "curl -sk 'https://myapi.arlo.com/hmsweb/users/devices' -H 'Authorization: <arloToken>'", safety: safe, note: "Enumerate all Arlo cameras, base stations, and SmartHub devices — read-only." }
references: ["CVE-2020-17057", "CVE-2020-9395", "Ring Law Enforcement Data Sharing Controversy 2022", "Arlo Security Advisory 2023"]
mitre: "T1078.004 / T1125"
---
# Ring / Arlo IP Cameras

Ring (Amazon subsidiary) and Arlo (Netgear spin-off) are the two largest consumer IP camera
and video doorbell platforms globally, with tens of millions of deployed units. Both operate
through cloud APIs: Ring at `api.ring.com` and Arlo at `myapi.arlo.com`/`api.arlo.com`.
Camera streams, motion events, and recordings are stored in vendor clouds; local API access is
available via RTSP on some Arlo models. Ring Alarm also integrates a physical security system
with door/window sensors, motion detectors, and professional monitoring.

**Why it matters offensively.** Account compromise grants access to live video feeds, motion
history, and home-occupancy patterns — intelligence that supports burglary planning or
stalking. Ring's OAuth2 flow has been targeted by credential-stuffing attacks; Ring users have
reported unauthorized access incidents at scale. Arlo's session API (`/hmsweb/login/v2`)
returns device inventory and streaming tokens. Both platforms use third-party push
notifications that may leak metadata. Arlo Pro cameras support local RTSP (`rtsp://` on
LAN) which is unauthenticated on some firmware versions. Ring Alarm's Z-Wave integration
has been researched for radio-layer attacks.

**Safe-first testing.** Use credential-validation probes against public OAuth/login endpoints
(GET-equivalent flows only — do not trigger camera activations, siren tests, or alarm modes).
Enumerate device inventory and location metadata without requesting streaming tokens or
accessing live feeds unless explicitly scoped.

**Key risks.** Account takeover via credential stuffing; unauthenticated local RTSP on some
Arlo firmware; third-party Ring Skill / IFTTT integrations with broad access; law enforcement
data-sharing APIs (Ring Neighbors) expanding the data exposure model; physical doorbell
hardware accessible from outside the perimeter. Remediation: enforce MFA on both Ring and
Arlo accounts, use unique strong passwords, disable RTSP if not needed, audit third-party
app connections, and update camera firmware automatically.
