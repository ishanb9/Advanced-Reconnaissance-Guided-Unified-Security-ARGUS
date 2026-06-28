---
id: vera_micasaverde
technology: "Vera / MiCasaVerde"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [3480]
  banners: ["MiCasaVerde", "Vera", "Luup"]
  markers: ["/data_request?id=", "vera", "luup_request", "MiOS", "eZLO"]
quick_wins:
  - { cmd: "curl -sk 'http://{host}:3480/data_request?id=user_data' | python3 -m json.tool", safety: safe, note: "Vera Luup API: dump user_data — full device, scene, and room inventory, unauthenticated on older firmware." }
  - { cmd: "curl -sk 'http://{host}:3480/data_request?id=status' | python3 -m json.tool", safety: safe, note: "Retrieve all device states — read-only status enumeration, unauthenticated by default." }
  - { cmd: "nmap -Pn -sT -p3480,3000 --script http-title,banner {host}", safety: safe, note: "Port/banner scan — confirm Vera firmware version and Luup service presence." }
  - { cmd: "curl -sk 'http://{host}:3480/data_request?id=lu_sdata' | python3 -m json.tool", safety: safe, note: "Request scene and device data (lu_sdata) — full automation inventory, read-only." }
  - { cmd: "curl -sk 'http://{host}:3480/data_request?id=lu_action&DeviceNum=<n>&serviceId=urn:upnp-org:serviceId:SwitchPower1&action=SetTarget&newTargetValue=0'", safety: disruptive, note: "GATED — sends UPnP action to switch off a device. Requires written authorization." }
references: ["CVE-2019-17274", "CVE-2019-17275", "CVE-2020-11692", "TrendMicro Research: Vera Edge Vulnerabilities 2019"]
mitre: "T1190 / ICS T0866"
---
# Vera / MiCasaVerde

Vera (MiCasaVerde, now eZLO) is a consumer Z-Wave and Zigbee hub platform with models
spanning Vera Lite, Vera Edge, Vera Plus, and Vera Secure. The Luup (Little Universal UPnP)
engine exposes a local REST API on **3480/tcp** (HTTP) and **3000/tcp** (legacy). The Luup
API's `data_request` endpoint accepts device control and enumeration requests in URL query
parameters. Older Vera firmware versions (prior to 7.0.29) served the API without any
authentication, making full device inventory and control available to any LAN host.

**Why it matters offensively.** TrendMicro Research published detailed vulnerability analysis
in 2019 covering Vera Edge: unauthenticated remote code execution via the Luup API
(CVE-2019-17274/17275), allowing an attacker to execute Lua scripts as root on the hub.
CVE-2020-11692 affected Vera Plus/Secure with an authentication bypass in the cloud relay
(mios.com). The `id=user_data` endpoint leaks the complete house topology, device names,
room structure, and Z-Wave device IDs — an attacker can map the home before any active
testing. Internet-exposed Vera hubs are detectable on Shodan via port 3480 and the
characteristic `data_request` URI.

**Safe-first testing.** The `id=user_data` and `id=status` Luup API calls are read-only and
reveal the full device estate. Check firmware version in the `user_data` response against
eZLO's changelog. Do not issue `lu_action` requests without explicit scope — these directly
command Z-Wave devices (locks, switches, thermostats).

**Key risks.** Default unauthenticated Luup API; RCE via Lua script injection on unpatched
firmware; cloud relay authentication bypass; internet-exposed 3480/tcp; eZLO cloud
dependency with limited transparency. Remediation: update Vera firmware to current eZLO
release, require authentication in the Luup API settings, block 3480/tcp at the perimeter,
segment the hub on an IoT VLAN, and consider migration to actively-maintained open-source
platforms.
