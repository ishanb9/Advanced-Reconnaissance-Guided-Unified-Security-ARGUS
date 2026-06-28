---
id: smarthome_hubs
technology: "Smart-home hubs (Hue/SmartThings/Tuya/Home Assistant)"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [6668, 1900, 5353, 8123, 39500]
  banners: ["Philips hue", "SmartThings", "tuyaLocal", "Home Assistant", "tuya", "hue-bridgeid"]
  markers: ["X-Hue-Bridgeid", "internalipaddress", "tuyaCAKey", "hassio", "homeassistant/", "NOTIFY * HTTP/1.1", "urn:schemas-upnp-org:device:Basic:1"]
quick_wins:
  - { cmd: "nmap -Pn -sU -p1900 --script upnp-info {host}", safety: safe, note: "SSDP/UPnP enumeration — retrieves device model, vendor, firmware, and service list. Read-only." }
  - { cmd: "nmap -Pn -sT -p5353 --script dns-service-discovery {host}", safety: safe, note: "mDNS/Bonjour scan — discovers _hue._tcp, _smartthings._tcp, _homeassistant._tcp service records. Read-only." }
  - { cmd: "curl -sk http://{host}/api/config | python3 -m json.tool", safety: safe, note: "Hue bridge unauthenticated /api/config — leaks bridgeid, model, SW version, and zigbee channel without a token." }
  - { cmd: "curl -sk http://{host}:8123/api/ -H 'Authorization: Bearer <token>'", safety: safe, note: "Home Assistant REST API root — confirms version and authentication posture. Token required; bearer probe only." }
  - { cmd: "python3 -c \"import socket,json; s=socket.socket(); s.connect(('{host}',6668)); s.send(b'{\"gwId\":\"\",\"devId\":\"\",\"uid\":\"\",\"t\":\"0\"}'); print(s.recv(1024))\"", safety: intrusive, note: "Tuya LAN protocol probe on 6668/tcp — banner grab identifies device type and reveals whether the local key is enforced. Active connection." }
  - { cmd: "curl -sk http://{host}/api/<username>/config | python3 -m json.tool", safety: intrusive, note: "Hue authenticated config dump — enumerates all lights, groups, scenes, schedules, and linked user tokens if username is known or guessed." }
  - { cmd: "curl -sk -X POST http://{host}/api -d '{\"devicetype\":\"pentest#probe\"}' | python3 -m json.tool", safety: intrusive, note: "Hue button-press token creation — registers a new API user if the bridge link-button is active or was recently pressed. Token exposure." }
references: ["CVE-2020-6007", "CVE-2017-16709", "CVE-2022-39071", "CVE-2023-24023"]
mitre: "T0866 / T1557"
---
# Smart-home hubs (Hue/SmartThings/Tuya/Home Assistant)

Smart-home hubs are always-on, network-attached controllers that bridge consumer IoT devices
(lights, plugs, sensors, locks, thermostats) to cloud services and mobile apps. Philips Hue
exposes an unauthenticated REST API on port 80/tcp; SmartThings and Tuya depend on cloud relay
but also expose local LAN endpoints; Home Assistant runs a full web application on port 8123/tcp.
All four ecosystems advertise themselves via **mDNS (_tcp service records on 5353/udp)** and
**SSDP/UPnP (1900/udp)** making passive discovery trivial from any host on the same L2 segment.

**Why it matters.** These hubs hold long-lived API tokens, Zigbee/Z-Wave pairing keys, and
sometimes credentials for linked cloud accounts (Google Home, Amazon Alexa, Samsung). The Hue
`/api/config` endpoint leaks bridge identity and firmware unauthenticated; the Tuya LAN protocol
on **6668/tcp** transmits device commands with AES-128-ECB and a per-device "local key" that
is often recoverable from cloud account credentials. A compromised hub is a pivot to every
device it controls — including smart locks — and an RF gateway into Zigbee/Z-Wave meshes
reachable only via radio.

**Safe-first testing.** Start with passive mDNS/SSDP enumeration (`dns-service-discovery`,
`upnp-info`) and the Hue unauthenticated `/api/config` — all three are read-only and do not
alter device state. Probe 6668/tcp with a raw TCP connect only to banner-grab; do not send
valid encrypted Tuya commands unless the engagement scope explicitly covers device actuation.
Before issuing any POST to `/api` on Hue, confirm the engagement permits token creation; that
request registers a persistent API credential that persists across reboots until manually
revoked. Home Assistant's `/api/` root reveals version; avoid issuing service-call endpoints
(`/api/services/*`) without explicit authorization, as they directly control downstream
physical devices.

**Key risks and remediation.** Token exposure is the primary finding class: Hue stores tokens
in plaintext in `/api/<username>/`, HA long-lived tokens appear in `configuration.yaml` and
SQLite databases, and Tuya local keys can be extracted from cloud account traffic. The IP-to-RF
pivot risk is real — once a hub is owned, an attacker can inject Zigbee frames or Z-Wave
commands with no radio hardware beyond the hub itself. Remediation: isolate hub LAN traffic to
a dedicated IoT VLAN with no lateral access to IT segments; disable UPnP/SSDP if unused; enable
HA authentication and rotate long-lived tokens regularly; update hub firmware to patch known
Hue Zigbee stack vulnerabilities (CVE-2020-6007); and audit linked cloud OAuth grants for stale
or overly permissive delegations.
