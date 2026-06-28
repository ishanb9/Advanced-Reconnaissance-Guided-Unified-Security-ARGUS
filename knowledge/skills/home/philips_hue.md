---
id: philips_hue
technology: "Philips Hue Bridge"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: medium
life_safety: false
match:
  ports: []
  banners: ["Philips hue"]
  markers: ["/api/newdeveloper", "/description.xml", "IpBridge", "hue personal wireless lighting", "X-HUE"]
quick_wins:
  - { cmd: "curl -sk http://{host}/description.xml | grep -E 'modelName|serialNumber|firmwareVersion'", safety: safe, note: "UPnP description.xml — reveals bridge model, serial, firmware version, unauthenticated." }
  - { cmd: "curl -sk http://{host}/api/newdeveloper/config | python3 -m json.tool", safety: safe, note: "Unauthenticated config dump — exposes bridge name, IP, MAC, software version, timezone." }
  - { cmd: "curl -sk http://{host}/api/<apiKey>/lights | python3 -m json.tool", safety: safe, note: "Enumerate all lights with names, states, and capabilities — read-only authenticated." }
  - { cmd: "curl -sk http://{host}/api/<apiKey>/groups | python3 -m json.tool", safety: safe, note: "List light groups and scenes — reveals room layout and schedules, read-only." }
  - { cmd: "nmap -Pn -sT -p80,443 --script http-title,http-headers {host}", safety: safe, note: "HTTP banner and headers — confirm Hue bridge presence and firmware version." }
  - { cmd: "curl -sk -X PUT http://{host}/api/<apiKey>/lights/<id>/state -d '{\"on\":false}'", safety: disruptive, note: "GATED — turns off a light. Requires valid API key and written authorization." }
references: ["CVE-2020-6007", "CVE-2018-16732", "CVE-2022-34820", "Signify Security Advisory 2020"]
mitre: "T1190 / ICS T0866"
---
# Philips Hue Bridge

The Philips Hue Bridge (Signify, models BSHB 2.1/2.0/1.0) is the central controller for the
Hue smart lighting ecosystem, communicating with bulbs over Zigbee and exposing a local REST
API on ports **80/tcp** and **443/tcp**. The Hue API (`/api/<apiKey>/`) is the primary
control interface: all lights, groups, scenes, and schedules are managed through it. The bridge
also responds to UPnP/SSDP and publishes a UPnP device description at `/description.xml`.

**Why it matters offensively.** The `/api/newdeveloper/config` endpoint leaks bridge metadata
(name, IP, MAC, software version) without any authentication. CVE-2020-6007 was a
Zigbee-layer heap overflow in the Hue Bridge that was weaponized by Check Point Research:
a malicious Zigbee packet from a replaced attacker-controlled bulb could propagate from the
Zigbee radio layer to the bridge firmware, achieving LAN-side RCE. CVE-2018-16732 allowed
unauthenticated API key creation on older firmware via a logic flaw in the pairing mechanism.
API keys are long-lived and stored in plain text on many integration platforms.

**Safe-first testing.** The `/api/newdeveloper/config` endpoint is always unauthenticated and
safe to probe — it reveals firmware version for comparison against Signify advisories.
Authenticated GET calls (`/api/<key>/lights`, `/groups`, `/scenes`) enumerate the full
lighting estate without triggering changes. Verify firmware version against Signify's
security bulletins as the first step.

**Key risks.** Long-lived API keys stored in plain text (Home Assistant, Hue apps); Zigbee
radio attack surface (bulb replacement attack, CVE-2020-6007); no authentication on metadata
endpoint; UPnP exposure enabling LAN-adjacent enumeration; cloud-bridge connection via
Signify servers for remote access. Remediation: update bridge firmware to latest Signify
release (auto-updates are on by default), restrict bridge network access to trusted LAN
segment, rotate API keys periodically, and disable UPnP if remote discovery is not needed.
