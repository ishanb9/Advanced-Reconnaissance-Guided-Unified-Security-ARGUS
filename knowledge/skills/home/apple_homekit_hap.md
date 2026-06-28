---
id: apple_homekit_hap
technology: "Apple HomeKit / HAP"
domain: IoT
category: home
transport: ip
safety_class: safe
severity: medium
life_safety: false
match:
  ports: [51826, 51827]
  banners: ["HAP", "_hap._tcp"]
  markers: ["_hap._tcp.local", "X-HAP-", "PairSetup", "PairVerify", "hap-nodejs"]
quick_wins:
  - { cmd: "dns-sd -B _hap._tcp local 2>/dev/null || avahi-browse -t _hap._tcp", safety: safe, note: "mDNS browse — enumerate all HomeKit accessories on the local LAN, unauthenticated." }
  - { cmd: "nmap -Pn -sT -p51826,51827 {host} --script=banner", safety: safe, note: "Probe HAP TCP port — confirm accessory presence and firmware hints." }
  - { cmd: "python3 -c \"import asyncio; from aiohomekit import Controller; ...\"", safety: safe, note: "HAP pairing probe — check if accessory is already paired (reduces attack surface) or unpaired." }
  - { cmd: "nmap -Pn --script=dns-service-discovery {host}", safety: safe, note: "Discover HAP service metadata (name, model, firmware, pairing state) via DNS-SD TXT records." }
references: ["CVE-2017-13080", "CVE-2019-8508", "HomeKit Accessory Protocol Specification R15"]
mitre: "T1040 / ICS T0888"
---
# Apple HomeKit / HAP

Apple HomeKit is a smart-home framework that defines the HomeKit Accessory Protocol (HAP)
for secure device pairing and control. HAP operates over both BLE and IP (TCP port **51826**
or **51827**). Accessories advertise via mDNS (`_hap._tcp.local`) and require a Curve25519
key-exchange pairing step protected by SRP-6a. Once paired, all communication is encrypted
and authenticated — however, the surrounding ecosystem introduces practical weaknesses.

**Why it matters offensively.** Unpaired accessories are visible on the LAN via mDNS and
accept the default eight-digit setup code (often printed on the device label, e.g., `111-11-111`).
An attacker who resets or discovers the setup code can pair and permanently control the device.
Third-party HAP-compatible bridges (Homebridge, Home Assistant HAP integration) widen the
attack surface: they run on non-Apple hardware without Apple's Secure Enclave and may expose
HAP over insecure channels. CVE-2019-8508 affected some third-party HomeKit bridges, allowing
unauthorized control via an unauthenticated REST endpoint.

**Safe-first testing.** mDNS enumeration with `avahi-browse` or `dns-sd` is passive and
reveals all accessible accessory names, models, firmware versions, and pairing state (the
`sf` TXT flag: `sf=1` = unpaired/vulnerable). Do not attempt to send HAP pair-setup requests
without authorization — this constitutes unauthorized access to a control system.

**Key risks.** Default/printed setup codes; third-party bridge software lacking Secure Enclave
protections; LAN-adjacent adversary can enumerate and attempt pairing; Homebridge instances
running on shared or Internet-exposed hosts; firmware update supply chain for non-Apple
accessories. Remediation: change default setup codes, use a dedicated IoT VLAN, keep
Homebridge behind authentication, and update accessory firmware regularly.
