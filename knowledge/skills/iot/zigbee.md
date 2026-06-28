---
id: zigbee
technology: "Zigbee (802.15.4)"
domain: IoT
transport: rf
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: []
  markers: ["zigbee2mqtt"]
quick_wins:
  - { cmd: "zbstumbler", safety: intrusive, note: "Passive beacon scan on all 802.15.4 channels (11-26, 2.4 GHz). Requires KillerBee-compatible hardware (ApiMote, RZUSBSTICK, TelosB). Lists PAN IDs, coordinator addresses, channel in use." }
  - { cmd: "zbdump -c 15 -w capture.pcap", safety: intrusive, note: "Passive capture of all 802.15.4 frames on channel 15 (adjust per zbstumbler). KillerBee hardware required. Captures join handshakes and NWK frames for offline key extraction." }
  - { cmd: "zbstumbler -c <channel>; zbdump -c <channel> -f 'wpan.frame_type == 0x3' -w joins.pcap", safety: intrusive, note: "Targeted capture of association (join) frames only. If TC link key is ZigBeeAlliance09 (default), Wireshark decrypts NWK key from the Transport-Key frame automatically." }
  - { cmd: "zbwireshark -c <channel>", safety: intrusive, note: "Live Wireshark feed via KillerBee pipe. Set Zigbee decryption key to 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39 in Wireshark Edit→Preferences→Protocols→ZigBee to decrypt in real time." }
references: ["CVE-2020-27890", "CVE-2019-15911", "DEF CON 22 — KillerBee: Practical ZigBee Exploitation Framework", "Black Hat USA 2015 — Hacking ZigBee Networks", "NIST SP 800-187"]
mitre: "T0842"
---
# Zigbee (802.15.4) guidance

Zigbee is a low-power mesh radio protocol built on IEEE 802.15.4, operating primarily in the 2.4 GHz ISM band across channels 11–26. It is pervasive in smart-home devices (bulbs, locks, sensors, thermostats), building automation (HVAC, access control), and industrial IoT. A Zigbee network consists of a coordinator (Trust Centre, TC), routers, and end devices. Security depends on two layered keys: a **Trust Centre link key** used to deliver the **Network key (NWK key)** at join time, and the NWK key used to encrypt all application traffic. The critical weakness is that most deployments ship with the well-known default TC link key `ZigBeeAlliance09` (hex `5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39`). An attacker who captures a single device-join exchange can decrypt the Transport-Key frame and recover the live NWK key, giving full visibility into all network traffic and the ability to inject or replay frames.

**Hardware required.** ARGUS surfaces this as operator guidance only — automated execution requires a hardware RF bridge that is NOT part of the ARGUS sensor stack. The primary toolchain is **KillerBee** (Python framework) with supported 802.15.4 USB hardware: ApiMote v4beta, Atmel RZUSBSTICK, MoteIV TelosB, or compatible CC2531 dongles flashed with sniffer firmware. `zbstumbler` performs passive channel-walk beacon discovery; `zbdump` captures raw PCAP for Wireshark analysis with the Zigbee dissector and pre-loaded decryption keys. A **HackRF One** or **YARD Stick One** can also receive raw 802.15.4 frames via GNU Radio, but KillerBee hardware offers purpose-built frame injection capability. **Flipper Zero** with a Sub-GHz module can scan sub-GHz Zigbee variants (868/915 MHz) used in some EU/US deployments.

**Safe-first approach.** Always begin with passive scanning (`zbstumbler`, `zbdump`) before considering any injection. Passive capture cannot disrupt network operation. Only after confirming scope and written authorisation should an operator attempt active techniques such as forcing a re-join (deauth) to capture a new key exchange, replaying frames, or injecting malformed packets — these are intrusive and may lock out legitimate devices or trigger alarm states. Document the PAN ID, extended PAN ID, coordinator IEEE address, and active channel before any further action. If the default TC link key is confirmed via Wireshark decryption, this constitutes a critical finding: the NWK key for all devices on the network is exposed to any passive observer within RF range.

**Remediation.** Replace the default TC link key `ZigBeeAlliance09` with a unique, random 128-bit key provisioned out-of-band. Enable **Zigbee 3.0 install codes** (device-specific pre-shared keys) so the TC key material is never broadcast. Rotate the NWK key periodically and after any device is decommissioned. Where possible, deploy Zigbee coordinators in shielded enclosures or areas that limit RF leakage outside the facility perimeter. For high-security environments, consider migrating to Zigbee Green Power with Enhanced Security or to a protocol with mandatory mutual authentication (e.g. Thread/Matter). Map findings to ICS-CERT advisories and NIST SP 800-187 for remediation priority guidance.
