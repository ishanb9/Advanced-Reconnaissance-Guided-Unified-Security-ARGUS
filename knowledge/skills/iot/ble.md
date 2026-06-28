---
id: ble
technology: "Bluetooth Low Energy (BLE)"
domain: IoT
transport: rf
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "hcitool lescan --duplicates", safety: intrusive, note: "Passive BLE advertisement scan — requires Bluetooth adapter (e.g. CSR/Cambridge Silicon Radio USB dongle, Ubertooth One). Lists advertising devices (MAC, name, AD type)." }
  - { cmd: "gatttool -b <BDADDR> -I  # then: connect, primary, char-read-hnd <handle>", safety: intrusive, note: "Interactive GATT exploration — enumerate services/characteristics and read attribute values. Requires Linux BlueZ stack + Bluetooth adapter." }
  - { cmd: "bettercap -eval 'ble.recon on; events.stream on'", safety: intrusive, note: "BLE passive recon with bettercap — enumerates advertisers, UUIDs, RSSI. Requires supported USB Bluetooth adapter (e.g. Ubertooth One or CSR dongle)." }
  - { cmd: "ubertooth-btle -f -A 37", safety: intrusive, note: "Ubertooth One promiscuous follow-on channel 37 — captures raw BLE advertisement and connection PDUs for offline analysis with Wireshark (Ubertooth hardware required)." }
  - { cmd: "bettercap -eval 'ble.recon on; ble.enum <BDADDR>'", safety: intrusive, note: "Full GATT service/characteristic enumeration of a specific device — reads all readable attributes. Requires bettercap + Bluetooth adapter." }
references: ["CVE-2019-9506", "CVE-2020-12965", "CVE-2021-28139", "DEF CON 27 - 'KNOB Attack'", "Black Hat USA 2020 - SweynTooth"]
mitre: "T0848"
---
# Bluetooth Low Energy (BLE) guidance

Bluetooth Low Energy (BLE, Bluetooth 4.0+) is the dominant short-range radio protocol for IoT
devices: fitness trackers, smart locks, medical sensors, industrial beacons, BLE-to-IP gateways,
and embedded controllers all rely on it. BLE operates in the **2.4 GHz ISM band** across 40
channels (37 advertising channels + 37 data channels) with a typical range of 10–100 m. Unlike
classic Bluetooth, BLE uses a connection-oriented GATT (Generic Attribute Profile) model: a
central (phone, hub) reads and writes **characteristics** on a peripheral (sensor, actuator). The
lack of mandatory authentication and the prevalence of the **Just-Works** pairing mode (which
provides no MITM protection) means many deployed devices accept unauthenticated GATT reads and
writes from any nearby radio.

**Hardware required.** ARGUS surfaces this as operator guidance — it cannot auto-execute BLE
attacks without a hardware bridge. The minimum toolkit is a **Linux host with BlueZ** and a
supported USB Bluetooth adapter (CSR/Qualcomm-based dongles, e.g. ASUS BT-400). For passive
full-packet capture, an **Ubertooth One** (open-source 2.4 GHz transceiver) is required — it
enables promiscuous sniffing of BLE advertising PDUs and connection packets for Wireshark
analysis. **bettercap** (v2+) unifies recon, enumeration, and MITM in a single tool and runs
on any Bluetooth-capable Linux host. For advanced injection or replay, a second BLE adapter or
Ubertooth is needed.

**Safe-first approach.** Always begin with **passive advertisement scanning** (`hcitool lescan`,
`bettercap ble.recon on`, or Ubertooth passive capture) before connecting to any device.
Advertisement frames reveal device name, manufacturer-specific data, service UUIDs, and TX
power without establishing a connection or alerting the target. Only after mapping the attack
surface should an operator connect (`gatttool` / `bettercap ble.enum`) and attempt characteristic
reads. **GATT writes to control-plane characteristics (e.g. lock/unlock, set-point, firmware OTA
trigger) are disruptive and require explicit, scoped authorization** — a write to the wrong handle
can brick a sensor or actuate a physical lock. Exploit attempts (KNOB, SweynTooth) should be
conducted in an isolated lab environment against a cloned device, never against production assets
without a tested rollback plan.

**Key risks and known vulnerabilities.** The **KNOB attack (CVE-2019-9506)** reduces Bluetooth
entropy negotiation to 1 byte, enabling brute-force of session keys in real time — it affects
both classic Bluetooth and BLE connections that delegate key negotiation to the BR/EDR layer.
**SweynTooth (2020)** is a family of 12+ BLE stack vulnerabilities (buffer overflows, deadlocks,
LLID crashes) affecting SoCs from Texas Instruments, Nordic, Dialog, STMicroelectronics, and
others — many IoT and medical devices remain unpatched. **CVE-2021-28139** (NimBLE out-of-bounds
write) can achieve RCE on ESP32-based devices. Just-Works pairing exposes any device to passive
eavesdropping and MITM via a rogue BLE central. Insecure GATT implementations frequently expose
sensitive characteristics (device credentials, firmware OTA, physical actuators) without any
authentication requirement.

**Remediation.** Require **LE Secure Connections with Numeric Comparison or Passkey Entry**
pairing — eliminate Just-Works on any device that controls a physical actuator or stores
credentials. Apply vendor BLE stack patches (Texas Instruments, Nordic, Cypress, STM all issued
SweynTooth patches in 2020–2021). Restrict GATT characteristic permissions to authenticated and
encrypted reads/writes. Implement connection whitelisting (privacy mode + IRK-based address
resolution) to reject connections from unknown centrals. For medical or safety-critical BLE
devices, mandate FIPS 140-2 validated BLE stacks and conduct periodic RF sweeps to detect rogue
centrals. Map findings to the CISA IoT security guidance and relevant ICS-CERT advisories rather
than relying on CVSS alone, which consistently under-scores RF-layer vulnerabilities.
