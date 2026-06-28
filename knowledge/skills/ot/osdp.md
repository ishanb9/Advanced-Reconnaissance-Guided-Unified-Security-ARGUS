---
id: osdp
technology: "OSDP access control"
domain: OT
transport: serial
safety_class: intrusive
severity: critical
life_safety: true
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "python3 -m osdp_utils sniff --device /dev/ttyUSB0 --baud 9600", safety: intrusive, note: "Passive RS-485 tap via USB-to-RS-485 adapter; captures PD<->CP exchanges. Requires physical access to the wiring harness." }
  - { cmd: "python3 -m osdp_utils probe --device /dev/ttyUSB0 --addr 0x7F", safety: intrusive, note: "Send osdp_ID poll to broadcast address to enumerate attached Peripheral Devices and firmware versions." }
  - { cmd: "python3 -m osdp_utils check-scbk-d --device /dev/ttyUSB0 --addr 0", safety: intrusive, note: "Attempt Secure Channel using SCBK-D (all-zeros default key, OSDP v2.2); confirms DEF CON 31 finding. Flags whether CP accepted the default key." }
  - { cmd: "python3 -m osdp_utils replay-card --device /dev/ttyUSB0 --raw <hex_card_data>", safety: intrusive, note: "Replay a previously captured osdp_RAW or osdp_CARD message; aborts immediately if Secure Channel is active and key unknown." }
references: ["DEF CON 31 - Bishop Fox 'OSDP Insecurity'", "CVE-2023-28654", "ICS-CERT ICSA-23-131-02", "SIA OSDP v2.2 § 6.6 SCBK-D"]
mitre: "T0812"
---
# OSDP access control guidance

Open Supervised Device Protocol (OSDP) is an IEC 60839-11-5 standard serial bus protocol used
to link physical-access control panels (Control Panels, CP) with readers and credential-processing
devices (Peripheral Devices, PD) — card readers, PIN pads, and biometric scanners. It runs over
**RS-485** at typical baud rates of 9 600–115 200. OSDP v2.x introduced an optional **Secure
Channel** layer (AES-128-CMAC) intended to replace the earlier cleartext exchanges; however,
the specification includes a mandatory fallback key named **SCBK-D** (Secure Channel Base Key —
Default) whose value is the 16-byte all-zeros string. DEF CON 31 (2023, Bishop Fox) demonstrated
that a significant fraction of deployed readers accept SCBK-D indefinitely, allowing an attacker
with bus access to negotiate a "secure" channel with a known key, then inject arbitrary credential
messages and unlock doors — including **life-safety egress doors** where a false unlock can impede
emergency mustering or enable tailgating into secured areas. Because OSDP controls physical locks,
every finding in this skill carries a `life_safety: true` classification.

**Hardware required.** ARGUS surfaces this as operator guidance only — auto-execution is not
possible without a hardware bridge. Minimum kit: a **USB-to-RS-485 converter** (e.g. FTDI
FT232H breakout, DFRobot RS-485 shield) clipped onto the 4-wire RS-485 bus between CP and PD.
A **Flipper Zero** with the OSDP community app can perform passive sniffing and basic enumeration
from a portable form factor. The Bishop Fox `osdp-utils` Python library (or equivalent tooling)
drives protocol interaction from a laptop. Physical access to the wiring closet or door frame
back-box is mandatory; no remote path exists without an out-of-band IP gateway.

**Safe-first approach.** Begin with **passive sniffing only** — tap the RS-485 differential pair
with a high-impedance connection and capture traffic for several minutes to map PD addresses,
baud rate, and whether Secure Channel `SCS_BEG` / `SCS_END` framing is present. Record the raw
CMAC values but do not inject. Only proceed to active probing (osdp_ID poll, SCBK-D challenge)
after written scope confirmation and with the physical-security team on standby, because even a
malformed frame can cause a PD to latch into an error state and fail-open or fail-secure
unexpectedly. **Never** replay credential messages or send osdp_OUT (output control) commands
against a life-safety or fire-egress door without an operator physically present at the door and
explicit authorisation — an uncontrolled unlock can violate fire and safety codes.

**Key risks and remediation.** The core vulnerability is SCBK-D: if a CP or PD accepts it after
initial installation, the Secure Channel provides false confidence. Operators should verify via
the CP management console that every PD has been provisioned with a site-specific SCBK and that
SCBK-D fallback is disabled in firmware. Firmware updates from HID, Allegion, and other vendors
released post-CVE-2023-28654 add a SCBK-D lockout option — apply them. Beyond the key issue,
OSDP lacks mutual authentication of the CP itself, so a rogue CP can be substituted on the bus;
mitigate by physically securing wiring conduits and using tamper-detect supervision loops.
Map findings to MITRE ATT&CK for ICS **T0812 (Default Credentials)** and to the relevant CISA
ICS advisory (ICSA-23-131-02). Engage the physical-security and facilities teams alongside the
cyber team — remediation requires reprogramming readers in the field, not just a software patch.
