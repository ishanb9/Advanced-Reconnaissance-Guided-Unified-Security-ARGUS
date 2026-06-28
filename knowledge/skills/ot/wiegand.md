---
id: wiegand
technology: "Legacy Wiegand"
domain: OT
transport: serial
safety_class: intrusive
severity: high
life_safety: true
match:
  ports: []
  banners: []
  markers: []
quick_wins:
  - { cmd: "proxmark3 hf search", safety: intrusive, note: "Proxmark3 RDV4 passive scan — identifies card frequency (125 kHz EM4100/HID Prox vs 13.56 MHz MIFARE). Read-only field interrogation." }
  - { cmd: "proxmark3 lf hid read", safety: intrusive, note: "Proxmark3: passively read HID 26-bit or 35-bit Wiegand facility code + card number from a presented card. Requires physical proximity (~5–10 cm)." }
  - { cmd: "proxmark3 lf hid clone -r <raw>", safety: intrusive, note: "Clone a captured HID credential onto a T5577 blank card. GATED — replay to a reader constitutes physical access bypass; requires explicit scope authorization." }
  - { cmd: "espkey-decode -f <capture.bin>", safety: intrusive, note: "ESPKey inline implant: decode Wiegand bit-stream captured from the data0/data1 pair on a reader harness. Requires physical implant installation." }
  - { cmd: "flipper wiegand read", safety: intrusive, note: "Flipper Zero RFID app: passive read of 125 kHz Wiegand cards (HID, EM4100, Indala). Pocket-sized; useful for opportunistic credential harvesting in scope." }
references:
  - "DEF CON 23 — 'Hacking Access Control' (Eric Evenchick)"
  - "DEF CON 18 — 'Wiegand Vulnerabilities' (Brad Antoniewicz)"
  - "Black Hat USA 2013 — 'Physical Security Assessment with ESPKey'"
  - "CVE-2019-6544"
mitre: "T0822"
---
# Legacy Wiegand guidance

Wiegand is a serial signalling protocol introduced in the 1980s that carries facility code and card number as a 26-bit (or extended 34/35/37-bit) unencrypted pulse stream over two data lines (DATA0, DATA1) between a badge reader and an access control panel. The protocol has **no encryption, no mutual authentication, and no replay protection** — once a credential is observed on the bus it can be replayed indefinitely to the same or any compatible reader. Because Wiegand gates physical doors — including server rooms, data centres, and life-safety-critical areas — successful exploitation translates directly to physical access bypass, making this a life_safety concern even when the underlying IT network is unaffected.

**Hardware required.** ARGUS surfaces this as operator guidance; execution requires named hardware bridges. The primary tools are: **Proxmark3 RDV4** (gold standard for 125 kHz HID Prox/EM4100 read, clone, and emulation; also handles 13.56 MHz MIFARE), **ESPKey** (a small ESP8266-based inline implant that physically taps into the four-wire reader harness behind a wall plate to silently log every badge swipe to flash/Wi-Fi), **Flipper Zero** (pocket-sized multi-protocol RFID reader for HID, EM4100, and Indala at 125 kHz), and a **T5577 blank card** for cloning captured credentials. None of these attacks can be executed over an IP network — they all require direct physical proximity to a reader or access to the wiring behind it.

**Safe-first approach.** Begin with **passive enumeration only**: use Proxmark3 `hf search` or `lf hid read` to identify the card technology and capture a single example credential without transmitting any signal to the panel. Confirm scope explicitly covers physical access testing before proceeding to clone or replay. An ESPKey implant must be installed inside the reader housing — this requires opening a wall-mounted unit, which is a physical action that should be coordinated with the facilities team and documented to avoid triggering alarm events. Never replay a cloned credential to a door that controls life-safety systems (fire egress, medical areas, emergency exits) without an authorised attendant physically present, as a failed replay attempt can trigger lockout. Wiegand attacks are intrusive by nature — there is no read-only equivalent once you pass passive sniffing.

**Key risks and remediation.** A single skim-and-replay attack is sufficient to defeat any Wiegand-only installation because every swipe leaks the full credential unencrypted. Organisations should: (1) upgrade to OSDP (Open Supervised Device Protocol) readers with AES-128 encrypted channels and bi-directional tamper monitoring, which eliminates the bus-sniff attack surface; (2) layer multi-factor authentication (PIN + badge, or mobile credential with challenge-response) so that a cloned card alone is insufficient; (3) enable reader tamper detection and alarm on any physical opening of the reader housing; (4) audit reader wiring runs — ESPKey implants fit inside standard single-gang boxes and are invisible without opening the cover; (5) segment the access control network from the corporate LAN and monitor for anomalous badge patterns (rapid multi-door access, off-hours swipes). MITRE ICS T0822 (Exploitation of Remote Services) is cited as the closest mapping; the attack chain also applies to MITRE ATT&CK T1078 (Valid Accounts) when the cloned credential grants logical access via physical bypass.
