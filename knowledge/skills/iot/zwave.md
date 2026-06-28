---
id: zwave
technology: "Z-Wave (G.9959)"
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
  - { cmd: "python3 -m scapy; from scapy.contrib.zwave import *; sniff(iface='HackRF', prn=lambda p: p.show())", safety: intrusive, note: "Passive ZWave frame capture via HackRF + scapy-radio; requires HackRF One + scapy-radio patched Scapy." }
  - { cmd: "grc-zwave-rx --freq 908.42e6 --samp-rate 2e6 | python3 zwave_parse.py", safety: intrusive, note: "GNU Radio ZWave companion receiver at 908.42 MHz (US); swap 868.42 MHz for EU band. Decodes unencrypted S0/plaintext frames." }
  - { cmd: "python3 EZWave/ezwave.py --interface hackrf --freq 908420000 --scan", safety: intrusive, note: "EZ-Wave active node discovery; enumerates NodeIDs, Home IDs, and command classes. Requires HackRF One." }
  - { cmd: "python3 EZWave/ezwave.py --interface hackrf --attack zshave --target <NodeID>", safety: intrusive, note: "Z-Shave S2-to-S0 downgrade attack (CVE-2017-9021): forces re-inclusion at legacy S0 security level. Disruptive — removes active S2 pairing." }
references: ["CVE-2017-9021", "CVE-2022-31178", "DEF CON 25 - Z-Wave ZShave", "Black Hat USA 2013 - Z-Wave Hacking", "SEC Consult Advisory 2017-008"]
mitre: "T0843"
---
# Z-Wave (G.9959) guidance

Z-Wave is a sub-GHz proprietary mesh radio protocol standardised as ITU-T G.9959 and used in tens
of millions of smart-home devices: door locks, thermostats, garage controllers, smoke detectors, and
alarm sensors. It operates at **908.42 MHz in North America** and **868.42 MHz in Europe** (and
national variants between 865–926 MHz), with a maximum PHY throughput of 100 kbps. The protocol
supports two security layers: the legacy **S0** framework (AES-128 ECB with a static network key
exchanged in plaintext during pairing) and the current **S2** framework (Elliptic Curve
Diffie-Hellman key exchange, AES-128 CCM, and device authentication codes). Many deployed devices
remain on S0 or support downgrade to it.

**Hardware required.** ARGUS surfaces Z-Wave as operator guidance only — execution requires a
software-defined radio capable of the sub-GHz band. The standard attack platform is a
**HackRF One** (TX/RX, 1 MHz–6 GHz) paired with the **EZ-Wave** toolkit or **scapy-radio** (a
Scapy fork with GNU Radio back-ends). An **RTL-SDR** (RTL2832U-based dongle, ~$25) can receive
and decode Z-Wave frames passively but cannot transmit; it is sufficient for reconnaissance.
A **Flipper Zero** with its built-in sub-GHz radio can receive and replay Z-Wave frames at basic
level. For controller-side interaction, a **Z-Wave USB stick** (UZB-7, Aeotec Z-Stick Gen5) running
**OpenZWave** or **Z-Wave JS** provides a higher-layer API but is limited to frames the controller
itself is paired to receive.

**Safe-first approach — passive before active.** Begin with passive capture: tune a HackRF or
RTL-SDR to 908.42 MHz (US) or 868.42 MHz (EU), capture IQ samples, and decode frames with the GNU
Radio ZWave companion block or `grc-zwave-rx`. This reveals Home IDs, Node IDs, command classes,
and — for S0 traffic — the unencrypted payload (S0 encrypts only the application layer; the S0
network key itself is transmitted in plaintext during initial inclusion). Move to active interaction
only with explicit written authorisation: active node enumeration (EZ-Wave `--scan`) and especially
the **Z-Shave downgrade attack** are intrusive and disruptive. Z-Shave (CVE-2017-9021) exploits the
Z-Wave controller's willingness to accept an S2 device re-including at S0 — the attacker jams the
S2 inclusion exchange and replays a lower-security join, permanently downgrading the device's
security class and exposing its traffic to the known S0 key weaknesses. This breaks the active
pairing and requires physical user intervention to restore S2.

**Key risks and remediation.** An unauthenticated attacker within radio range (~30 m indoors,
~100 m line-of-sight) can: (1) eavesdrop all plaintext S0 or unencrypted frames; (2) replay
captured command frames against locks and actuators; (3) execute Z-Shave to downgrade S2 nodes;
(4) inject malformed frames to crash vulnerable controller firmware. For remediation, ensure all
devices include under **S2 Authenticated** or **S2 Access Control** (not S0 or Unauthenticated);
disable re-inclusion without physical button press on the device; apply vendor firmware updates
addressing CVE-2022-31178 (Z-Wave long-range spoofing); and monitor for unexpected re-inclusion
events in the Z-Wave controller log (Z-Wave JS UI surfaces these). ARGUS cannot auto-execute Z-Wave
attacks — the operator must attach the appropriate hardware bridge (HackRF/RTL-SDR/USB stick) and
invoke EZ-Wave or scapy-radio manually using the guidance above.
