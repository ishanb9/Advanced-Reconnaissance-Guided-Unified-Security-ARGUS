---
id: lorawan
technology: "LoRaWAN"
domain: IoT
transport: rf
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: []
  markers: ["chirpstack", "lora-app-server"]
quick_wins:
  - { cmd: "python3 -m loratools scan --freq 868.1 --bw 125 --sf 7", safety: intrusive, note: "Passive LoRa frame capture (HackRF One / RTL-SDR required); logs Join-Request OTAAs with DevEUI, AppEUI, DevNonce." }
  - { cmd: "hackrf_transfer -r lorawan_capture.iq -f 868100000 -s 2000000 -g 40 -l 32 -a 1", safety: intrusive, note: "Raw IQ capture on EU868 uplink channel (HackRF One); feed into LAF/LoRattack for frame decode." }
  - { cmd: "python3 lorattack.py --mode replay --pcap join_request.pcap --freq 868.1 --sf 7", safety: intrusive, note: "v1.0 Join-Request replay (LAF / LoRattack + HackRF); exploits missing DevNonce uniqueness enforcement to force re-join." }
  - { cmd: "python3 lorattack.py --mode mic-brute --join-req join_request.pcap --wordlist appkeys.txt", safety: intrusive, note: "Offline AppKey brute-force from captured Join-Request MIC (CPU-only; no hardware needed after capture)." }
  - { cmd: "curl http://<chirpstack-host>:8080/api/applications -H 'Grpc-Metadata-Authorization: Bearer <token>'", safety: safe, note: "ChirpStack REST API enumeration — lists applications, device profiles, AppKeys if admin token is leaked (IP pivot from gateway)." }
references:
  - "CVE-2019-17357"
  - "DEF CON 27 — 'LoRa and LoRaWAN Security'"
  - "Black Hat USA 2018 — 'LoRaWAN Networks Susceptible to Hacking'"
  - "https://github.com/aijunbai/laf"
  - "https://github.com/rbaron/lorattack"
mitre: "T0854"
---
# LoRaWAN guidance

LoRaWAN is an open LPWAN (Low-Power Wide-Area Network) protocol stack built on top of Semtech's
LoRa chirp-spread-spectrum physical layer. It is designed for kilometre-range, battery-constrained
IoT sensors — smart meters, agriculture monitors, industrial telemetry — operating on unlicensed
sub-GHz ISM bands (EU868, US915, AS923). The LoRa PHY is purely RF; there is no IP socket to
connect to. The security boundary is the **AppKey** (root 128-bit AES key distributed out-of-band),
which seeds session key derivation during the Over-The-Air Activation (OTAA) Join handshake. The
network backend (e.g. ChirpStack, The Things Stack) is IP-reachable and presents a separate attack
surface once a gateway host is identified.

**Hardware required.** ARGUS surfaces this as operator guidance only — autonomous execution is
blocked because all LoRa attacks require a software-defined radio bridge.
Recommended hardware: **HackRF One** (TX + RX, required for replay/injection), **RTL-SDR v3**
(RX-only, sufficient for passive capture and MIC brute-force prep), or a **LimeSDR**.
Software toolchains: **LAF** (`laf` / `loratools`), **LoRattack**, **GNU Radio** with
`gr-lora` / `gr-lorawan`, and **Wireshark** with the LoRaWAN dissector.

**Key attack vectors.**
*v1.0 Join-Request replay* — LoRaWAN 1.0 does not enforce uniqueness of the DevNonce counter;
a captured Join-Request frame can be retransmitted verbatim (HackRF One at correct frequency,
spreading factor, and bandwidth) to trigger a re-join and force the device to regenerate session
keys, momentarily breaking uplink connectivity and potentially resetting frame counters.
*AppKey brute-force from Join MIC* — the Join-Request MIC is computed as `AES-CMAC(AppKey,
MHDR|AppEUI|DevEUI|DevNonce)`; because DevEUI, AppEUI, and DevNonce are all plaintext in the
captured frame, an offline dictionary or exhaustive search over a weak or default AppKey space can
recover the root key entirely from CPU, with no further RF interaction.
*Backend pivot* — LoRaWAN gateways forward decoded frames to a network server over IP
(typically ChirpStack on 8080/tcp, MQTT 1883/tcp, or gRPCWeb 443); if the gateway host is in
scope and exposes the ChirpStack REST or gRPC API with a default or leaked admin token, an
attacker can enumerate all registered devices and — critically — export stored AppKeys, achieving
full session-key derivation without touching the air.

**Safe-first approach and remediation.** Begin with **passive-only** IQ capture (RTL-SDR RX) and
offline analysis before any transmission. Injection and replay (requiring HackRF TX) must be
scoped and gated — even a single replayed Join-Request causes a live sensor outage.
Remediation priorities: (1) upgrade all devices to **LoRaWAN 1.1** which enforces DevNonce
uniqueness and adds a Join counter to prevent replay; (2) provision AppKeys from a hardware secure
element or HSM rather than firmware constants or stickers on the device; (3) enforce frame-counter
integrity and reject frames with replayed FCnt; (4) harden the network-server backend — segment
ChirpStack behind an authenticating reverse proxy, rotate API tokens, and monitor for unexpected
OTAA joins or frame-counter resets as indicators of replay. ARGUS will flag ChirpStack/LNS markers
in the IP scan surface and surface this guidance; a credentialed operator with the named RF
hardware must execute the air-side steps.
