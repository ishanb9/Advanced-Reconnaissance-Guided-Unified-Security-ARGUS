---
id: wifi
technology: "Wi-Fi (WPA2/WPA3)"
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
  - { cmd: "airmon-ng start wlan0 && airodump-ng wlan0mon", safety: intrusive, note: "Enable monitor mode (requires a monitor-mode NIC such as Alfa AWUS036ACH) and passively capture all visible BSSIDs, channels, and client associations. Passive sniff — no frames injected." }
  - { cmd: "hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3 --filterlist_ap=targets.txt --filtermode=2", safety: intrusive, note: "Capture PMKID frames and EAPOL handshakes against listed APs. Requires monitor-mode NIC and physical proximity to the target AP." }
  - { cmd: "hcxpcapngtool -o hashes.22000 capture.pcapng && hashcat -m 22000 hashes.22000 wordlist.txt -r rules/best64.rule", safety: intrusive, note: "Convert pcapng to hashcat 22000 format and crack WPA2/WPA3 PMKIDs or handshakes offline. GPU recommended (RTX 3080+). No radio contact required during crack phase." }
  - { cmd: "airbase-ng -e 'TargetSSID' -c 6 -a <spoofed_bssid> wlan0mon", safety: intrusive, note: "Stand up a rogue AP (evil-twin) on the target SSID using airbase-ng. Combine with hostapd-wpe or eaphammer for RADIUS credential harvest against 802.1X networks. Requires monitor+injection-capable NIC." }
  - { cmd: "eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid CorpNet --creds", safety: intrusive, note: "Evil-twin targeting 802.1X/PEAP clients; captures MSCHAPv2 credentials relayed to attacker-controlled RADIUS on UDP 1812. Requires injection-capable NIC and root privileges." }
references:
  - "CVE-2019-13377"
  - "CVE-2020-26139"
  - "CVE-2022-47522"
  - "DEF CON 22 — Defeating PPTP VPNs and WPA2 Enterprise via MS-CHAPv2 (Marlinspike)"
  - "Black Hat USA 2019 — Dragonblood: Analysing WPA3 (Vanhoef & Ronen)"
  - "Black Hat USA 2018 — PMKID Attack (Jens Steube / Hashcat)"
mitre: "T1040"
---
# Wi-Fi (WPA2/WPA3) guidance

Wi-Fi networks are among the most prevalent radio-frequency attack surfaces in IoT and enterprise environments. WPA2-Personal (PSK) and WPA2-Enterprise (802.1X/RADIUS) both have well-documented attack paths: PMKID extraction requires capturing a single EAPOL frame from the AP beacon without waiting for a full four-way handshake, drastically lowering capture time. WPA3-SAE (Dragonfly) mitigates offline dictionary attacks but introduced its own side-channel and downgrade issues (CVE-2019-13377, "Dragonblood"). IoT devices frequently ship with hardcoded or default PSKs that appear in common wordlists, making offline cracking viable even against WPA2 deployments with strong passphrases if the device vendor is known.

**Hardware required.** ARGUS surfaces Wi-Fi findings as operator guidance because all active techniques require a radio bridge that ARGUS does not possess. A **monitor-mode and frame-injection-capable NIC** is mandatory — recommended adapters include the Alfa AWUS036ACH (802.11ac, MT7612U chipset) or Alfa AWUS036ACHM (MT7610U). For 802.1X / RADIUS evil-twin attacks a second NIC acting as the rogue AP uplink is helpful. Offline cracking is CPU/GPU-bound; a dedicated GPU rig (RTX 3080 or better) with hashcat is strongly recommended for large WPA2 hash sets. No SDR (HackRF/RTL-SDR) is needed for standard Wi-Fi; those tools are relevant for sub-GHz or Bluetooth work.

**Safe-first approach.** Begin with **passive enumeration only**: run `airodump-ng` in monitor mode to survey SSIDs, BSSIDs, channels, vendor OUIs, and associated client MACs without transmitting. Review the beacon information elements for supported RSN ciphers (CCMP vs TKIP) and WPA3 transition-mode flags. Only escalate to active capture (`hcxdumptool`) after scoping is confirmed — this tool issues targeted probe requests and may trigger IDS/WIDS alerts. Evil-twin and deauthentication attacks (CVE-2020-26139) are **actively disruptive**: they sever legitimate client sessions and should be gated behind explicit written authorization. RADIUS credential harvesting via eaphammer captures cleartext or NetNTLM hashes from 802.1X supplicants; the downstream blast radius is significant and must be scoped carefully.

**Key risks and remediation.** WPA2-PSK deployments are vulnerable to offline PMKID/handshake cracking; migrate to WPA3-SAE or enforce per-device PSKs with a RADIUS back-end to limit lateral movement from a single compromised credential. WPA2-Enterprise with PEAP/MSCHAPv2 is vulnerable to evil-twin RADIUS harvest (MSCHAPv2 is cryptographically broken — CVE-2012-2001); enforce certificate validation on supplicants and prefer EAP-TLS with mutual certificate authentication. Ensure WIDS/WIPS sensors alert on rogue APs, deauth floods, and PMKID capture patterns. Segment IoT Wi-Fi onto isolated VLANs with no lateral access to OT or corporate networks. ARGUS will surface this skill when Wi-Fi IoT gateways, access points, or 802.11 markers are detected in scope; the operator must attach the appropriate hardware bridge and execute the listed commands manually.
