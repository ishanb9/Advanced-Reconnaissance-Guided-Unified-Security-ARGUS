---
id: mdns
technology: "mDNS / DNS-SD"
domain: IoT
safety_class: safe
severity: medium
life_safety: false
match:
  ports: [5353]
  banners: ["mdns", "_tcp.local", "_udp.local", "dns-sd"]
  markers: ["_services._dns-sd._udp.local", "_http._tcp.local", "_workstation._tcp.local", "_ipp._tcp.local", "_airplay._tcp.local"]
quick_wins:
  - { cmd: "nmap -sU -p 5353 --script dns-service-discovery {host}", safety: safe, note: "Enumerate mDNS/DNS-SD services advertised by the host" }
  - { cmd: "avahi-browse -a -t -r 2>/dev/null || dns-sd -B _services._dns-sd._udp local", safety: safe, note: "Passive DNS-SD service inventory on local segment" }
  - { cmd: "nmap -sU -p 5353 --script mdns-name-info {host}", safety: safe, note: "Resolve .local hostnames and extract device metadata" }
  - { cmd: "python3 -m impacket.examples.mdns_poison --interface eth0", safety: intrusive, note: "Responder-style mDNS poisoning to intercept .local resolution — captures credentials/NTLMv2 hashes" }
  - { cmd: "Responder.py -I eth0 -wrf", safety: intrusive, note: "Poison mDNS + LLMNR + NBT-NS simultaneously; harvests NTLM challenge-responses on the segment" }
references: ["CVE-2020-9454", "CVE-2020-3657", "CVE-2021-28918"]
mitre: "T1557.001"
---
# mDNS / DNS-SD Guidance

Multicast DNS (mDNS, RFC 6762) and DNS-SD (RFC 6763) allow zero-configuration service advertisement and discovery on the local link using UDP port 5353. Devices broadcast their hostnames and service records (.local TLD) without requiring a central DNS server. IoT endpoints — smart speakers, printers, IP cameras, build/lab equipment, and embedded Linux systems — rely heavily on mDNS to publish capabilities such as `_http._tcp`, `_ssh._tcp`, `_airplay._tcp`, and vendor-specific service types.

From an authorized pentest perspective, mDNS provides a passive, read-only inventory mechanism with no authentication boundary. A single `avahi-browse -a -t -r` or the `dns-service-discovery` NSE script against the multicast group (224.0.0.251) reveals hostnames, service types, IP addresses, and TXT records containing firmware versions, device models, and configuration hints — all without sending a single packet to the target device. This passive enumeration phase should always precede active scanning in IoT/OT environments.

The primary active risk is mDNS poisoning (analogous to Responder's LLMNR/NBT-NS poisoning). Because mDNS has no authentication, any host on the segment can respond to a `.local` query before the legitimate device does. Tools like Responder or purpose-built scripts can intercept Windows credential negotiations (NTLMv2), redirect HTTP/SMB traffic to attacker-controlled services, or perform man-in-the-middle attacks against IoT control-plane communications. On flat IoT network segments — common in operational environments — this can affect hundreds of devices simultaneously. This technique is marked intrusive because it injects spoofed DNS responses and may disrupt legitimate device discovery.

Remediation: segment IoT devices onto dedicated VLANs with multicast isolation to prevent cross-zone mDNS traffic; disable mDNS on Windows hosts where not required (disable the `DNS Client` multicast listener or deploy group policy); deploy 802.1X port authentication to limit who can participate in the multicast domain. Where mDNS must traverse zones, use a unicast DNS-SD proxy with strict allowlisting of permitted service types.
