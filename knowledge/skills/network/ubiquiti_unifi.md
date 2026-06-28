---
id: ubiquiti_unifi
technology: "Ubiquiti UniFi / EdgeOS"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [10001]
  banners: ["UniFi", "ubiquiti", "EdgeOS", "ubnt", "UniFi Network"]
  markers: ["ubiquiti", "unifi", "edgeos", "ubnt", "x-ubnt", "UniFi Network Application"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p8080,8443,10001 --script=http-title,ssl-cert {host}", safety: safe, note: "UniFi Network Application on 8080/8443 + discovery port 10001/udp — identifies controller version and site name." }
  - { cmd: "nmap -Pn -p10001 -sU --script ubiquiti-discovery {host}", safety: safe, note: "Ubiquiti Discovery Protocol on 10001/udp — unauthenticated broadcast/unicast reply leaks model, firmware, MAC, IP, and hostname." }
  - { cmd: "curl -sk https://{host}:8443/api/self/sites 2>/dev/null | python3 -m json.tool | head -40", safety: safe, note: "UniFi API site list — if authenticated session or default credentials (ubnt/ubnt) are in scope, lists all managed sites." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr {host}", safety: safe, note: "SNMP sysDescr on EdgeOS routers — leaks EdgeOS version, board type, and hostname." }
references: ["CVE-2021-22909", "CVE-2021-44228", "CVE-2020-8155", "CVE-2023-35083"]
mitre: "T1190"
---
# Ubiquiti UniFi / EdgeOS

Ubiquiti makes two main product lines with distinct software: UniFi (access points, switches, and
security gateways managed via UniFi Network Application on 8080/8443/tcp) and the EdgeMAX line
(EdgeRouter running VyOS-derived EdgeOS, EdgeSwitch). Both are extremely popular in SMB, MSP,
and prosumer deployments due to their price-performance ratio. The UniFi controller exposes a
REST-like API, and Ubiquiti devices respond to a proprietary UDP discovery protocol on 10001 that
broadcasts device model, firmware version, MAC address, and current IP — all unauthenticated.

**Why it matters.** The Ubiquiti Discovery Protocol on 10001/udp leaks device inventory without
any authentication — Shodan and Censys index hundreds of thousands of such responses. CVE-2021-22909
allowed unauthenticated SSRF and RCE against the UniFi Network Application. CVE-2021-44228
(Log4Shell) impacted the UniFi Network Application directly due to its Java/Log4j stack — Ubiquiti
was one of the earliest named products in the Log4Shell disclosure. Default credentials (`ubnt`/`ubnt`)
remain widely deployed across EdgeOS and older UniFi AP firmware.

**Safe-first testing.** Send a UDP probe to port 10001 to trigger the Ubiquiti Discovery response —
this is completely passive from the device's perspective and leaks substantial inventory. Probe the
UniFi controller HTTPS on 8443 for TLS certificate details and server headers. Do not attempt
credential brute-forcing; account lockout policies vary and failed attempts may be logged and
alerted on the controller. Do not interact with the UniFi adoption (inform) protocol.

**Remediation.** Block UDP 10001 at the network perimeter; change default `ubnt` credentials
immediately; move UniFi controller management off the internet to an RFC1918 or VPN-only address;
apply Ubiquiti firmware updates (especially Log4j-affected versions); and disable cloud remote
access (cloud key / UNMS) if not operationally required.
