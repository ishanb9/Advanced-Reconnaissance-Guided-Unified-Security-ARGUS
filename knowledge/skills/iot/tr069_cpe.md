---
id: tr069_cpe
technology: "Routers / CPE (TR-069/CWMP)"
domain: IoT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [7547]
  banners: ["RomPager", "AllegroSoft", "CWMP", "ACS", "acs-url", "CPE WAN Management"]
  markers: ["cwmp:ID", "urn:dslforum-org:cwmp", "GetRPCMethods", "Inform"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p7547 --script http-headers,http-server-header {host}", safety: safe, note: "Grab the HTTP Server header — RomPager/AllegroSoft version reveals known Misfortune Cookie range (RomPager 4.07 and below)." }
  - { cmd: "curl -sk http://{host}:7547/ -o /dev/null -D - | grep -Ei 'server:|acs|cwmp'", safety: safe, note: "Read server banner and CWMP endpoint identity without sending a valid SOAP body." }
  - { cmd: "nmap -Pn -p7547 --script cwmp-detect {host}", safety: safe, note: "NSE cwmp-detect sends a minimal TR-069 Inform probe and reports ACS URL, firmware, and model — read-only enumeration." }
  - { cmd: "routersploit -t {host} -m autopwn", safety: intrusive, note: "GATED — RouterSploit autopwn iterates all CPE exploits (Misfortune Cookie, ROM-0 backup, default-credential modules). Active exploitation; can reboot or brick device. Requires explicit authorization." }
references: ["CVE-2014-9222", "CVE-2014-9223", "CVE-2017-17215", "CVE-2018-10561", "CVE-2018-10562"]
mitre: "T0886"
---
# Routers / CPE (TR-069/CWMP)

TR-069 (CPE WAN Management Protocol, CWMP) is the DSL Forum standard that lets ISPs remotely
provision and manage Customer Premises Equipment — home routers, DSL modems, cable gateways, and
ONUs. The management listener sits on **7547/tcp** and expects SOAP-over-HTTP from an
Auto-Configuration Server (ACS). The protocol has no built-in mutual authentication in its most
common deployments, and the web server layer (RomPager, AllegroSoft) has a long tail of
unauthenticated memory-corruption and authentication-bypass CVEs. Hundreds of millions of
internet-exposed devices run outdated firmware with these listeners publicly reachable.

**Misfortune Cookie (CVE-2014-9222/9223)** is the canonical critical flaw: a corrupt HTTP
cookie triggers a heap overflow in RomPager 4.07 (and earlier) that allows an unauthenticated
attacker to overwrite kernel memory, gain root-level access, and pivot into the home LAN behind
the device. The affected firmware shipped in routers from ZTE, Huawei, D-Link, TP-Link, and
dozens of white-label OEMs. The **HTTP Server banner** (e.g. `Server: RomPager/4.07`) is the
primary fingerprint — anything ≤ 4.07 is presumptively vulnerable. Huawei HG532 routers are
separately affected by CVE-2017-17215 (SOAP command injection) used by the Satori/Brickerbot
botnets. Eir D1000 / ZTE F660 devices expose CVE-2018-10561/10562 (credential disclosure via
CWMP before authentication).

**Safe-first testing.** Always start with the `http-server-header` or `curl -D -` banner grab —
the Server field alone confirms exploitability for Misfortune Cookie without touching any
functional endpoint. The NSE `cwmp-detect` script sends a single well-formed TR-069 Inform probe
that reveals ACS URL, device model, and firmware string while remaining read-only. Only escalate
to RouterSploit autopwn under explicit, scoped written authorization: autopwn modules are
inherently intrusive (they cycle through dozens of exploits) and several can trigger a factory
reset or permanent denial of service on cheap consumer hardware.

**Remediation.** ISPs should block inbound 7547/tcp at the network edge — CPE should only accept
CWMP connections originating from the ACS IP. Firmware upgrades must be pushed via the ACS
itself, removing the need for a public-facing listener. Where upgrade is impossible, firewall
rules or TR-069 client-side filtering (whitelisting the ACS IP in the CWMP config) substantially
reduce exposure. Device owners should confirm with their ISP that the WAN-facing CWMP listener
is firewalled; failing that, replacing end-of-life hardware is the only reliable remediation.
