---
id: insteon
technology: "Insteon Hub / Protocol"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [25105, 9761]
  banners: ["Insteon", "Insteon Hub"]
  markers: ["/3?", "insteon.net", "X-Insteon", "PLM", "Insteon Hub"]
quick_wins:
  - { cmd: "curl -sk http://{host}:25105/1 -u admin:admin", safety: safe, note: "Probe Insteon Hub on default credentials — reveals device list and link table, read-only." }
  - { cmd: "nmap -Pn -sT -p25105,9761 --script banner,http-auth {host}", safety: safe, note: "Banner grab and auth-type detection on Insteon Hub ports." }
  - { cmd: "curl -sk 'http://{host}:25105/sx.xml' -u <user>:<pass>", safety: safe, note: "Retrieve Insteon Hub status XML — device states and link records, read-only." }
  - { cmd: "curl -sk 'http://{host}:25105/buffstatus.xml' -u <user>:<pass>", safety: safe, note: "Read PLM buffer status — shows recent Insteon messages and device activity." }
  - { cmd: "curl -sk 'http://{host}:25105/3?<hex_cmd>=I=3' -u <user>:<pass>", safety: disruptive, note: "GATED — sends raw Insteon command to actuate a device. Requires explicit authorization." }
references: ["CVE-2017-7244", "CVE-2017-7245", "CVE-2017-7246", "Trustwave SpiderLabs Advisory 2017"]
mitre: "T1190 / ICS T0866"
---
# Insteon Hub / Protocol

Insteon is a dual-mesh (powerline + RF 915 MHz) home-automation protocol with an IP gateway
called the Insteon Hub (models 2242-222, 2245-222). The Hub exposes an HTTP API on
**25105/tcp** that accepts Basic Authentication with a short numeric PIN (default: `admin`/`admin`
or a 4-8 digit code printed on the device). Commands are sent as hex-encoded Insteon Standard
Message strings in the URL path (`/3?<hex>=I=3`). Insteon ceased operations in April 2022,
leaving millions of deployed hubs without vendor security updates permanently.

**Why it matters offensively.** Trustwave SpiderLabs disclosed three CVEs in 2017
(CVE-2017-7244/7245/7246) demonstrating unauthenticated device enumeration, command
injection, and cross-site request forgery against the Insteon Hub HTTP API. The short
numeric password combined with no brute-force protection makes credential attacks trivial.
The hub sends raw powerline/RF commands to paired devices — lights, switches, thermostats,
and locks — with no per-command authorization. Because Insteon as a company no longer exists,
no patches will ever be issued for any future vulnerabilities. Internet-exposed Insteon hubs
(detectable via Shodan on 25105/tcp) remain permanently unpatched.

**Safe-first testing.** Probe the default credential pair on 25105; check `/buffstatus.xml`
and `/sx.xml` for device inventory and recent message logs. Both are read-only and reveal the
full linked device table without sending any Insteon commands to physical devices.

**Key risks.** Permanently unpatched hub (vendor defunct); trivially brute-forced numeric
PIN; unauthenticated device enumeration; no TLS; CSRF enabling malicious web pages to control
devices; Insteon RF range (~45 m) allows physical-layer attacks without IP access; powerline
segment exposure. Remediation: immediately firewall 25105/tcp to trusted hosts only, change
the default PIN to maximum length, place the hub behind a VPN if remote access is needed,
and plan migration to actively-maintained platforms (Home Assistant + Z-Wave/Zigbee).
