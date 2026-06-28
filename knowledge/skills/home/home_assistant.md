---
id: home_assistant
technology: "Home Assistant"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [8123]
  banners: ["Home Assistant"]
  markers: ["/api/", "X-Ha-Version", "/lovelace", "homeassistant"]
quick_wins:
  - { cmd: "curl -sk http://{host}:8123/api/ -H 'Authorization: Bearer <token>'", safety: safe, note: "Probe REST API root — returns version/message without state changes." }
  - { cmd: "curl -sk http://{host}:8123/api/states | python3 -m json.tool", safety: safe, note: "Dump all entity states (lights, locks, sensors) — read-only enumeration." }
  - { cmd: "nmap -Pn -sT -p8123 --script http-title,http-headers {host}", safety: safe, note: "Banner grab — confirm HA version without auth." }
  - { cmd: "curl -sk http://{host}:8123/api/services -H 'Authorization: Bearer <token>'", safety: intrusive, note: "List all callable service domains — shows controllable devices." }
  - { cmd: "curl -sk -X POST http://{host}:8123/api/services/switch/turn_off -H 'Authorization: Bearer <token>' -d '{\"entity_id\":\"switch.target\"}'", safety: disruptive, note: "GATED — actuates a device. Requires scoped authorization." }
references: ["CVE-2023-27482", "CVE-2021-42079", "CVE-2023-41895", "KEV: CVE-2023-27482"]
mitre: "T1190 / ICS T0866"
---
# Home Assistant

Home Assistant (HA) is the most popular open-source home-automation platform, running on
Raspberry Pi, x86, or as an OVA/Docker container. Its REST API, WebSocket API, and optional
cloud-relay (Nabu Casa) all listen on **8123/tcp** by default. The platform integrates
thousands of IoT devices — locks, cameras, thermostats, alarms — making it a single pivot
point for an entire home network.

**Why it matters offensively.** A single long-lived API token (visible in HA UI, often
hard-coded in scripts or Ansible playbooks, and frequently leaked to GitHub) grants full
device control. CVE-2023-27482 was a CVSS 10.0 authentication bypass in the Supervisor
component that allowed unauthenticated RCE on Home Assistant OS/Supervised installs. It
reached CISA KEV within days of disclosure.

**Safe-first testing.** Start with `GET /api/` and `GET /api/states` (read-only); both reveal
version and the full device inventory. Check `/api/config` for geographic coordinates and
integrations. Avoid `POST /api/services/*` calls without an explicit scope gate — they
directly actuate physical devices (locks, garage doors, alarms).

**Key risks.** Unauthenticated or over-privileged Long-Lived Access Tokens (LLATs); exposed
8123 to the internet; legacy HTTP (no TLS) on local LAN; add-on/HACS supply chain; insecure
webhooks; cloud proxy tunnelling through Nabu Casa exposing local HA instances. Remediation:
enforce HTTPS, use short-lived tokens, restrict 8123 to LAN, apply updates promptly, audit
installed integrations.
