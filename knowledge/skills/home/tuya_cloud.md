---
id: tuya_cloud
technology: "Tuya Smart Cloud"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [6668, 6667]
  banners: ["tuya", "TUYACLOUD"]
  markers: ["openapi.tuya.com", "openapi.tuyaus.com", "TuyaLink", "tuya-sdk", "GizWits", "3.3\x00\x00\x00\x00"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p6668 --script banner {host}", safety: safe, note: "Probe Tuya local control port 6668 — reveals protocol version in banner, no auth required." }
  - { cmd: "python3 -c \"import tinytuya; d=tinytuya.Device(dev_id='<id>',address='{host}',local_key='<key>'); print(d.status())\"", safety: safe, note: "Tuya local API status query — reads device state using local key, read-only." }
  - { cmd: "curl -sk 'https://openapi.tuya.com/v1.0/token?grant_type=1' -H 'client_id: <clientId>' -H 'sign: <hmac>' -H 't: <timestamp>'", safety: safe, note: "Obtain cloud API token — verifies credential validity before device enumeration." }
  - { cmd: "curl -sk 'https://openapi.tuya.com/v1.0/users/<uid>/devices' -H 'access_token: <token>' -H 'client_id: <clientId>' -H 'sign: <hmac>'", safety: safe, note: "List all devices under a Tuya user account — cloud API enumeration, read-only." }
  - { cmd: "python3 -c \"import tinytuya; d=tinytuya.Device(dev_id='<id>',address='{host}',local_key='<key>'); d.set_value(1,True)\"", safety: disruptive, note: "GATED — actuates device switch. Requires local key and written authorization." }
references: ["CVE-2022-37917", "CVE-2019-10008", "CVE-2023-33463", "Tuya Security Bulletin 2023-Q2"]
mitre: "T1078.004 / ICS T0866"
---
# Tuya Smart Cloud

Tuya is the dominant OEM white-label IoT cloud platform, powering hundreds of millions of
consumer smart devices sold under thousands of brand names (Smart Life, LSC Smart Connect,
Gosund, Treatlife, and many more). Tuya devices operate in two modes: cloud-dependent (via
`openapi.tuya.com`) and local control over **6668/tcp** using a proprietary encrypted
binary protocol. The local protocol uses a device-specific AES-128 key (`local_key`) that
is issued during cloud provisioning and can be extracted from the Tuya cloud API.

**Why it matters offensively.** The massive scale of the Tuya ecosystem means compromised
cloud credentials (client_id + client_secret from the Tuya Developer Platform) grant access
to the full device fleet of any linked account. CVE-2022-37917 exposed local key extraction
without authentication. CVE-2019-10008 demonstrated that early Tuya firmware used static
or weak local keys, allowing LAN control without authentication. The local 6668/tcp port
responds to enumeration probes even without a valid local_key (version 3.1 devices use only
MD5 auth). Third-party `tinytuya` tooling makes local exploitation trivially scriptable.

**Safe-first testing.** Enumerate with Tuya cloud API GET calls (device list, status) using
obtained credentials. For local testing, use `tinytuya`'s `Device.status()` (read-only)
against devices where local key access has been authorized. Never issue `set_value()` calls
without written scope authorization — Tuya devices include smart plugs, heaters, and locks.

**Key risks.** White-label branding obscures the shared Tuya backend; local_key extraction
from cloud API enables LAN bypass; unencrypted local protocol v3.1 susceptible to MITM;
supply-chain: Tuya firmware updates applied silently to third-party branded devices; shared
cloud tenant data in multi-user environments. Remediation: isolate Tuya devices on a
firewalled IoT VLAN blocking 6668 from other segments, disable cloud APIs when not needed,
rotate local_keys after provisioning, and prefer Matter-certified devices over proprietary
Tuya protocol.
