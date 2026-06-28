---
id: arista_eos
technology: "Arista EOS"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [6020]
  banners: ["Arista", "EOS", "arista networks", "Arista EOS", "Extensible Operating System"]
  markers: ["arista-eos", "eapi", "Arista", "vEOS", "cEOS"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22,443,6020 --script=ssh-hostkey,http-title {host}", safety: safe, note: "SSH banner grab + eAPI HTTPS (443) and gRPC (6020) fingerprint — reveals EOS version and platform." }
  - { cmd: "curl -sk -u admin: -X POST https://{host}/command-api -d '{\"jsonrpc\":\"2.0\",\"method\":\"runCmds\",\"params\":{\"version\":1,\"cmds\":[\"show version\"],\"format\":\"json\"},\"id\":1}'", safety: safe, note: "Arista eAPI JSON-RPC show version — read-only, reveals EOS release, model, serial, and uptime. Gate on credential availability." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr {host}", safety: safe, note: "SNMP sysDescr — leaks EOS version and Arista platform (7050X, 7280R, etc.) with default community." }
  - { cmd: "nmap -Pn -p6020 --script grpc-info {host}", safety: safe, note: "gRPC/gNMI port fingerprint — Arista OpenConfig/gNMI subscription surface on 6020/tcp." }
references: ["CVE-2023-24512", "CVE-2022-29056", "CVE-2020-24360"]
mitre: "T1190"
---
# Arista EOS

Arista EOS (Extensible Operating System) runs on Arista's 7000-series data-center switches and is
the dominant platform in hyperscaler-adjacent and high-frequency-trading network environments. EOS is
Linux-based and exposes management via SSH, a REST/JSON-RPC eAPI on HTTPS (443), SNMP, OpenConfig
gNMI/gRPC (6020/tcp), NETCONF, and RESTCONF. Its programmability story (CloudVision, eAPI) is a
selling point — and an expanded attack surface.

**Why it matters.** CVE-2023-24512 allowed privilege escalation from operator to root via a crafted
eAPI request on unpatched EOS versions. CVE-2020-24360 (CVSS 7.8) exposed a race condition leading
to privilege escalation from the admin shell. eAPI, when enabled with HTTP (not HTTPS) or with
default/weak credentials, gives any network-reachable attacker full CLI access to the switch via
simple JSON-RPC calls — the entire running configuration and VLAN topology can be extracted in a
single request.

**Safe-first testing.** Probe eAPI with a read-only `show version` JSON-RPC call if credentials are
in scope. Enumerate gNMI capabilities via a gRPC capability-request — this reveals supported OpenConfig
models without changing state. SNMP sysDescr with the `public` community string leaks EOS version and
platform. Do not use eAPI `enable` commands that write configuration.

**Remediation.** Disable eAPI HTTP and enforce HTTPS with valid certificates; rotate default admin
credentials; restrict eAPI and gNMI access via management ACLs; apply Arista Security Advisories;
use RBAC roles to limit eAPI users to read-only where appropriate; integrate with CloudVision for
centralized config drift detection.
