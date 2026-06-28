---
id: amx_netlinx
technology: "AMX NetLinx (ICSP)"
domain: IoT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [1319]
  banners: ["AMX", "NetLinx", "ICSP"]
  markers: ["AMX-0100", "ICSP/1"]
quick_wins:
  - { cmd: "nmap -Pn -sT -sU -p1319 --script banner {host}", safety: safe, note: "Grab TCP/UDP ICSP banner — reveals AMX firmware version, device model. Read-only." }
  - { cmd: "nmap -Pn -sT -p1319 --script telnet-ntlm-info {host}", safety: safe, note: "Check telnet-mode response on ICSP port for firmware/model strings. Read-only." }
  - { cmd: "nmap -Pn -sT -p23 --script telnet-brute --script-args userdb=/dev/stdin,passdb=/dev/stdin <<< $'administrator\nnetlinx\n' {host}", safety: intrusive, note: "Test CVE-2016-1984 hardcoded backdoor credentials (user: administrator / pass: password). Active auth attempt — intrusive, gated." }
  - { cmd: "curl -sk telnet://{host}:23 --max-time 5", safety: safe, note: "Pull raw telnet banner from AMX controller to confirm firmware build string. Read-only." }
  - { cmd: "python3 -c \"import socket,time; s=socket.create_connection(('{host}',1319),timeout=5); s.sendall(b'\\x02\\x10\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x03'); time.sleep(1); print(s.recv(256))\"", safety: safe, note: "Send minimal ICSP connect request and read controller response — passive fingerprint. Read-only." }
references: ["CVE-2016-1984"]
mitre: "T0866"
---
# AMX NetLinx (ICSP)

AMX NetLinx controllers are commercial building automation and AV control processors widely
deployed in conference rooms, auditoriums, hotels, and government facilities. They run a
proprietary firmware and listen on **1319/tcp+udp** for the **ICSP (Inter-Chassis Switching
Protocol)** bus, which is the native AMX control-plane protocol used to carry device discovery,
event routing, and command traffic between NetLinx masters and touch-panel clients. Many deployments
also expose a **Telnet management interface on 23/tcp** and a web UI on 80/443. Because ICSP carries
AV-switching and room-control commands, a compromised controller can mute microphones, blank
displays, unlock A/V systems, and pivot to adjacent building networks.

**CVE-2016-1984 — hardcoded backdoor credential.** AMX NetLinx firmware prior to the patch
released in 2016 ships a hardcoded administrator account (`administrator` / `password`) that
cannot be disabled or changed through normal administrative means. An attacker with TCP access
to the management interface (Telnet/23 or web/80) can authenticate as a full administrator,
upload arbitrary firmware or NetLinx source code, reconfigure device routing, and access the
full ICSP device tree. The vulnerability is trivially exploitable with a one-line Telnet login.
The CVSS score is **9.8 (Critical)**. Validate only against in-scope targets with explicit
written authorization — authentication attempts are logged in some firmware versions.

**Safe-first testing.** Begin with passive banner grabs: the ICSP TCP handshake returns a
firmware header that includes model string and software version without requiring credentials.
`nmap -p1319 --script banner` and a raw `curl telnet://` against port 23 both extract this
string read-only. Only escalate to the CVE-2016-1984 credential check (`administrator` /
`password`) when the engagement scope explicitly covers authentication testing; even a failed
login attempt is an active intrusion on some hardened firmware builds. Never issue ICSP
device-write or port-output commands on live systems — these carry real control-plane effect
and can disrupt AV, lighting, or room-environment subsystems mid-session.

**Remediation.** Apply AMX firmware updates that remove the hardcoded credential and enforce
password complexity on the administrator account. Place NetLinx controllers on a dedicated,
firewalled AV/control VLAN with no inbound access from the corporate LAN or internet; block
1319/tcp+udp and 23/tcp at the perimeter. Disable the Telnet interface and restrict web
management to HTTPS with MFA where the firmware supports it. Monitor for unexpected ICSP
device-join events, which may indicate rogue touch-panel or controller enrollment.
