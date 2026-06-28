---
id: control4
technology: "Control4"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [5020, 5010]
  banners: ["Control4", "c4soap", "director"]
  markers: ["/control4_service/", "c4i", "C4-Auth", "director.control4.com", "_c4._tcp"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p5010,5020,5900 --script banner {host}", safety: safe, note: "Banner grab on Control4 director and VNC ports — enumerate version and service presence." }
  - { cmd: "curl -sk http://{host}:5020/control4_service/v2/ -H 'Accept: application/json'", safety: safe, note: "Probe Control4 director REST endpoint — returns system info without auth on older firmware." }
  - { cmd: "curl -sk 'http://{host}:5010/' | head -50", safety: safe, note: "Probe legacy c4soap port for Control4 SOAP API version and device metadata." }
  - { cmd: "dns-sd -B _c4._tcp local || avahi-browse -t _c4._tcp", safety: safe, note: "mDNS service discovery — find Control4 controllers on local network." }
  - { cmd: "python3 -c \"import socket; s=socket.create_connection(('{host}',5020)); s.send(b'GET /control4_service/v2/project HTTP/1.0\\r\\n\\r\\n'); print(s.recv(4096))\"", safety: intrusive, note: "Request project file — reveals room layout, device names, and driver inventory." }
references: ["CVE-2021-32950", "CVE-2019-7234", "Snap One Security Advisory 2023"]
mitre: "T1190 / ICS T0866"
---
# Control4

Control4 (now Snap One) is a professional-grade home and commercial automation platform
deployed by certified dealers. The Control4 OS 3 Director service listens on **5020/tcp**
(REST API), with a legacy SOAP/XML interface on **5010/tcp**, and VNC (5900/tcp) for
remote support. The platform integrates AV, lighting, HVAC, locks, security, and custom
drivers written in Lua. Control4 systems are typically found in high-net-worth residential
and enterprise deployments.

**Why it matters offensively.** The Control4 Director REST API on older firmware versions
exposes project files and device inventories without authentication, revealing the complete
physical layout of a home or facility. CVE-2019-7234 affected older Control4 EA controllers
with unauthenticated API access to system configuration. CVE-2021-32950 (Snap One OS 3)
exposed stack-based vulnerabilities in the Director. The Lua driver ecosystem means
third-party drivers from the Control4 Marketplace can execute arbitrary code on the
Director with system-level privileges.

**Safe-first testing.** Probe the Director REST API with GET calls: project metadata, device
list, room structure, and driver inventory can be read without triggering actions. mDNS
discovery (`_c4._tcp`) enumerates controllers passively. Check firmware version against
Snap One security advisories before proceeding.

**Key risks.** Unauthenticated REST API on unpatched systems; Lua driver supply chain;
VNC port exposure; dealer-side backdoor access credentials; CSRF in the web configuration
interface; physical-layer bridging (Control4 switches have management interfaces). Remediation:
apply Snap One/Control4 OS updates, restrict Director ports to the management VLAN, disable
VNC when not actively used, audit installed third-party drivers, and enforce strong
dealer/operator passwords.
