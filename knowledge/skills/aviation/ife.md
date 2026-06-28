---
id: ife
technology: "IFE (In-Flight Entertainment System)"
domain: OT
category: aviation
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: [23, 554, 1935, 4444, 9090]
  banners: ["Panasonic Avionics", "Thales InFlight", "Lumexis", "Zodiac IFE", "IFE", "PAVES", "TopSeries"]
  markers: ["panasonic-avionics", "thales-ife", "lumexis", "x-ife-server", "PAVES", "eX2", "eX3"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p 23,554,1935,4444,9090 --script http-title,http-headers,telnet-info {host}", safety: safe, note: "Banner grab on IFE server vendor ports — identify IFE vendor, firmware version, management interface." }
  - { cmd: "curl -sk http://{host}/api/system/info | python3 -m json.tool", safety: safe, note: "Probe IFE management API for unauthenticated system information disclosure." }
  - { cmd: "nmap -Pn -sV -p 1-65535 --open {host} --script vulners", safety: intrusive, note: "Full port scan + CVE correlation against IFE server — active; moderate noise." }
references: ["CVE-2015-7283", "CVE-2019-9563", "GAO-15-370", "DHS ICS-CERT Advisory ICSA-18-011-01"]
mitre: "T1190 / T1021.001"
---
# IFE — In-Flight Entertainment System

In-Flight Entertainment (IFE) systems provide passengers with audio/video on demand, moving map displays, seat-to-seat calling, internet connectivity, and USB/power outlets. Major vendors include Panasonic Avionics (eX series, PAVES), Thales (TopSeries, AVANT), Collins Aerospace, and Lumexis. IFE systems run on a dedicated cabin network (ARINC 628) that connects the Server Unit (SU) — typically Linux- or Windows CE-based — to Passenger Control Units (PCU) at every seat. This cabin network connects upward to the aircraft IP network (AIRINC 763), which provides Wi-Fi backhaul and may bridge to the **crew rest network** or maintenance access ports.

**Why it matters.** The IFE network is the widest attack surface on a commercial aircraft accessible to passengers. Historical research (Chris Roberts, 2015; subsequent GAO/DHS reports) highlighted that IFE systems — particularly older Panasonic PAVES and Thales TopSeries implementations — shared network infrastructure with aircraft avionics networks or had undocumented lateral paths. IFE servers have been found running outdated Linux kernels with public exploits, exposing telnet management ports with default credentials, and serving unauthenticated REST APIs that disclose configuration data. The critical question in any assessment is whether the IFE network is **physically or logically isolated** from the aircraft avionics backbone (AFDX, ARINC 429 gateways) — Boeing 787 and Airbus A350 design documentation specifies separation, but implementation bugs and gateway misconfiguration have been cited in advisories.

**Safe-first testing approach.** IFE assessment is typically scoped to the ground-side IFE content management system (CMS) or a grounded aircraft in maintenance — not to an in-service flight. On a maintenance aircraft, connect to the IFE server's maintenance Ethernet port (typically in the avionics bay) and conduct passive enumeration: nmap service scan, banner grabbing, HTTP API enumeration, RTSP stream enumeration (live moving map, camera feeds). Check for default vendor credentials (Panasonic, Thales, Lumexis all have published defaults in maintenance manuals). Enumerate network routing tables on the IFE server to identify any routes toward avionics VLAN segments. **Do not attempt to send commands toward flight avionics or flight crew networks** — any lateral movement toward avionics must be treated as out-of-scope and escalated to the airline.

**Key risks and remediation.** Key findings in IFE audits typically include: outdated OS/firmware (EOL Linux 2.x kernels), default SSH/telnet credentials on server units, unauthenticated RTSP streams (cabin camera feeds), and missing IFE-to-avionics firewall rules. Remediation: enforce a hardware data diode or one-way firewall between the IFE LAN and any avionics-adjacent network, mandate firmware update cycles aligned with vendor security bulletins, rotate all vendor default credentials, disable telnet and expose only SSH/HTTPS management, and validate firewall rule sets against the ARINC 763 architecture specification after every software update.
