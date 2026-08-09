---
id: atc_automation
technology: "ATC Automation (STARS / ERAM / TopSky — Air Traffic Control Systems)"
domain: OT
category: aviation
transport: ip
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [4001, 5050, 8500, 9001]
  banners: ["STARS", "ERAM", "TopSky", "EUROCAT", "ATC automation", "Raytheon STARS", "Lockheed STARS"]
  markers: ["STARS", "ERAM", "TopSky", "EUROCAT", "atc-system", "nfdc", "ARTS"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p 4000,4001,5050,8500,9001 --script banner,http-title {host}", safety: safe, note: "Banner grab on ATC automation system ports — identify software version, system type. Read-only." }
  - { cmd: "nmap -Pn -sV -p 1-65535 --open {host} -oN /tmp/atc_portscan.txt", safety: intrusive, note: "Full port scan of ATC automation host — enumerate all exposed services. Active; coordinate with site owner." }
  - { cmd: "curl -sk https://{host}:8500/api/v1/status | python3 -m json.tool", safety: safe, note: "Probe ATC system REST API for unauthenticated status disclosure." }
references: ["CVE-2021-27852", "CVE-2020-10740", "FAA ATO Cybersecurity Framework", "NIST SP 800-82 Rev3", "CISA AA22-265A"]
mitre: "T1190 / T0813 / T0855"
---
# ATC Automation — STARS / ERAM / TopSky (Air Traffic Control Systems)

Air Traffic Control (ATC) automation systems are the software platforms that fuse radar surveillance data, flight plan data, and weather information to provide controllers with the situational picture required to separate aircraft safely. In the US, the FAA operates **STARS** (Standard Terminal Automation Replacement System, Raytheon) at TRACONs and **ERAM** (En Route Automation Modernization, Lockheed Martin) at ARTCCs. In Europe, the dominant platforms are Thales **TopSky-ATC** and Indra **EUROCAT**, with additional national systems. These are complex distributed software systems running on specialized hardware, typically Linux or Solaris-based, networked within the ATC facility on a segmented LAN with feeds from radar processors, flight data processors, NOTAM systems, and ATIS.

**Why it matters.** ATC automation systems are arguably the highest-consequence OT target in civil aviation — they directly support aircraft separation. Documented risks include: (1) **ransomware/availability attacks** — the 2019 FAA NOTAM system outage and multiple European ATC cyberincidents demonstrated that ATC system disruptions cause mass flight delays and potential safety degradation; (2) **data integrity attacks** — an attacker who can inject fabricated flight plan data or radar returns into STARS/ERAM could cause controllers to issue erroneous clearances; (3) **network intrusion** — STARS/ERAM communicate over IP with adjacent facilities, NOTAM servers, and weather systems, creating lateral movement paths; (4) **supply chain** — ATC software updates delivered via supplier VPNs or removable media have been cited as attack vectors.

**Safe-first testing approach.** ATC automation assessment must be conducted under strict regulatory authorization (FAA/ANSP sponsorship, engagement rules documented in writing). On authorized engagements, begin with passive network observation: tap or SPAN on the ATC facility LAN, passively capture traffic, and identify all system components. Perform read-only service enumeration (banner grabbing, version fingerprinting) only during off-peak hours coordinated with facility management. Review network architecture diagrams, firewall rule sets, and patch management records. **Never attempt to inject data into the live ATC system** — this includes forged radar returns, flight plan messages, or NOTAM injections. Any active testing must occur on an isolated replica/simulation environment that is physically disconnected from operational ATC infrastructure.

**Key risks and remediation.** Common ATC automation vulnerabilities: outdated OS/middleware (STARS/ERAM instances running Solaris 10, RHEL 6 beyond EOL), supplier VPN connections with weak authentication (cited in CISA advisories), inadequate network segmentation between operational ATC LAN and facility IT/admin networks, and insufficient monitoring for anomalous data feeds from radar processors. Remediation must follow FAA/ANSP configuration management procedures — patches require regression testing and operational approval before deployment. Key controls: network microsegmentation, authentication on all inter-system data feeds, anomaly detection on radar and flight data processor outputs, and documented incident response procedures for ATC system compromise.
