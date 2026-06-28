---
id: sdwan_edge
technology: "SD-WAN Edge Appliances (Cisco Viptela/VMware VeloCloud/Fortinet)"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [12346, 12347, 12366, 12444]
  banners: ["vEdge", "vManage", "VeloCloud", "VeloClouds SD-WAN", "FortiGate", "vmware sd-wan"]
  markers: ["vmanage", "vedge", "velocloud", "sdwan", "viptela", "SD-WAN", "orchestrator"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p443,8443,12346,12347,12366 --script=ssl-cert,http-title {host}", safety: safe, note: "SD-WAN management portal (443/8443) + Viptela DTLS control-plane port (12346) — reveals platform vendor and version from TLS cert and HTTP title." }
  - { cmd: "curl -sk https://{host}:443/dataservice/system/device/vedges 2>/dev/null | python3 -m json.tool | head -40", safety: safe, note: "Cisco vManage REST API edge inventory — read-only list of enrolled vEdge devices; unauthenticated on unpatched builds." }
  - { cmd: "nmap -Pn -p161 -sU --script snmp-sysdescr {host}", safety: safe, note: "SNMP sysDescr on SD-WAN appliance — leaks vendor (Viptela/FortiGate/VMware), firmware version, and serial number." }
  - { cmd: "curl -sk https://{host}/guestportal/pages/portal.jsp -I 2>/dev/null | head -20", safety: safe, note: "VeloCloud Orchestrator guest portal probe — response headers reveal VMware SD-WAN version string." }
references: ["CVE-2021-1479", "CVE-2021-1480", "CVE-2023-20235", "CVE-2022-42475", "KEV 2021-11-03"]
mitre: "T1190"
---
# SD-WAN Edge Appliances

SD-WAN (Software-Defined Wide Area Network) edges replace traditional MPLS branch routers with
software-defined appliances that select the best WAN path dynamically. The dominant platforms are
Cisco SD-WAN (formerly Viptela vEdge/vManage), VMware VeloCloud (now Broadcom), and Fortinet
Secure SD-WAN (FortiGate-based). These appliances receive routing policy from a centralized
management controller (vManage, VCO Orchestrator) over an encrypted control channel and forward
production branch-office traffic to data centers and cloud endpoints. SD-WAN edges are deployed
at every branch location of large enterprises, making them a high-value pivot target.

**Why it matters.** CVE-2021-1479 and CVE-2021-1480 (both CVSS 9.8, KEV) in Cisco SD-WAN
vManage allowed unauthenticated RCE via buffer overflows in the web service and system file
read primitives — compromising the controller gives an attacker policy control over every branch
edge in the fabric. CVE-2023-20235 allowed command injection via the vManage API. Cisco vManage
instances have been observed on the public internet with default or weak credentials. Fortinet
SD-WAN shares the FortiOS vulnerability surface (CVE-2022-42475, CVSS 9.3, zero-day in the wild).

**Safe-first testing.** Identify the SD-WAN controller (vManage on 443, VCO Orchestrator on 443)
via TLS certificate CN and HTTP title. Attempt the Cisco vManage REST API version endpoint
(`/dataservice/system/device/vedges`) as a read-only GET — on unpatched versions this returned
a full device inventory without authentication. Do not send crafted authentication bypass or
command injection payloads; these can destabilize the controller and cause fabric-wide routing
disruption across all branches.

**Remediation.** Move SD-WAN controllers off the public internet to private or VPN-only addresses;
apply vendor security advisories promptly; enforce certificate-based mutual TLS for edge-to-controller
authentication; rotate vManage admin credentials; enable multi-factor authentication on the
management portal; monitor controller API access logs; and segment SD-WAN management traffic from
production data-plane VLANs.
