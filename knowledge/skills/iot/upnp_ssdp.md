---
id: upnp_ssdp
technology: "UPnP / SSDP"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1900, 49152]
  banners: ["upnp", "ssdp", "igd", "rootdevice", "miniupnpd", "wanipdconnection"]
  markers: ["/rootDesc.xml", "/IGD.xml", "/upnp/control/", "urn:schemas-upnp-org", "ST: ssdp:all", "MAN: \"ssdp:discover\""]
quick_wins:
  - { cmd: "nmap -sU -p 1900 --script upnp-info {host}", safety: safe, note: "SSDP M-SEARCH discovery + rootDesc.xml retrieval; enumerates device type, manufacturer, services" }
  - { cmd: "nmap -p 49152 --script upnp-info {host}", safety: safe, note: "Probe UPnP HTTP control port 49152 (IANA dynamic/private range, UPnP-dedicated) for root device description; rely on /rootDesc.xml or urn:schemas-upnp-org banner to confirm UPnP rather than port alone" }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'M-SEARCH * HTTP/1.1\\r\\nHOST:239.255.255.250:1900\\r\\nMAN:\\\"ssdp:discover\\\"\\r\\nMX:3\\r\\nST:ssdp:all\\r\\n\\r\\n',('{host}',1900)); print(s.recv(4096))\"", safety: safe, note: "Raw M-SEARCH unicast to enumerate UPnP responders without network-wide multicast" }
  - { cmd: "curl -s http://{host}:<port>/rootDesc.xml | python3 -m xml.dom.minidom -", safety: safe, note: "Fetch and pretty-print the root device description XML to enumerate exposed services and control URLs" }
  - { cmd: "upnp-inspector --host {host} --port <port>", safety: intrusive, note: "IGD enumeration — queries WANIPConnection/WANPPPConnection services to list active port mappings" }
  - { cmd: "python3 -m miniupnpc -a {host} <port>", safety: intrusive, note: "Attempt to add a test NAT port mapping via IGD AddPortMapping action; confirms write access to the gateway" }
references: ["CVE-2020-12695", "CVE-2013-0229", "CVE-2013-0230", "CVE-2019-12780", "ICSA-13-140-01"]
mitre: "T1046"
---
# UPnP / SSDP guidance

Universal Plug and Play (UPnP) is a suite of networking protocols that allows devices to discover each other and expose services automatically with zero authentication. The Simple Service Discovery Protocol (SSDP) operates over UDP port 1900, using multicast M-SEARCH requests to locate devices. Discovered devices advertise a root description URL (typically `/rootDesc.xml`) over HTTP, from which clients can enumerate available services including the Internet Gateway Device (IGD) profile used for NAT traversal. UPnP is ubiquitous on consumer routers, smart TVs, NAS devices, printers, and IP cameras.

For authorized penetration testing, UPnP/SSDP exposure is significant because the IGD profile provides an unauthenticated mechanism to add and delete NAT port mappings on the gateway. An attacker with LAN or SSRF access can forward arbitrary external ports through the router to internal hosts, bypassing firewall rules entirely. The CallStranger vulnerability (CVE-2020-12695) further allows abuse of the UPnP SUBSCRIBE callback mechanism to perform SSRF, data exfiltration, and DDoS amplification through devices without requiring authentication, affecting billions of devices across major vendors. Start enumeration with the safe nmap NSE script and rootDesc.xml fetch before escalating to IGD write operations.

Begin with a passive SSDP unicast M-SEARCH and rootDesc.xml retrieval to map the device type, firmware version, and exposed control URLs. Identify whether the WANIPConnection or WANPPPConnection service is present — these are the IGD services that allow port mapping manipulation. Review the control URL paths and service descriptors for the full action set. Only escalate to AddPortMapping or SUBSCRIBE callback probing after confirming scope authorization for intrusive testing, as these actions modify gateway state and may trigger alerts or disrupt legitimate NAT sessions.

Remediation: disable UPnP on all network-edge devices unless strictly required; apply vendor firmware patches for CallStranger; restrict UPnP control endpoints to localhost or trusted VLANs using firewall rules; audit existing port mappings with `upnp-inspector` or router admin interfaces and remove any that are unauthorized.
