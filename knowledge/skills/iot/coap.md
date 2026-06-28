---
id: coap
technology: "CoAP"
domain: IoT
safety_class: safe
severity: medium
life_safety: false
match:
  ports: [5683, 5684]
  banners: ["coap", "coap/1.0"]
  markers: ["/.well-known/core", "coap://", "coaps://"]
quick_wins:
  - { cmd: "nmap -sU -p 5683 --script coap-resources {host}", safety: safe, note: "Enumerate CoAP resource directory via /.well-known/core (RFC 6690 discovery)" }
  - { cmd: "coap-client -m get coap://{host}/.well-known/core", safety: safe, note: "Read-only GET of the resource directory; lists all advertised endpoints" }
  - { cmd: "coap-client -m get coap://{host}/sys/info", safety: safe, note: "Common vendor info endpoint; reveals firmware version and device metadata" }
  - { cmd: "nmap -sU -p 5683 --script coap-resources --script-args coap-resources.path=/ {host}", safety: intrusive, note: "Recursive resource walk; generates additional UDP traffic against the device" }
  - { cmd: "python3 -m scapy -c 'send(IP(dst=\"{host}\")/UDP(dport=5683)/Raw(load=\"\\x40\\x01\\x00\\x01\\xbb.well-known\\x04core\"), loop=0)'", safety: intrusive, note: "Raw CoAP GET to measure amplification factor; compare request vs response byte ratio" }
  - { cmd: "coap-client -m put coap://{host}/actuator/relay -e '1'", safety: disruptive, note: "Write to actuator endpoint — changes physical device state; run only with explicit scope approval" }
references:
  - "CVE-2019-9750"
  - "CVE-2020-27628"
  - "ICSA-21-236-01"
  - "CISA KEV 2022-02-10"
mitre: "T0884"
---
# CoAP guidance

Constrained Application Protocol (CoAP) is a lightweight REST-like protocol designed for low-power, lossy IoT networks (RFC 7252). It runs over UDP (port 5683 for plain CoAP, 5684 for DTLS-secured CoAPS) and is common on embedded sensors, smart meters, industrial controllers, and building-automation endpoints. The canonical first step in any assessment is a read-only GET to `/.well-known/core`, which returns a CoRE Link Format resource directory advertising every endpoint the device exposes — effectively a self-documenting attack surface map.

During authorized engagements the resource directory frequently reveals writable actuator paths (`/relay`, `/setpoint`, `/output`) alongside diagnostic endpoints leaking firmware version, network configuration, and device credentials. Because CoAP is stateless and has no built-in authentication in most deployments, unauthenticated PUT/POST to these paths can directly alter physical-world state. Always document every discovered path before attempting any write operations and gate disruptive commands behind explicit per-host scope approval from the engagement owner.

CoAP's UDP transport introduces a significant amplification risk: a spoofed 10–20 byte GET to `/.well-known/core` can elicit a multi-kilobyte response, yielding amplification factors of 50x or higher. This makes exposed CoAP servers candidates for DDoS reflection abuse (similar to memcached or DNS amplification). During safe enumeration, measure the response-to-request byte ratio on `/.well-known/core` and flag any device reachable from the internet with an amplification factor above 10x as a critical finding even if no further vulnerabilities exist.

Remediation focus: restrict CoAP to RFC 7252 DTLS mode (port 5684) with certificate-based client authentication; apply OSCORE (RFC 8613) for object-level security where DTLS is impractical; firewall UDP/5683 from internet-facing interfaces; and audit resource directories for actuator endpoints that should not be exposed without authorization.
