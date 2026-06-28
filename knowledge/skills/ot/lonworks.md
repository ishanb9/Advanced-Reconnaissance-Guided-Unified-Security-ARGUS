---
id: lonworks
technology: "LonWorks / LonTalk (IP-852)"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1628, 1629]
  banners: ["LonWorks", "LonTalk", "Neuron", "IP-852", "i.LON", "Echelon"]
  markers: ["lonworks", "ip-852", "neuron-id", "CEA-852"]
quick_wins:
  - { cmd: "nmap -Pn -sU -sT -p1628,1629 --script banner {host}", safety: safe, note: "Detect IP-852 channel routing service; banner often discloses Neuron ID, firmware, and vendor string. Read-only." }
  - { cmd: "nmap -Pn -sT -p1628,1629 -sV {host}", safety: safe, note: "Version probe — recovers gateway product name and IP-852 stack version without touching the LON bus." }
  - { cmd: "python3 -c \"import socket,struct; s=socket.socket(); s.connect(('{host}',1628)); s.send(b'\\x00\\x10\\x00\\x00'); print(s.recv(256).hex())\"", safety: safe, note: "Raw IP-852 session-request probe; response may disclose Neuron ID and device type. Passive read." }
  - { cmd: "curl -s --connect-timeout 5 -u admin:admin http://{host}/index.xml && echo 'DEFAULT-CRED-HIT'", safety: intrusive, note: "Default-credential check against i.LON SmartServer web API endpoint /index.xml (common defaults: admin/admin, ilon/ilon). Active auth attempt — gated; document all attempts." }
references: ["CVE-2012-6435", "CVE-2012-6436", "CVE-2012-6437", "CVE-2012-6438", "ICSA-13-011-01"]
mitre: "T0886"
---
# LonWorks / LonTalk (IP-852)

LonWorks is an ANSI/CEA-709 peer-to-peer fieldbus protocol widely deployed in building
automation (HVAC, lighting, access control, metering) and industrial control systems. Each
device carries a globally unique **48-bit Neuron ID** burned into the Motorola/Echelon
Neuron chip; this ID is used for addressing, commissioning, and network management. The
**IP-852** tunnel (ANSI/CEA-852) bridges LON segments over UDP/TCP on ports **1628** (session)
and **1629** (channel routing), allowing LON devices to be reached across IP networks —
dramatically widening the attack surface of an originally air-gapped bus.

**Neuron ID enumeration.** The IP-852 session service responds to unauthenticated connection
requests with device metadata that typically includes the Neuron ID, firmware revision, and
vendor string. Passive banner-grabbing and Nmap service-version probes (`-sV -p1628,1629`)
are entirely read-only and give an attacker (or assessor) a complete device fingerprint
without touching the LON bus itself. Shodan and Censys index thousands of exposed IP-852
gateways; search `port:1628` or `port:1629` to confirm internet exposure before any active
testing.

**Gateway default credentials.** Echelon i.LON SmartServer, i.LON 100, and third-party
IP-852 gateways historically shipped with unchanged defaults (`admin/admin`, `guest/guest`,
`ilon/ilon`). ICSA-13-011-01 documents multiple unauthenticated and default-credential
vulnerabilities in the i.LON 100 series that allow full configuration read/write — including
the ability to reprogram LON network variables, alter schedules, and push firmware.
Credential testing against the gateway web console or FTP service is **intrusive** and must
be explicitly authorized; successful login gives control over all downstream LON nodes.

**Remediation.** Restrict ports 1628/1629 to management VLANs with strict ACLs; change all
gateway credentials from vendor defaults and enforce minimum password complexity; apply vendor
firmware patches addressing ICSA-13-011-01; disable the FTP/TFTP management interfaces if
not required; enable IP-852 session-layer channel authentication where the stack supports it;
and log all session-establishment events for anomaly detection. Treat any internet-exposed
IP-852 endpoint as fully compromised until verified otherwise — the LON bus offers no
authentication at the fieldbus layer.
