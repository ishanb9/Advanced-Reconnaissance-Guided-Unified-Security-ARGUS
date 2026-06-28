---
id: weblogic
technology: "Oracle WebLogic Server"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [7001, 7002, 9002, 7070, 7071]
  banners: ["WebLogic", "Oracle WebLogic"]
  markers: ["X-Powered-By: Servlet/2.5 JSP/2.1", "WebLogicServer", "/console/", "bea.cookie.ADMINCONSOLESESSION", "WL-Proxy-SSL", "/wls-wsat/"]
quick_wins:
  - { cmd: "curl -s http://{host}:7001/console/ -o /dev/null -w '%{http_code}'", safety: safe, note: "WebLogic Admin Console reachability check — 200 = exposed; reveals if admin UI is Internet-facing." }
  - { cmd: "curl -s http://{host}:7001/wls-wsat/CoordinatorPortType -o /dev/null -w '%{http_code}'", safety: safe, note: "WS-AT endpoint check — CVE-2019-2725/CVE-2018-2628 attack surface presence indicator." }
  - { cmd: "nmap -Pn -sT -p7001,7002 --script weblogic-t3-info {host}", safety: safe, note: "T3 protocol version probe — read-only, reveals WebLogic version and cluster info." }
  - { cmd: "python3 weblogic_exploit.py --host {host} --port 7001 --cmd 'id'", safety: intrusive, note: "GATED — T3/IIOP deserialization RCE (CVE-2020-14882 or CVE-2019-2725); only against authorized target." }
references: ["CVE-2024-20931","CVE-2023-21839","CVE-2020-14882","CVE-2019-2725","CVE-2018-2628","KEV CISA"]
mitre: "T1190"
---
# Oracle WebLogic Server

Oracle WebLogic Server is the dominant Java EE application server in large enterprise and financial
services environments. It is a perennial top-10 CVE target — Oracle's quarterly CPU (Critical Patch
Update) routinely contains multiple critical WebLogic RCEs each quarter. WebLogic's proprietary T3
and IIOP protocols (port 7001) enable Java deserialization attacks that have been exploited by
ransomware groups, crypto-mining operators, and APT actors. CVE-2020-14882 (unauthenticated RCE via
console endpoint bypass) was mass-exploited within 48 hours of publication.

**Key attack surfaces.** The T3 protocol (WebLogic proprietary protocol on 7001/tcp) accepts
serialized Java objects and has been the vector for dozens of deserialization CVEs (CVE-2018-2628,
CVE-2019-2725, CVE-2023-21839). The WS-AT endpoint (`/wls-wsat/CoordinatorPortType`) was
unauthenticated and processed XML containing serialized objects. The admin console
(`/console/`) at 7001 suffers from authentication bypass in multiple versions. IIOP (port 7001,
7002) provides an alternate deserialization vector. The JNDI lookup via LDAP in CVE-2023-21839
was trivially exploited.

**Safe-first testing.** Probe 7001/tcp for the admin console and T3 endpoint. Run the Nmap
`weblogic-t3-info` script for version extraction. Check whether the admin console requires
authentication. Enumerate deployed applications via the console REST API if credentials are
available. Do NOT send deserialization payloads, trigger JNDI lookups, or interact with the T3
protocol beyond version enumeration without explicit authorization.

**Remediation.** Apply Oracle CPU patches on a monthly cadence — never skip a quarter. Restrict
port 7001/7002 to the application server network using firewall rules; never expose to the
Internet. Disable IIOP and T3 if not required by applications. Enable WebLogic Connection Filters
to allowlist admin console source IPs. Consider the WebLogic Admin channel on a separate port with
IP restrictions. Monitor for outbound LDAP/DNS connections from the WebLogic process.
