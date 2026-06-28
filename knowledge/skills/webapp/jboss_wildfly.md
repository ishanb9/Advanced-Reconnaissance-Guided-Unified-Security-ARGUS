---
id: jboss_wildfly
technology: "JBoss / WildFly Application Server"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [9990, 9993, 4712, 4713]
  banners: ["JBoss", "WildFly", "EAP"]
  markers: ["JBoss", "WildFly", "/jmx-console/", "/web-console/", "/management", "X-Powered-By: Servlet/3", "JBossWebServer", "/invoker/JMXInvokerServlet"]
quick_wins:
  - { cmd: "curl -s http://{host}:8080/ | grep -oE 'JBoss|WildFly|EAP [0-9.]+'", safety: safe, note: "Server product and version from landing page — read-only fingerprint." }
  - { cmd: "curl -s http://{host}:8080/jmx-console/ -o /dev/null -w '%{http_code}'", safety: safe, note: "JMX Console availability check — 200 without auth is a critical misconfiguration on legacy JBoss." }
  - { cmd: "curl -s http://{host}:9990/management -u 'admin:admin' | jq '.product-name,.product-version'", safety: safe, note: "WildFly management API version probe with default credentials — read-only." }
  - { cmd: "curl -s -X POST 'http://{host}:8080/invoker/JMXInvokerServlet' -H 'Content-Type: application/x-java-serialized-object' --data-binary @ysoserial_payload.bin", safety: intrusive, note: "GATED — Java deserialization RCE via JMX invoker servlet (CVE-2015-7501); only against authorized target." }
references: ["CVE-2015-7501","CVE-2017-12149","CVE-2015-7501","CVE-2013-4810","CVE-2021-29441"]
mitre: "T1190"
---
# JBoss / WildFly Application Server

JBoss Application Server (now rebranded as WildFly for the community version, Red Hat JBoss EAP
for the enterprise version) is a Jakarta EE container widely deployed in banking, government, and
enterprise middleware. JBoss has one of the longest histories of unauthenticated critical RCE
vulnerabilities in the Java ecosystem — CVE-2015-7501 (Java deserialization via JMX invoker),
CVE-2017-12149 (deserialization via `/invoker/readonly`), and the notorious exposed JMX Console
were all extensively exploited in the wild and form the basis of entire exploit frameworks.

**Key attack surfaces.** The JMX Console (`/jmx-console/`) and Web Console (`/web-console/`) on
legacy JBoss 4.x and 5.x were accessible without authentication, allowing an attacker to deploy
arbitrary EAR/WAR files via the `DeploymentFileRepository` MBean — instant RCE. The Invoker
servlet (`/invoker/JMXInvokerServlet`, `/invoker/EJBInvokerServlet`) accepts serialized Java
objects and is vulnerable to gadget-chain deserialization on any unpatched JBoss version prior to
EAP 7.x. The WildFly management interface (9990/tcp HTTP, 9993/tcp HTTPS) uses default credentials
(`admin:admin`) in many deployments. EJB remote (port 4712/4713) also exposed historical
deserialization paths.

**Safe-first testing.** Fingerprint the product version from the landing page or `Server` header.
Probe the JMX Console and Web Console without credentials. Check whether the management interface
(9990) is Internet-exposed. Enumerate deployed applications via the management REST API
(`/management/deployment`). Do NOT deploy applications, invoke MBeans that write state, or trigger
deserialization payloads without explicit written authorization.

**Remediation.** Upgrade to WildFly 26+ or JBoss EAP 7.4+. Remove or disable the JMX Console,
Web Console, and Invoker servlets — they have no production use case. Firewall the management
interface (9990/9993) to localhost or admin VLAN only. Change default management credentials.
Disable the EJB remote connector if not needed. Apply patches for all listed CVEs — ysoserial
gadget chains remain viable in unpatched installations.
