---
id: apache_tomcat
technology: "Apache Tomcat"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [8009]
  banners: ["Apache Tomcat", "Apache-Coyote"]
  markers: ["Apache Tomcat/", "Server: Apache-Coyote", "/manager/html", "Apache Tomcat Error Report", "/examples/servlets/"]
quick_wins:
  - { cmd: "curl -s http://{host}:8080/ | grep -o 'Apache Tomcat/[0-9.]*'", safety: safe, note: "Version banner from default landing page — read-only fingerprint." }
  - { cmd: "curl -s -o /dev/null -w '%{http_code}' http://{host}:8080/manager/html", safety: safe, note: "Check Manager application reachability — 401 = requires auth, 200 = open, 404 = not deployed." }
  - { cmd: "curl -s http://{host}:8080/manager/html -u 'tomcat:tomcat' | grep -i 'war\\|deploy'", safety: safe, note: "Common default credential check (tomcat:tomcat, admin:admin) — read-only if no deploy action taken." }
  - { cmd: "curl -s -X PUT 'http://{host}:8080/manager/deploy?path=/shell' --upload-file shell.war -u 'tomcat:s3cr3t'", safety: intrusive, note: "GATED — WAR deploy via Manager REST API; yields webshell. Only against authorized target with valid credentials." }
references: ["CVE-2025-24813","CVE-2020-1938","CVE-2019-0232","CVE-2017-12617","CVE-2016-8735","KEV CISA"]
mitre: "T1190"
---
# Apache Tomcat

Apache Tomcat is the dominant Java Servlet container, running behind millions of Java EE / Spring
web applications in enterprise environments. The Tomcat Manager application (`/manager/html`) is
a built-in web GUI for WAR deployment — when exposed with default or weak credentials, it
trivially yields RCE via a malicious WAR upload. CVE-2020-1938 ("GhostCat") was an unauthenticated
file read and inclusion vulnerability over the AJP connector (port 8009) — it affected virtually
every Tomcat deployment and achieved widespread exploitation.

**Key attack surfaces.** The Manager and Host-Manager applications ship as part of Tomcat and must
be explicitly removed or access-restricted; default credentials (`tomcat:tomcat`, `admin:admin`,
`s3cr3t:s3cr3t`) are found in the wild. The AJP connector (8009/tcp) historically exposed GhostCat
(CVE-2020-1938) and should be disabled unless fronted by Apache httpd. CVE-2019-0232 (CGI servlet
command injection on Windows) and CVE-2017-12617 (PUT method JSP upload) demonstrate the breadth
of the attack surface. CVE-2025-24813 (partial PUT deserialization, RCE) demonstrates continued
critical-severity research on Tomcat core. The examples web application (`/examples/`) ships by
default and enables session cookie stealing via XSS examples.

**Safe-first testing.** Banner-grab the Tomcat version from the error page or response header.
Check whether `/manager/html`, `/manager/text`, and `/host-manager/html` are reachable without
credentials (or with defaults). Enumerate `/examples/` and `/docs/` for default app exposure.
Test AJP connectivity on 8009/tcp (`nmap -p8009 --script ajp-headers {host}`). Do NOT deploy
WARs, modify server configuration, or restart services.

**Remediation.** Remove or restrict the Manager, Host-Manager, and Examples applications from
production deployments. Change all default credentials; restrict manager access to localhost or
admin IP range in `context.xml` (`allow="127\.\d+\.\d+\.\d+|::1"`). Disable AJP connector in
`server.xml` if not needed. Apply Tomcat security patches promptly. Keep the Tomcat version from
appearing in error pages (`server.xml` → `Server` attribute blank).
