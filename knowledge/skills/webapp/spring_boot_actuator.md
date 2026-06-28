---
id: spring_boot_actuator
technology: "Spring Boot Actuator"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: []
  markers: ["/actuator/health", "/actuator/env", "/actuator/mappings", "/actuator/beans", "/actuator/heapdump", "actuator/loggers", "/actuator/info", "spring-boot"]
quick_wins:
  - { cmd: "curl -s http://{host}/actuator | jq '._links | keys'", safety: safe, note: "Actuator discovery endpoint — lists all enabled management endpoints without authentication." }
  - { cmd: "curl -s http://{host}/actuator/env | jq '.propertySources[].properties | to_entries[] | select(.key|test(\"password|secret|key|token\";\"i\")) | {key:.key,value:.value}'", safety: safe, note: "Environment endpoint — dumps all application properties including secrets (masked if Spring Security active, but often not)." }
  - { cmd: "curl -s http://{host}/actuator/info | jq '.'", safety: safe, note: "App info endpoint — version, git commit, build info. Frequently exposes git hash and internal repo structure." }
  - { cmd: "curl -s http://{host}/actuator/heapdump -o heap.hprof && jhat heap.hprof", safety: intrusive, note: "GATED — heap dump download contains full JVM memory: secrets, session tokens, passwords in RAM. Large (100MB+). Authorized only." }
  - { cmd: "curl -s -X POST http://{host}/actuator/env -H 'Content-Type: application/json' -d '{\"name\":\"spring.datasource.url\",\"value\":\"jdbc:h2:mem:testdb\"}'", safety: intrusive, note: "GATED — actuator env write can reconfigure the live application; only against authorized target." }
references: ["CVE-2022-22965","CVE-2022-22963","CVE-2021-22053","OWASP Spring Security"]
mitre: "T1190"
---
# Spring Boot Actuator

Spring Boot Actuator is a production-monitoring subsystem bundled with virtually every Spring Boot
application. When misconfigured (all endpoints exposed, no security applied), it becomes a
catastrophic information-disclosure and RCE vector. The `/actuator/env` endpoint dumps all
environment variables and application properties, frequently including database passwords, cloud
API keys, JWT signing secrets, and SMTP credentials. The `/actuator/heapdump` endpoint triggers
and downloads a full JVM heap dump — a snapshot of RAM that contains decrypted secrets, live
session tokens, and plaintext credentials.

**Key attack surfaces.** Pre-Spring Boot 2.x versions exposed all actuator endpoints on the
main HTTP port without authentication by default. Post-2.x exposed only `/health` and `/info` by
default, but misconfigured `management.endpoints.web.exposure.include=*` (a commonly copy-pasted
developer config) re-exposes everything. The `/actuator/env` POST endpoint allows reconfiguring
running Spring properties including `spring.datasource.url` (database reconnection), which chained
with the Jolokia endpoint (`/actuator/jolokia`) can achieve JNDI-based RCE (Log4Shell patterns).
`/actuator/logfile` streams the live log file, `/actuator/threaddump` exposes thread state and
stack traces, and `/actuator/mappings` reveals every registered HTTP endpoint.

**Safe-first testing.** Probe `/actuator` for the discovery index. Enumerate exposed endpoints
and collect version, git info, and env properties. Check whether environment values are masked
(`******`) or plaintext. Do NOT download the heap dump (large, intrusive, may cause OOM on
constrained instances), POST to the `env` endpoint, invoke JMX operations via Jolokia, or restart
the application via `/actuator/shutdown`.

**Remediation.** In `application.properties` / `application.yaml`: set
`management.endpoints.web.exposure.include=health,info` (minimum needed). Secure actuator
endpoints with Spring Security (`management.endpoint.env.enabled=false` for env, etc.). Move
actuator to a separate management port (`management.server.port=9090`) and firewall that port to
the monitoring network only. Never use `management.endpoints.web.exposure.include=*` in production.
