---
id: jenkins
technology: "Jenkins CI/CD"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [50000]
  banners: ["Jenkins", "X-Jenkins", "Hudson"]
  markers: ["X-Jenkins:", "X-Hudson:", "/jenkins/", "/jnlpJars/agent.jar", "Jenkins-Crumb", "/blue/rest/"]
quick_wins:
  - { cmd: "curl -s http://{host}:8080/api/json?pretty=true | jq '.jobs[].name'", safety: safe, note: "Unauthenticated Jenkins API job list — confirms open access and enumerates pipeline names." }
  - { cmd: "curl -s http://{host}:8080/systemInfo | grep -i 'version\\|os.name\\|java'", safety: safe, note: "System info page — version, OS, Java version. Often accessible without auth." }
  - { cmd: "curl -s http://{host}:8080/credentials/store/system/domain/_/api/json | jq '.'", safety: safe, note: "Credential store enumeration — reveals stored secret IDs (not values) when anon read is enabled." }
  - { cmd: "curl -s -X POST http://{host}:8080/script --data 'script=println(\"id\".execute().text)'", safety: intrusive, note: "GATED — Groovy Script Console RCE; only against authorized target. Executes OS commands as Jenkins service user." }
references: ["CVE-2024-23897","CVE-2023-27898","CVE-2019-1003000","CVE-2018-1000861","KEV CISA AA24-016A"]
mitre: "T1190"
---
# Jenkins CI/CD

Jenkins is the dominant open-source CI/CD orchestrator, used by millions of development teams to
compile, test, and deploy software. Because Jenkins typically runs with elevated OS privileges and
has access to production secrets (cloud API keys, deploy credentials, code-signing certificates),
it is one of the highest-value lateral-movement targets in any enterprise. CVE-2024-23897
(arbitrary file read via the CLI arg-parsing bug) was weaponized within a day of disclosure and
appeared in ransomware supply-chain attacks within weeks.

**Key attack surfaces.** The Jenkins Script Console (`/script`) allows authenticated users to
execute arbitrary Groovy code (and thus OS commands) — if authentication is disabled or bypassed,
this is an instant RCE. The CLI over JNLP (port 50000) has historically shipped deserialization
vulnerabilities. CVE-2024-23897 allows unauthenticated file read of `/etc/passwd`,
`secrets/master.key`, and other sensitive files. Stored pipelines (Jenkinsfiles) often contain
hardcoded secrets. The `credentials` plugin stores secrets in an encrypted store, but the
encryption key at `secrets/master.key + secrets/hudson.util.Secret` is readable by the Jenkins
process owner and recoverable if file-read vulnerabilities exist.

**Safe-first testing.** Probe the REST API at `/api/json` without credentials — anonymous read
access is a common misconfiguration. Check `/systemInfo`, `/manage`, and `/script` for auth
requirements. Enumerate exposed jobs, build logs (which often contain secrets printed by pipelines),
and credential IDs. Do NOT trigger builds or write to the Groovy console without authorization.

**Remediation.** Enable the Jenkins authorization matrix; enforce "Authenticated users can do
anything" as the minimum, then adopt Role-Based Access Control (RBAC). Disable CLI over JNLP if
unused, or move it behind a firewall. Update Jenkins and plugins weekly — the plugin ecosystem
ships CVEs continuously. Store secrets in a dedicated vault (HashiCorp Vault, AWS Secrets Manager)
rather than Jenkins native credentials. Restrict access to `/script` to Jenkins administrators only.
