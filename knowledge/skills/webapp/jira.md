---
id: jira
technology: "Atlassian Jira"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [8085]
  banners: ["Jira", "Atlassian Jira"]
  markers: ["X-ASEN:", "ajs-product-version", "/secure/Dashboard.jspa", "/rest/api/2/", "jira-frontend", "X-Seraph-LoginReason"]
quick_wins:
  - { cmd: "curl -s 'http://{host}:8080/rest/api/2/serverInfo' | jq '.version,.serverTitle,.deploymentType'", safety: safe, note: "Unauthenticated server info — returns Jira version and instance name without auth (REST API v2)." }
  - { cmd: "curl -s 'http://{host}:8080/rest/api/2/project' | jq '.[].key,.[].name'", safety: safe, note: "Project list via REST — often accessible without auth on self-hosted; reveals all project keys." }
  - { cmd: "curl -s 'http://{host}:8080/rest/api/2/issue/search?jql=text~\"password\"+OR+text~\"secret\"&maxResults=10' | jq '.issues[].fields.summary'", safety: safe, note: "JQL search for credential leaks in issue text — read-only, high-value data if anonymous access is on." }
  - { cmd: "curl -s 'http://{host}:8080/rest/api/2/field' | jq '.[].name' | grep -i 'token\\|secret\\|password'", safety: safe, note: "Custom field enumeration — surface custom fields that may store secrets." }
references: ["CVE-2022-0540","CVE-2021-39115","CVE-2019-8449","CVE-2020-14179"]
mitre: "T1190"
---
# Atlassian Jira

Atlassian Jira is the global standard for software issue tracking, used by hundreds of thousands
of teams. Self-hosted instances frequently have misconfigured anonymous access, exposing internal
tickets, developer discussions, security vulnerabilities in backlog, and occasionally secrets
pasted into descriptions. CVE-2022-0540 (Seraph authentication bypass in Seraph filter chain)
allowed unauthenticated access to protected endpoints in Jira and Jira Service Management,
including admin-level actions.

**Key attack surfaces.** Anonymous access to projects and issues (enabled by default on older
versions) lets unauthenticated users read the entire issue tracker — a goldmine for credential
harvesting (AWS keys, SSH passwords), internal IP enumeration, and understanding security
posture. The REST API (`/rest/api/2/`) mirrors these permissions. CVE-2019-8449 exposed user
info via the `/rest/api/latest/groupuserpicker` endpoint without authentication. The Jira Server
and Data Center mobile plugin (CVE-2021-39115) allowed unauthenticated RCE via JNDI injection.
Webhooks and automation rules can trigger outbound SSRF if attacker-controlled input reaches them.

**Safe-first testing.** Query `/rest/api/2/serverInfo` for version disclosure. Attempt
unauthenticated access to `/rest/api/2/project` to enumerate projects. Issue a JQL search over
issue text for keywords like "password", "token", "AWS_SECRET" to surface credential leaks.
Review the user picker endpoint for user enumeration. Do NOT create, modify, or delete issues,
projects, or users.

**Remediation.** Disable anonymous access at the global and project level. Apply Atlassian
security patches promptly. Enable audit logging and alert on access from unexpected IPs. Use
Atlassian Access (SAML + SCIM) with mandatory MFA. Restrict the REST API to authenticated
sessions at the reverse proxy. Educate developers on credential hygiene in issue descriptions.
