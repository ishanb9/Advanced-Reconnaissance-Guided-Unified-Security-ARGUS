---
id: grafana
technology: "Grafana"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["Grafana"]
  markers: ["grafana", "X-Grafana-Id", "grafana-app", "/api/health", "GrafanaSession", "/api/dashboards/"]
quick_wins:
  - { cmd: "curl -s http://{host}:3000/api/health | jq '.'", safety: safe, note: "Grafana health endpoint — returns version and database status without authentication." }
  - { cmd: "curl -s -u 'admin:admin' http://{host}:3000/api/datasources | jq '.[].type,.[].url,.[].database'", safety: safe, note: "Default credential probe + datasource enumeration — reveals connected databases, URLs, and credentials if auth succeeds." }
  - { cmd: "curl -s http://{host}:3000/api/snapshots | jq '.snapshots[].name'", safety: safe, note: "Public snapshot enumeration — may expose sensitive monitoring dashboards shared publicly." }
  - { cmd: "curl -s 'http://{host}:3000/public/plugins/alertlist/../../../../../../../../etc/passwd' --path-as-is", safety: intrusive, note: "GATED — CVE-2021-43798 directory traversal for arbitrary file read; only against authorized target." }
references: ["CVE-2021-43798","CVE-2022-31107","CVE-2021-27358","CVE-2023-3128"]
mitre: "T1190"
---
# Grafana

Grafana is the dominant open-source observability dashboarding platform, used by DevOps and SRE
teams globally to visualize metrics from Prometheus, InfluxDB, Elasticsearch, cloud providers, and
dozens of other datasources. CVE-2021-43798 — an unauthenticated directory traversal in the plugin
static file server — was one of the most rapidly exploited web vulnerabilities of 2021, allowing
unauthenticated read of `/etc/passwd`, Grafana's own database (`grafana.db`), and environment
files containing datasource credentials.

**Key attack surfaces.** The default admin credential (`admin:admin`) is widely encountered in
internal deployments — Grafana prompts for a change on first login but many instances skip this.
The datasource API (`/api/datasources`) exposes connection strings, database names, and sometimes
embedded credentials for connected systems (Prometheus, InfluxDB, Postgres, AWS CloudWatch).
CVE-2021-43798 path traversal enabled unauthenticated reads of `grafana.db` (SQLite database
containing all users, datasource passwords, and API keys). CVE-2022-31107 (OAuth login bypass)
and CVE-2023-3128 (Azure AD auth bypass) both allow account takeover without credentials.

**Safe-first testing.** Query `/api/health` for version without authentication. Attempt default
credentials (`admin:admin`) against the API. Enumerate public dashboards via
`/api/search?query=&starred=false&type=dash-db` without auth. Check if public snapshot sharing is
enabled. Review the datasource list for sensitive connected systems. Do NOT modify dashboards,
datasources, or alert rules. Do NOT attempt the path traversal without explicit authorization.

**Remediation.** Change the default admin password immediately on deployment. Disable public
snapshot sharing (`allow_embedding`, `external_enabled = false`) unless required. Upgrade to
Grafana 8.3.10+/9.x+ to patch CVE-2021-43798. Enforce LDAP/OAuth SSO with MFA. Restrict Grafana
to internal networks; do not expose port 3000 to the Internet. Audit datasource credentials and
rotate them if the `grafana.db` file may have been exposed.
