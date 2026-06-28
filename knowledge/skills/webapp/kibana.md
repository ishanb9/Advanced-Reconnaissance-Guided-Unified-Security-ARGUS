---
id: kibana
technology: "Kibana / Elastic Stack"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [5601, 9200]
  banners: ["Kibana", "Elasticsearch"]
  markers: ["/app/kibana", "kbn-version", "kbn-xsrf", "/api/status", "x-elastic-product", "X-Found-Handling-Cluster"]
quick_wins:
  - { cmd: "curl -s http://{host}:5601/api/status | jq '.version.number,.status.overall.state'", safety: safe, note: "Kibana status API — returns version and health state without authentication (if security disabled)." }
  - { cmd: "curl -s http://{host}:9200/ | jq '.version.number,.cluster_name,.tagline'", safety: safe, note: "Elasticsearch root endpoint — version and cluster name; no auth required on open clusters." }
  - { cmd: "curl -s 'http://{host}:9200/_cat/indices?v&h=index,docs.count,store.size' | head -30", safety: safe, note: "Elasticsearch index enumeration — lists all indices, document counts; often unauthenticated on misconfigured deployments." }
  - { cmd: "curl -s 'http://{host}:9200/_search?size=5&pretty' -H 'Content-Type: application/json' -d '{\"query\":{\"match_all\":{}}}'", safety: safe, note: "Elasticsearch global search — samples data across all indices; read-only but may surface PII/secrets." }
references: ["CVE-2019-7614","CVE-2022-23708","CVE-2023-31419","CVE-2023-46671"]
mitre: "T1190"
---
# Kibana / Elastic Stack

Kibana is the visualization layer of the Elastic Stack (ELK: Elasticsearch, Logstash, Kibana),
the world's most widely deployed log analytics platform. Elasticsearch clusters are chronically
misconfigured without authentication — the default out-of-the-box configuration (prior to
Elasticsearch 8.x) required zero authentication for full read/write/delete access over HTTP.
Shodan regularly indexes hundreds of thousands of unauthenticated Elasticsearch clusters containing
medical records, financial data, user PII, application logs with embedded credentials, and
infrastructure data.

**Key attack surfaces.** Unauthenticated Elasticsearch (`9200/tcp`) exposes all stored data
(sensitive logs, app data, PII, secrets) via the REST API. Index enumeration (`/_cat/indices`),
document sampling (`/_search`), and mapping inspection (`/<index>/_mapping`) require no credentials
on misconfigured instances. Kibana (5601/tcp) without authentication allows full dashboard access,
saved search access, and in some versions developer-console access (which is an unrestricted
Elasticsearch query interface). CVE-2019-7614 (CSRF via iframe on Kibana) allowed session hijacking.
CVE-2023-31419 (stack overflow via malformed search query) can crash the cluster. Kibana Canvas
and TSVB features have historically allowed SSRF.

**Safe-first testing.** Query `http://{host}:9200/` for version and cluster name without credentials.
Enumerate indices via `/_cat/indices`. Sample documents from indices with potentially sensitive
names (`logs-*`, `users`, `auth`, `app-*`). Check Kibana at 5601 for authentication requirements.
Review the Kibana developer console (`/app/dev_tools`) for accessibility. Do NOT write, update, or
delete any indices or documents.

**Remediation.** Enable Elasticsearch security features (`xpack.security.enabled: true`) — mandatory
in Elasticsearch 8.x by default. Set strong usernames/passwords for the `elastic` superuser. Enable
TLS on transport (9300) and HTTP (9200) layers. Restrict port 9200/9300/5601 to the application
and analytics VLANs — never expose to the Internet. Use Kibana Spaces and role-based access control
to limit index visibility. Rotate the `elastic` bootstrap password immediately after deployment.
