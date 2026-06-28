---
id: confluence
technology: "Atlassian Confluence"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [8090, 8091]
  banners: ["Confluence", "Atlassian"]
  markers: ["X-Confluence-Request-Time", "/confluence/", "ajs-confluence-", "Confluence-Version", "/wiki/spaces/", "/display/"]
quick_wins:
  - { cmd: "curl -s http://{host}:8090/rest/api/space?limit=50 | jq '.results[].key,.results[].name'", safety: safe, note: "REST API space enumeration — often unauthenticated on self-hosted instances; reveals all wiki spaces." }
  - { cmd: "curl -s 'http://{host}:8090/rest/api/content?spaceKey=~admin&limit=10' | jq '.results[].title'", safety: safe, note: "Enumerate user home-space pages — may surface sensitive runbooks, passwords in page bodies." }
  - { cmd: "curl -s -o /dev/null -w '%{http_code}' 'http://{host}:8090/login.action'", safety: safe, note: "Check if login page requires authentication; 200 without redirect indicates open instance." }
  - { cmd: "curl -s -X GET 'http://{host}:8090/server-info.action' | grep -i 'version\\|build'", safety: safe, note: "Version disclosure from server-info action — read-only." }
  - { cmd: "curl -s 'http://{host}:8090/setup/setupadministrator.action'", safety: intrusive, note: "GATED — check if setup wizard is exposed (CVE-2023-22515 unauthenticated admin creation); only against authorized target." }
references: ["CVE-2023-22515","CVE-2022-26134","CVE-2021-26084","CVE-2023-22518","KEV CISA AA23-144A"]
mitre: "T1190"
---
# Atlassian Confluence

Atlassian Confluence is the most widely deployed enterprise wiki platform, used for internal
documentation, runbooks, credentials (often pasted in pages), and project planning. It is a
recurring CVE vehicle: CVE-2022-26134 (OGNL injection RCE, unauthenticated) and CVE-2021-26084
(unauthenticated OGNL injection via widget connector) were both exploited in the wild within
hours of disclosure. CVE-2023-22515 allowed unauthenticated creation of administrator accounts
in Confluence Data Center and Server — it was listed in CISA KEV immediately and linked to
state-sponsored actors.

**Key attack surfaces.** OGNL expression injection via HTTP request parameters (historically the
`/rest/tinymce/1/macro/preview`, widget connector, and template endpoints) enables unauthenticated
RCE. The setup wizard endpoint (`/setup/setupadministrator.action`) is accessible if Confluence is
not fully initialized or if a specific request triggers a state reset (CVE-2023-22515). Anonymous
access to spaces is frequently misconfigured, leaking internal credentials, AWS keys, and
infrastructure diagrams posted in wiki pages. CVE-2023-22518 (improper authorization, data
destruction) is critical for Confluence Data Center.

**Safe-first testing.** Enumerate accessible spaces and pages via the REST API without
authentication. Check server-info for version and compare to Atlassian's security advisories.
Look for pages with titles like "passwords", "credentials", "AWS", "ssh" using the search API
(`/rest/api/content/search?cql=title="passwords"`). Test whether the setup endpoint is reachable
without credentials. Do NOT create or delete pages, users, or spaces during testing.

**Remediation.** Apply Atlassian security updates on the same day of release for critical CVEs.
Disable public anonymous access (`Admin → General Configuration → Global Permissions`). Restrict
Confluence to the corporate network or VPN. Use Atlassian Access (SSO/SCIM) with MFA. Audit space
permissions quarterly — especially "Any logged-in user" grants. Block the setup and admin endpoints
at the reverse proxy layer.
