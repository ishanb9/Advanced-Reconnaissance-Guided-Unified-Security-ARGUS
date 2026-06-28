---
id: sharepoint
technology: "Microsoft SharePoint"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["SharePoint", "Microsoft-IIS"]
  markers: ["MicrosoftSharePointTeamServices", "X-SharePointHealthScore", "/_layouts/15/", "SPO", "X-MS-SharePoint", "/_api/web/", "SharePoint.Foundation"]
quick_wins:
  - { cmd: "curl -s 'https://{host}/_api/web?$select=Title,Url,Created' -H 'Accept: application/json'", safety: safe, note: "SharePoint REST API site metadata — returns title and URL without auth if anonymous access is enabled." }
  - { cmd: "curl -s 'https://{host}/_layouts/15/viewlsts.aspx' -o /dev/null -w '%{http_code}'", safety: safe, note: "SharePoint list enumeration page reachability — 200 without auth indicates anonymous read is on." }
  - { cmd: "curl -s 'https://{host}/_vti_pvt/service.cnf'", safety: safe, note: "FrontPage server extensions config — version and configuration disclosure; often accessible unauthenticated." }
  - { cmd: "curl -s 'https://{host}/_api/search/query?querytext=%27password%27&rowlimit=10' -H 'Accept: application/json'", safety: safe, note: "SharePoint Search API query for 'password' — read-only; surfaces documents containing credentials if anonymous search is on." }
  - { cmd: "python3 sharepointexploit.py --host {host} --cve CVE-2023-29357", safety: intrusive, note: "GATED — CVE-2023-29357 authentication bypass for privilege escalation; only against authorized target." }
references: ["CVE-2024-38094","CVE-2023-29357","CVE-2023-24955","CVE-2022-29108","KEV CISA"]
mitre: "T1190"
---
# Microsoft SharePoint

Microsoft SharePoint is the enterprise collaboration and intranet platform embedded in Microsoft 365
and deployed on-premises by tens of thousands of organizations. It is a high-value target because
it houses sensitive documents, HR records, financial data, and project artifacts. CVE-2023-29357
(authentication bypass to privilege escalation) and CVE-2023-24955 (authenticated RCE via server-side
code injection) were chained together by threat actors and listed in CISA KEV. CVE-2024-38094
(authenticated RCE) appeared in ransomware campaigns targeting on-premises deployments.

**Key attack surfaces.** Anonymous access to SharePoint sites and document libraries is a common
misconfiguration, allowing unauthenticated document browsing and download. The SharePoint REST API
(`/_api/`) and SOAP endpoint (`/_vti_bin/`) are broad and version-rich. CVE-2023-29357 leveraged
forged JWT authentication tokens to bypass auth entirely. The SSRF surface in SharePoint's Business
Connectivity Services (BCS) and web parts allows reaching internal network services. SharePoint
Designer (`_vti_pvt/`, FrontPage extensions) exposes version metadata. Site Search indexes all
documents including those in "restricted" libraries if search permissions are misconfigured.

**Safe-first testing.** Check the REST API (`/_api/web`) for unauthenticated access. Enumerate
document libraries and lists via the viewlsts page. Query the Search API for sensitive terms.
Identify the SharePoint version from `/_vti_pvt/service.cnf` or response headers. Do NOT upload,
modify, or delete documents, lists, or site settings.

**Remediation.** Apply Microsoft Patch Tuesday updates promptly for SharePoint — critical RCEs
appear multiple times per year. Disable anonymous access at the web application and site collection
level. Enforce Microsoft Entra ID (Azure AD) conditional access with MFA for all SharePoint access.
Restrict the SharePoint REST API to authenticated sessions. Audit library permissions and anonymous
link sharing quarterly. Deploy Microsoft Defender for Office 365 to detect anomalous document
access patterns.
