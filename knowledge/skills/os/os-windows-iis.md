---
id: os-windows-iis
technology: "Windows IIS (Internet Information Services)"
domain: IT
category: os
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: []
  banners: ["Microsoft-IIS", "IIS/", "ASP.NET", "X-Powered-By: ASP.NET"]
  markers: ["Microsoft-IIS", "X-AspNet-Version", "X-Powered-By: ASP.NET", "/.aspx", "/.ashx", "web.config"]
quick_wins:
  - { cmd: "curl -sk -I http://{host}/ | grep -iE 'server:|x-powered|x-aspnet'", safety: safe, note: "Retrieve HTTP response headers to fingerprint IIS version and ASP.NET version — read-only." }
  - { cmd: "nmap -Pn -sV -p80,443 --script http-iis-webdav-vuln,http-methods,http-server-header {host}", safety: safe, note: "Detect WebDAV misconfiguration and enumerate permitted HTTP methods — read-only." }
  - { cmd: "nmap -Pn -p80,443 --script http-enum {host}", safety: safe, note: "Enumerate common IIS paths and files (global.asa, web.config backup, trace.axd) — read-only directory brute-force." }
  - { cmd: "curl -sk http://{host}/trace.axd", safety: safe, note: "Check if ASP.NET trace viewer is enabled — reveals request parameters, session state, app internals — read-only." }
  - { cmd: "nuclei -u http://{host} -t cves/ -t exposures/ -severity critical,high", safety: intrusive, note: "Run CVE/exposure templates against IIS — GATED; active HTTP probing, generates significant traffic." }
references: ["CVE-2021-31166 (HTTP Protocol Stack RCE)", "CVE-2022-30209 (IIS authentication)", "CVE-2017-7269 (WebDAV ScStoragePathFromUrl buffer overflow)", "CVE-2015-1635 (MS15-034 HTTP.sys)", "MSRC IIS advisories"]
mitre: "T1190"
---
# Windows IIS (Internet Information Services)

Internet Information Services (IIS) is Microsoft's web server platform, shipped with Windows Server and widely deployed to host ASP.NET applications, .NET Core APIs, classic ASP, and WebDAV shares. IIS fingerprinting is straightforward from the `Server: Microsoft-IIS/x.x` header and `X-Powered-By: ASP.NET` / `X-AspNet-Version` headers. Historical IIS CVEs span from the Unicode directory traversal of IIS 4/5 to the HTTP Protocol Stack worm-grade RCE (CVE-2021-31166, CVSS 9.8) targeting Windows 10/Server 2019/2022 HTTP.sys kernel driver.

**Common exposures.** Outdated IIS versions with unpatched HTTP.sys (CVE-2015-1635 / MS15-034 allows remote DoS and potentially RCE; CVE-2021-31166 is wormable pre-auth RCE). WebDAV enabled with PUT/MOVE methods permitting webshell upload. ASP.NET `trace.axd` enabled in production exposing request parameters and session data. `web.config` backup files (`.bak`, `~`, `.old`) discoverable via directory brute-force containing connection strings and secrets. Application pool accounts running as SYSTEM rather than least-privilege service accounts.

**Safe-first testing.** Start with HTTP header analysis: `Server` header gives IIS version, `X-Powered-By` and `X-AspNet-Version` give ASP.NET framework version. Use `http-methods` NSE to check for PUT/DELETE/WebDAV enabled — read-only enumeration of supported methods. Check `trace.axd`, `elmah.axd`, and common backup file paths. Run Nuclei templates for IIS-specific CVEs only with authorization; `http-enum` performs directory brute-force which generates significant web server log entries.

**Remediation.** Keep Windows Server and IIS patched via WSUS/Windows Update; disable WebDAV unless explicitly required; remove `trace.axd` and debug handlers from production `web.config`; run application pools under least-privilege service accounts (not SYSTEM or Network Service); suppress `Server` and `X-Powered-By` headers; enforce HTTPS with HSTS; apply URL rewrite rules to block access to backup files; and monitor IIS access logs for directory traversal patterns and unusual file extensions.
