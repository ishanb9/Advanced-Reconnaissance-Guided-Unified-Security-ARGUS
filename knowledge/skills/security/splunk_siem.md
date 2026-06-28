---
id: splunk_siem
technology: "Splunk Enterprise SIEM"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [8089, 9997]
  banners: ["splunk", "splunkd", "splunk enterprise", "splunk cloud"]
  markers: ["/en-US/account/login", "/services/server/info", "splunkd_session", "X-Splunkd-Build", "splunk-build"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}:8089/services/server/info 2>/dev/null | grep -i 'x-splunkd\\|version\\|build\\|serverName'", safety: safe, note: "Splunkd REST API server info endpoint — version and hostname disclosure from HTTP response headers without credentials." }
  - { cmd: "curl -sk -D - https://{host}:8089/services -u 'admin:' | head -30", safety: safe, note: "Splunkd management port (8089) header grab — confirms Splunk REST API presence and build from X-Splunkd-Build header." }
  - { cmd: "nmap -Pn -sT -p8089,9997 --script http-title,ssl-cert {host}", safety: safe, note: "Splunkd API (8089) and data receiver (9997) port scan — confirm Splunk components and TLS certificate metadata." }
  - { cmd: "curl -sk https://{host}:8089/services/server/info --negotiate -u : 2>/dev/null | grep -i 'VERSION\\|os_build'", safety: safe, note: "Unauthenticated server info probe — some Splunk versions expose build info without credentials on the REST API." }
  - { cmd: "curl -sk -X POST 'https://{host}:8089/services/auth/login' -d 'username=admin&password=changeme' | grep -i 'sessionKey\\|messages'", safety: intrusive, note: "Default credential check against Splunk REST API; produces authentication log in Splunk audit index. Gate with authorisation." }
references:
  - "CVE-2023-46214"
  - "CVE-2022-43571"
  - "CVE-2022-32158"
  - "CVE-2021-33845"
  - "CVE-2019-5002"
  - "CISA KEV 2023-11-16 (Splunk Enterprise RCE)"
mitre: "T1078"
---
# Splunk Enterprise SIEM

Splunk Enterprise is the world's most widely deployed security information and event management (SIEM) platform, used by enterprises, government agencies, and managed security service providers (MSSPs) for log aggregation, threat detection, and incident response. The Splunk daemon (`splunkd`) exposes an HTTPS management REST API on port 8089/tcp, a web UI on port 8000/tcp, and a data receiver (universal forwarder protocol) on port 9997/tcp. Splunk sits in a privileged position in the environment — it ingests logs from nearly every system, and a compromised Splunk instance gives an attacker visibility into all monitored systems as well as the ability to suppress or modify detection rules.

From an offensive perspective, Splunk's management API (8089/tcp) is the primary attack surface. The endpoint `/services/server/info` may disclose version and build information without authentication or with default credentials (`admin:changeme`). CVE-2023-46214 (Splunk XSLT injection enabling RCE, CVSS 8.8) and CVE-2022-43571 (Splunk Enterprise dashboard RCE) are recent exploitable vulnerabilities. CVE-2022-32158 allows a compromised Splunk deployment server to push malicious bundles to Universal Forwarder agents across the monitored environment — an extremely high-impact lateral movement path. The Splunk Universal Forwarder running as SYSTEM on Windows endpoints has been repeatedly abused for code execution.

**Safe-first testing.** Port-scan for 8089 and 9997 to confirm Splunk components. Probe `/services/server/info` for unauthenticated version disclosure. Check for default credentials (`admin:changeme`) under explicit written scope — this is a common finding in enterprise deployments where Splunk was not hardened post-installation. Cross-reference the Splunk version against the advisory list. The data receiver on 9997 accepts Splunk Universal Forwarder connections — probing this unauthenticated is disruptive to logging and must be avoided without explicit authorisation.

**Remediation.** Upgrade Splunk Enterprise to the current release; change the default admin password immediately on deployment; restrict the management API (8089) and web UI (8000) to SIEM administrator and management networks only; enable Splunk's built-in audit logging and alert on admin authentication failures; use TLS for data receiver connections (9997 with SSL certificates); upgrade Universal Forwarders alongside the Splunk server; and apply the deployment server certificate controls to prevent rogue bundle injection (CVE-2022-32158 mitigation).
