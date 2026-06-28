---
id: nas_appliances
technology: "NAS (Synology/QNAP/WD)"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [5001, 49152]
  banners:
    - "Synology"
    - "QNAP"
    - "Western Digital"
    - "WD My Cloud"
    - "DSM"
    - "QTS"
    - "NAS Web Manager"
    - "X-Powered-By: Synology"
    - "Server: nginx (Synology)"
    - "Server: Apache (QNAP)"
  markers:
    - "/webman/login.cgi"
    - "/cgi-bin/authLogin.cgi"
    - "DiskStation Manager"
    - "QTS Web Console"
    - "/api/2.0/entry.cgi"
    - "My Cloud"
    - "var L10N"
    - "SYNO.API.Info"
quick_wins:
  - { cmd: "curl -sk https://{host}:5001/ -I | grep -Ei 'server|x-powered|dsm|qts|location'", safety: safe, note: "Grab DSM/QTS HTTP response headers; reveals vendor and sometimes firmware version string." }
  - { cmd: "nmap -Pn -sV -p5000,5001,8080,49152 --script http-title,http-headers {host}", safety: safe, note: "Banner grab on common NAS management ports; http-title returns DSM/QTS/MyCloud page title with version." }
  - { cmd: "curl -sk 'https://{host}:5001/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all' | python3 -m json.tool", safety: safe, note: "Synology unauthenticated API enumeration endpoint — lists all available API namespaces and max supported versions without credentials." }
  - { cmd: "curl -sk 'http://{host}:8080/cgi-bin/authLogin.cgi' | grep -Ei 'version|firmware|model|QTS'", safety: safe, note: "QNAP unauthenticated auth page leaks firmware version and model in HTML/JSON response body." }
  - { cmd: "curl -sk 'http://{host}/api/2.0/rest/public/release-notes/firmware' -H 'Content-Type: application/json'", safety: safe, note: "WD My Cloud REST endpoint — returns firmware version unauthenticated on older appliances." }
  - { cmd: "nmap -Pn -sV -p5000,5001 --script http-auth,http-form-fuzzing {host}", safety: intrusive, note: "Probes auth mechanism; may trigger lockout on hardened appliances." }
references:
  - "CVE-2021-28799"
  - "CVE-2021-31439"
  - "CVE-2022-27593"
  - "CVE-2023-27992"
  - "CVE-2019-11189"
  - "CVE-2022-36537"
  - "CVE-2021-35941"
  - "CVE-2022-4504"
mitre: "T1190"
---
# NAS Appliances (Synology / QNAP / WD My Cloud)

Network-Attached Storage appliances from Synology (DSM), QNAP (QTS/QuTS hero), and Western
Digital (My Cloud OS / WD My Cloud) are consumer and SMB devices that frequently expose a
full-featured web management interface directly to the internet. They hold terabytes of backup
data, run third-party packages (Docker, VPN, mail, Plex), and often serve as implicit jump
points into the internal LAN. Because owners rarely patch appliance firmware, NAS devices are
a persistent, high-value target — appearing by the millions on Shodan and Censys.

**Ransomware families targeting NAS.** DeadBolt (2021-2022) hit Synology and QNAP by
exploiting pre-auth RCE in the Photo Station module (CVE-2021-28799) and the Netatalk AFP
daemon (CVE-2021-31439), encrypting shares and dropping ransom notes directly in the web
console. eCh0raix (QNAPCrypt / ThunderX variant) targeted QNAP QTS devices via brute-forced
admin credentials and known unpatched RCE paths, appearing in two major waves (2019, 2021).
WD My Cloud suffered a hardcoded backdoor credential (CVE-2021-35941) and multiple pre-auth
RCEs in the My Cloud OS 3 REST API (CVE-2022-36537), leading to mass remote compromise events.
These ransomware lineages share a common dependency on internet-exposed management ports
combined with delayed or missing firmware updates.

**Safe-first enumeration.** Start with unauthenticated banner and API discovery only. Synology's
`SYNO.API.Info` endpoint (`/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=all`)
returns full API capability metadata without credentials — this is the canonical fingerprinting
path. QNAP's `authLogin.cgi` page embeds the firmware version string in HTML. WD My Cloud exposes
a REST API under `/api/2.0/` with several unauthenticated informational endpoints on older firmware.
Version resolution lets you cross-reference against the CVE/firmware tables without ever attempting
a login. Never attempt credential stuffing or brute-force on production appliances; default Synology
DSM and QTS configurations auto-block IPs after repeated failed logins.

**Key risks and remediation.** The highest-risk configurations are: (1) management UI accessible
from the internet (port 5000/5001 for Synology, 8080/8081 for QNAP, 80/443 for WD); (2) firmware
older than the vendor security bulletin that patched DeadBolt/eCh0raix targets; (3) default or
weak admin credentials; (4) QuickConnect / EZ-Connect relay services that circumvent firewall rules
silently. Recommended remediation: block all management ports at the perimeter; enable two-factor
authentication in DSM/QTS admin console; disable UPnP port-mapping; apply all firmware updates
promptly (Synology and QNAP both issue emergency out-of-cycle patches for critical NAS CVEs);
enable ransomware protection / immutable snapshots where the firmware supports it; and review
which third-party packages (Photo Station is especially impactful) are installed and exposed.
