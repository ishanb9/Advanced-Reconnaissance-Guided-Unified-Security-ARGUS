---
id: drupal
technology: "Drupal"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["Drupal"]
  markers: ["/sites/default/files/", "X-Generator: Drupal", "drupal.js", "/core/misc/drupal.js", "Drupal.settings", "?q=user/login"]
quick_wins:
  - { cmd: "curl -s https://{host}/ -I | grep -i 'x-generator\\|x-drupal'", safety: safe, note: "Header fingerprint — reveals Drupal version without authentication." }
  - { cmd: "curl -s 'https://{host}/CHANGELOG.txt' | head -5", safety: safe, note: "Changelog exposes exact Drupal version — available unauthenticated on older installs." }
  - { cmd: "droopescan scan drupal -u https://{host}", safety: safe, note: "Passive module/theme/version enumeration via known URL patterns; read-only." }
  - { cmd: "curl -s 'https://{host}/user/register' -d 'name[#post_render][]=passthru&name[#type]=markup&name[#markup]=id'", safety: intrusive, note: "GATED — Drupalgeddon2 (CVE-2018-7600) RCE probe; only against authorized target." }
references: ["CVE-2018-7600","CVE-2018-7602","CVE-2019-6340","CVE-2022-25271","KEV CISA"]
mitre: "T1190"
---
# Drupal

Drupal is a widely deployed enterprise CMS used by governments, universities, and Fortune 500 firms.
Its extensible module system, like WordPress plugins, is the primary CVE surface. The "Drupalgeddon"
vulnerabilities (CVE-2018-7600 / SA-CORE-2018-002 and CVE-2018-7602) are among the most massively
exploited web CVEs ever disclosed — unauthenticated RCE via AJAX form rendering and REST API
deserialization (CVE-2019-6340) were trivially weaponized within hours of publication and remain in
active exploitation toolkits years later.

**Key attack surfaces.** The `user/register` and `user/password` endpoints are unauthenticated and have
historically allowed RCE via Form API injection (Drupalgeddon2/3). The REST and JSON:API endpoints
(enabled by default in Drupal 8+) exposed deserialization gadgets in CVE-2019-6340.
`CHANGELOG.txt`, `INSTALL.txt`, and `/core/CHANGELOG.txt` leak exact version numbers unauthenticated.
Persistent XSS in TinyMCE-based fields and SSRF in media modules are recurring theme. Modules like
`webform`, `views`, and `paragraphs` have individually shipped critical SQLi and XSS bugs.

**Safe-first testing.** Fingerprint the version via `CHANGELOG.txt`, `X-Generator` headers, and
`droopescan`. Enumerate installed modules by probing `/modules/<name>/` known paths. Check whether
`update.php` is accessible (`/update.php`) without authentication — a common misconfiguration that
allows schema upgrades. Review `/admin/reports/status` if credentials are available.

**Remediation.** Apply Drupal security updates immediately on release (Drupal's advisory cadence
publishes on Wednesdays). Disable `CHANGELOG.txt` and `README.txt` via `nginx`/`.htaccess`. Restrict
REST/JSON:API to authenticated sessions. Monitor `watchdog` for unusual PHP errors. Enforce an
application WAF rule set for SA-CORE advisories. Disable PHP execution in `sites/default/files/`.
