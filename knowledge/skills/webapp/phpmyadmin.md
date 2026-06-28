---
id: phpmyadmin
technology: "phpMyAdmin"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["phpMyAdmin"]
  markers: ["/phpmyadmin/", "/pma/", "/phpMyAdmin/", "phpMyAdmin", "pma_username", "token=", "PMA_", "/index.php?route=/"]
quick_wins:
  - { cmd: "curl -s https://{host}/phpmyadmin/ | grep -o 'phpMyAdmin [0-9.]*'", safety: safe, note: "Version disclosure from login page — read-only fingerprint." }
  - { cmd: "curl -s -c /tmp/pma_cookie.txt -b /tmp/pma_cookie.txt 'https://{host}/phpmyadmin/index.php' -d 'pma_username=root&pma_password=&server=1' -L | grep -i 'welcome\\|error'", safety: safe, note: "Default empty-password root login attempt — read-only if unsuccessful; reveals auth posture." }
  - { cmd: "curl -s 'https://{host}/phpmyadmin/ChangeLog' | head -5", safety: safe, note: "Changelog file version disclosure — accessible without auth on many installs." }
  - { cmd: "nmap -Pn --script http-phpmyadmin-dir-traversal {host}", safety: intrusive, note: "GATED — CVE-2018-12613 directory traversal probe to read /etc/passwd; only against authorized target." }
references: ["CVE-2018-12613","CVE-2016-5734","CVE-2019-12922","CVE-2023-25727"]
mitre: "T1190"
---
# phpMyAdmin

phpMyAdmin is a PHP-based web interface for MySQL/MariaDB administration, installed on millions of
shared hosting servers and developer environments. Its very nature — a full database administration
tool exposed over HTTP — makes it a high-priority target. Default or empty root passwords, combined
with public Internet exposure, give an attacker the ability to read/dump all databases, write
arbitrary files to the filesystem (via `SELECT ... INTO OUTFILE`), and execute OS commands if the
MySQL `FILE` privilege and `secure_file_priv` are misconfigured. Common paths (`/phpmyadmin/`, `/pma/`,
`/db/`) are routinely brute-forced by automated scanners.

**Key attack surfaces.** Empty or default root password login is the most common initial access
vector. CVE-2016-5734 (remote code execution via preg_replace with /e modifier via table rename)
and CVE-2018-12613 (local file inclusion allowing reads of `/etc/passwd` and PHP configuration)
have been widely exploited. The "Login without password" feature (`$cfg['Servers'][$i]['AllowNoPassword']`)
is a misconfiguration found on many hosting panels. Once authenticated, `LOAD DATA LOCAL INFILE`
or `SELECT INTO OUTFILE` can read/write OS files. SQL tabs allow arbitrary query execution —
dropping entire databases in seconds.

**Safe-first testing.** Identify the phpMyAdmin path via common URL patterns and banner analysis.
Check the version from the login page and `ChangeLog`. Attempt empty-password root login (safe
read, fails loudly on correctly secured instances). Verify whether the setup directory (`/phpmyadmin/setup/`)
is accessible. Do NOT execute any SQL queries, create/drop databases, or write files to the
filesystem.

**Remediation.** Never expose phpMyAdmin on a public-facing IP or port — restrict to localhost or
VPN. Use HTTP basic authentication at the web server level in addition to phpMyAdmin's own auth.
Set a strong root MySQL password; disable remote root login. Set `$cfg['blowfish_secret']` to a
strong random value. Remove the `setup/` directory. Use an allow-list of source IP addresses in
`config.inc.php`. Update phpMyAdmin regularly — it is actively maintained with security fixes.
