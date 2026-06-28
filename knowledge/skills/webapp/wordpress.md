---
id: wordpress
technology: "WordPress"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["WordPress", "wp-content", "wp-includes"]
  markers: ["/wp-login.php", "/wp-admin/", "/wp-json/wp/v2/", "wp-content/plugins", "generator\" content=\"WordPress"]
quick_wins:
  - { cmd: "curl -s https://{host}/wp-json/wp/v2/users | jq '.[].name,.slug'", safety: safe, note: "REST API user enumeration — unauthenticated, read-only. Reveals author logins." }
  - { cmd: "wpscan --url https://{host} --enumerate p,t,u --api-token <TOKEN>", safety: safe, note: "Passive plugin/theme/user enumeration with WPScan; read-only, uses vuln DB." }
  - { cmd: "curl -s https://{host}/?author=1 -L | grep -o 'Posts by [^<]*'", safety: safe, note: "Author-ID brute enumerate via redirect — read-only admin username leak." }
  - { cmd: "wpscan --url https://{host} --passwords /usr/share/wordlists/rockyou.txt --usernames admin", safety: intrusive, note: "GATED — credential brute-force against xmlrpc/wp-login; generates auth log noise." }
references: ["CVE-2024-27956","CVE-2023-2732","CVE-2022-21661","KEV CISA AA23-040A"]
mitre: "T1190"
---
# WordPress

WordPress powers roughly 43 % of all websites globally, making it the largest single attack surface
on the public internet. Its plugin ecosystem (60 000+ plugins) is the primary source of critical
vulnerabilities — SQLi, XSS, RCE, and arbitrary file upload flaws appear weekly.
The WordPress REST API (`/wp-json/wp/v2/users`) exposes author usernames unauthenticated by default,
making credential-stuffing and brute-force trivial when combined with `xmlrpc.php` (which allows
unlimited login attempts per POST) or the standard login page.

**Key attack surfaces.** `xmlrpc.php` (should be disabled or blocked), the login page at `/wp-login.php`,
exposed `debug.log` files (`/wp-content/debug.log`), the REST API, and vulnerable plugins/themes
(especially those with LFI or SQLi in shortcodes). CVE-2024-27956 (WP Automatic plugin SQLi),
CVE-2022-21661 (core WP_Query SQLi), and stored-XSS chains in popular themes are frequently weaponized.
Unauthenticated attackers who gain subscriber-level access can often escalate via privilege-escalation
plugin bugs to `administrator`, then plant webshells via the theme editor.

**Safe-first testing.** Begin with `wpscan` in passive/enumerate mode (`--enumerate p,t,u`) and the
REST API for user disclosure. Confirm plugin version exposure via `/wp-content/plugins/<name>/readme.txt`.
Check `robots.txt` and `sitemap.xml` for sensitive URL leaks. Do not attempt login brute-force without
explicit authorization; do not activate or upload themes/plugins (modifies state).

**Remediation.** Enforce auto-updates for core, plugins, and themes. Block `xmlrpc.php` at the WAF or
`nginx`/`.htaccess` level. Restrict REST API user endpoint (`/wp-json/wp/v2/users`) to authenticated
requests. Deploy a WAF (Wordfence, Cloudflare) and enforce MFA on all admin accounts. Disable the
theme/plugin editor in `wp-config.php` (`define('DISALLOW_FILE_EDIT', true)`).
