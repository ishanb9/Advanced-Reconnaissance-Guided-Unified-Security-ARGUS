---
id: gitlab
technology: "GitLab"
domain: IT
category: webapp
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["GitLab", "gitlab-workhorse"]
  markers: ["X-Gitlab-Meta", "gitlab-ci.yml", "/users/sign_in", "gl-form-group", "/api/v4/version", "Gitlab-Lb-Id"]
quick_wins:
  - { cmd: "curl -s https://{host}/api/v4/version", safety: safe, note: "Unauthenticated version endpoint on GitLab CE — returns version JSON without auth." }
  - { cmd: "curl -s https://{host}/explore/projects?visibility=public | grep -o 'data-track-label=\"[^\"]*\"' | head -20", safety: safe, note: "Enumerate public projects — read-only discovery of exposed repositories." }
  - { cmd: "curl -s 'https://{host}/-/liveness'", safety: safe, note: "Health/liveness endpoint — confirms GitLab instance, version hints, and component status." }
  - { cmd: "curl -s -X POST 'https://{host}/users/password' -d 'user[email]=victim@corp.com' -H 'Content-Type: application/x-www-form-urlencoded'", safety: intrusive, note: "GATED — CVE-2023-7028 account takeover via password reset email delivery to attacker-controlled secondary email; only against authorized target." }
references: ["CVE-2024-0402","CVE-2023-7028","CVE-2021-22205","CVE-2023-2825","KEV CISA AA24-016A"]
mitre: "T1190"
---
# GitLab

GitLab is a complete DevSecOps platform — source control, CI/CD, container registry, package
registry, and issue tracking in one application. Its broad attack surface and high-value payload
(source code, secrets in CI variables, private container images, and deploy keys) make it a
prime target. CVE-2021-22205 (unauthenticated RCE via ExifTool image processing) was exploited
in the wild within days and appeared in APT-linked intrusion sets. CVE-2023-7028 (account takeover
via secondary email in password reset) achieved KEV listing within a month of disclosure.

**Key attack surfaces.** The ExifTool-based image upload pipeline (CVE-2021-22205) triggered RCE
as the `git` user without authentication on unpatched instances. The Workhorse/Rails split
architecture creates SSRF and path traversal opportunities (CVE-2023-2825 arbitrary file read,
CVE-2024-0402 arbitrary file write). The `/api/v4/` REST API is broad and version-exposed
unauthenticated at `/-/health` and `/api/v4/version`. CI/CD variables set to "protected" can
still be dumped if a branch protection is misconfigured. Runner registration tokens (if leaked)
allow an attacker to register a malicious CI runner and intercept pipeline secrets.

**Safe-first testing.** Check the version endpoint (`/api/v4/version`) and compare against GitLab's
published vulnerability database. Enumerate public projects and exposed `.gitlab-ci.yml` files for
hardcoded secrets. Review group/project visibility settings. If credentials are available, audit
deployed CI variables and runner registration status.

**Remediation.** Keep GitLab updated — security patches are released monthly with clear KEV
advisories. Disable user registration if not required (`Admin → Settings → Sign-up restrictions`).
Enforce OAuth/SAML SSO with MFA. Mark all CI/CD secrets as Protected+Masked. Scope deploy keys
to read-only. Run GitLab behind a reverse proxy; do not expose the bundled Puma/Unicorn ports
directly. Review `/-/admin/runners` for unauthorized runners regularly.
