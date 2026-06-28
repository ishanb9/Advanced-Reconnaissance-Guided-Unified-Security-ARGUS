---
id: os-freebsd
technology: "FreeBSD / OpenBSD"
domain: IT
category: os
transport: ip
safety_class: safe
severity: medium
life_safety: false
match:
  ports: []
  banners: ["FreeBSD", "OpenBSD", "NetBSD", "SSH-2.0-OpenSSH_.*BSD"]
  markers: ["FreeBSD", "OpenBSD", "pfSense", "OPNsense", "FreeNAS/TrueNAS"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22 --script ssh-hostkey,banner {host}", safety: safe, note: "Fingerprint BSD variant from SSH banner string (e.g. 'SSH-2.0-OpenSSH_9.3 FreeBSD-20230719') — read-only." }
  - { cmd: "nmap -Pn -sV -p22,80,443,8080 --script http-title,http-server-header {host}", safety: safe, note: "Fingerprint BSD-based firewall/NAS appliances (pfSense, OPNsense, TrueNAS) from web UI — read-only." }
  - { cmd: "ssh user@{host} 'uname -a; id; sudo -l; sockstat -l'", safety: intrusive, note: "Post-access BSD enumeration: kernel, user context, sudo rules, listening sockets — GATED." }
  - { cmd: "ssh user@{host} 'find / -perm -4000 -ls 2>/dev/null; pkg audit -F'", safety: intrusive, note: "SUID binary and installed package vulnerability audit — GATED; post-access." }
references: ["CVE-2020-7461 (FreeBSD dhclient RCE)", "CVE-2019-5611 (FreeBSD kernel)", "CVE-2022-23093 (ping buffer overflow)", "pfSense CVE-2023-42326", "FreeBSD Security Advisories"]
mitre: "T1082"
---
# FreeBSD / OpenBSD

FreeBSD and OpenBSD are UNIX-derived operating systems widely used as the foundation for network appliances, firewalls, and storage systems. **pfSense** and **OPNsense** (both FreeBSD-based) are the most widely deployed open-source firewall platforms globally; **TrueNAS** (formerly FreeNAS) runs on FreeBSD. OpenBSD's security-first design philosophy (memory protections, W^X, pledge/unveil syscall sandboxing) makes it an extremely hardened target, while FreeBSD's production workloads in appliances introduce CVE exposure through vendor-specific customizations and delayed patching.

**Common exposures.** pfSense/OPNsense web UIs (80/443) are frequently internet-exposed and have had critical authenticated-and-unauthenticated RCE CVEs (pfSense CVE-2023-42326 — command injection). FreeBSD's `dhclient` (CVE-2020-7461) allowed a malicious DHCP server to execute arbitrary code. The `ping` utility buffer overflow (CVE-2022-23093) required root privileges but was SUID-set. BSD jails (containers) are generally well-isolated but shared kernel vulnerabilities affect all jails. Network-facing daemons (ntpd, ftpd, lpd) in legacy FreeBSD installs carry old CVEs.

**Safe-first testing.** The most reliable BSD fingerprinting is the SSH banner — OpenSSH on BSD includes the distribution name and date in the version string. For appliance web UIs (pfSense, OPNsense, TrueNAS), read the login page title and HTTP server headers. Post-access, `uname -a` gives exact kernel version; `pkg audit -F` (FreeBSD) queries the vulnerability database for installed packages; `pkg_info` (OpenBSD) lists packages. Avoid exploit attempts against firewall appliances — disruption is extremely high-impact.

**Remediation.** Apply FreeBSD Security Advisories (security.freebsd.org) and errata patches promptly; for pfSense/OPNsense, run appliance updates from the web UI; restrict web management interfaces to management VLANs with no internet exposure; use HTTPS only for web UIs with strong TLS; disable unused services in `/etc/inetd.conf` and `rc.conf`; enable OpenBSD's pledge/unveil for custom daemons; and audit SUID bits with `find / -perm -4000`.
