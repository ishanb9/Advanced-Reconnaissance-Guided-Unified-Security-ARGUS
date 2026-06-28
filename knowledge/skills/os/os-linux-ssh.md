---
id: os-linux-ssh
technology: "Linux SSH (Secure Shell)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: []
  banners: ["SSH-2.0-OpenSSH", "SSH-1.99", "SSH-2.0-Dropbear", "SSH-2.0-libssh"]
  markers: ["OpenSSH", "Dropbear", "libssh"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p22 --script ssh2-enum-algos,ssh-hostkey {host}", safety: safe, note: "Enumerate supported key-exchange, cipher, and MAC algorithms plus host key fingerprint — read-only." }
  - { cmd: "ssh-audit {host}", safety: safe, note: "Full SSH configuration audit: deprecated algorithms, CVE exposure, policy compliance — read-only." }
  - { cmd: "nmap -Pn -p22 --script ssh-auth-methods --script-args 'ssh.user=root' {host}", safety: safe, note: "Enumerate auth methods accepted for a given username — read-only." }
  - { cmd: "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{host}", safety: intrusive, note: "Password brute-force — GATED; produces auth log entries and may trigger fail2ban." }
  - { cmd: "ssh -i id_rsa -o StrictHostKeyChecking=no user@{host}", safety: intrusive, note: "Private key authentication attempt — GATED; requires a candidate key." }
references: ["CVE-2023-38408 (OpenSSH agent)", "CVE-2024-6387 (regreSSHion)", "CVE-2016-0777", "NIST SP 800-70"]
mitre: "T1021.004"
---
# Linux SSH (Secure Shell)

SSH (Secure Shell) on **22/tcp** is the primary remote-access protocol for Linux and Unix systems. OpenSSH is the dominant implementation; Dropbear is common on embedded Linux. SSH provides encrypted interactive shell access, file transfer (SCP/SFTP), and port-forwarding tunnels. It is both the first point of entry for attackers and the mechanism used for lateral movement once credentials or keys are obtained.

**Common exposures.** Root login enabled (`PermitRootLogin yes`), password authentication left enabled alongside weak credentials, deprecated key-exchange algorithms (diffie-hellman-group1-sha1), outdated OpenSSH versions (e.g., the 2024 **regreSSHion** CVE-2024-6387 re-introduced a signal-handler race RCE in glibc Linux builds of OpenSSH 8.5p1–9.7p1), agent forwarding to untrusted hosts leaking key material, and authorized_keys files with overly permissive entries are all prevalent findings.

**Safe-first testing.** Use `ssh-audit` or the `ssh2-enum-algos` NSE script to enumerate algorithm support and spot deprecated primitives — both are fully read-only and generate only normal connection/negotiation traffic. Check `ssh-auth-methods` to see if password auth is accepted before escalating to credential-based tests. Only run brute-force (Hydra, Medusa) or key-testing after explicit scope confirmation; even read-only probes may trigger intrusion-detection tools like Fail2Ban.

**Remediation.** Disable password authentication (`PasswordAuthentication no`); require SSH key pairs with strong key types (Ed25519); disable root login or restrict to command-specific keys; apply OS patches promptly given the regreSSHion severity; use `AllowUsers`/`AllowGroups` directives; place SSH behind a bastion or VPN for internet-facing hosts; configure `MaxAuthTries 3`; and monitor `/var/log/auth.log` or journald for repeated failures and unusual source IPs.
