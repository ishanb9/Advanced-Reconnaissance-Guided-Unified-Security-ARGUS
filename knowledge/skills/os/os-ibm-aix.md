---
id: os-ibm-aix
technology: "IBM AIX"
domain: IT
category: os
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [657, 32768]
  banners: ["AIX", "IBM AIX", "rsct"]
  markers: ["aixterm", "RSCT", "IBM_PowerPC", "AIX Version"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p111,22,657 --script rpcinfo,banner {host}", safety: safe, note: "Enumerate RPC services and banner-grab on AIX management ports — read-only." }
  - { cmd: "nmap -Pn -sV --script banner -p 22,111,514,657,32768 {host}", safety: safe, note: "Banner-grab across common AIX service ports to confirm version — read-only." }
  - { cmd: "ssh user@{host} 'oslevel -s; id; lsuser -a ALL; netstat -an'", safety: intrusive, note: "Post-access AIX enumeration: OS level, users, network state — GATED; requires credentials." }
  - { cmd: "ssh user@{host} 'find / -perm -4000 -ls 2>/dev/null'", safety: intrusive, note: "SUID binary enumeration on AIX — GATED; post-access read-only FS enumeration." }
references: ["CVE-2015-5600 (OpenSSH on AIX)", "CVE-2021-38951 (IBM AIX nimsh)", "IBM Security Bulletins", "IBM PSIRT advisories"]
mitre: "T1082"
---
# IBM AIX

IBM AIX (Advanced Interactive eXecutive) is a UNIX operating system running on IBM Power Systems hardware. It is deployed in large banks, insurance companies, airlines, and government agencies running core transaction systems (COBOL/RPG applications, IBM DB2, WebSphere). AIX presents a distinct attack surface: NIM (Network Installation Management) on **657/tcp**, IBM's RSCT (Reliable Scalable Cluster Technology) cluster daemons on high RPC ports, `nimsh` (NIM service handler), and legacy RPC services inherited from UNIX System V.

**Common exposures.** AIX systems are often long-lived with infrequent patching due to the criticality of hosted applications. Legacy remote services (rsh, rlogin, rexec) are sometimes enabled for legacy application compatibility. `nimsh` (IBM's network installation protocol) has had authenticated-but-weak RCE vulnerabilities. AIX's C2 security mode is rarely enabled, leaving audit trails minimal. SUID binaries on AIX include AIX-specific utilities that may not appear in generic Linux GTFOBins lists but have equivalent escalation paths.

**Safe-first testing.** Run `nmap` banner grabs and RPC enumeration to fingerprint AIX version (`oslevel` equivalent via banner: "IBM AIX Version x.y") and identify listening services. Check for `nimsh` (657) and NFS/RPC services. Post-access, `oslevel -s` returns the precise Technology Level and Service Pack — cross-reference with IBM Security Bulletins (www.ibm.com/support/pages/aix-security-advisories). Enumerate SUID binaries and check for world-writable files in `/usr/lib` which are AIX-specific risk areas.

**Remediation.** Apply IBM AIX Technology Level and Service Pack updates on a regular schedule; disable legacy remote access services (rsh/rlogin/rexec) in `/etc/inetd.conf`; restrict NIM access to management hosts only; enable AIX Audit subsystem; enforce AIX Role-Based Access Control (RBAC) to limit privilege escalation paths; and audit SUID bits regularly with `find / -perm -4000`.
