---
id: os-solaris
technology: "Oracle Solaris"
domain: IT
category: os
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [111, 32771]
  banners: ["SunOS", "Solaris", "Oracle Solaris"]
  markers: ["SunOS 5", "rpcbind", "dtspcd", "CDE"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p111,22,23,513,514 --script rpcinfo {host}", safety: safe, note: "Enumerate RPC services registered with rpcbind (portmapper) — read-only service discovery." }
  - { cmd: "nmap -Pn -sV --script banner {host}", safety: safe, note: "Banner-grab across open ports to fingerprint Solaris version from SunOS banner strings — read-only." }
  - { cmd: "rpcinfo -p {host}", safety: safe, note: "List all RPC programs and versions registered on the host — read-only enumeration." }
  - { cmd: "ssh user@{host} 'uname -a; zonename; ppriv -v all; isainfo -v'", safety: intrusive, note: "Post-access Solaris enumeration: kernel, zone context, privileges, ISA — GATED." }
references: ["CVE-2019-2725 (Oracle WebLogic RCE)", "CVE-2010-4435 (Solaris rpc.walld)", "CVE-2017-10151 (Solaris CDE dtspcd)", "Oracle CPU advisories"]
mitre: "T1082"
---
# Oracle Solaris

Oracle Solaris (formerly Sun Solaris, derived from AT&T System V UNIX) remains in production at banks, telcos, and critical infrastructure operators running SPARC or x86-64 hardware. Solaris exposes a distinctive set of legacy services: **rpcbind (portmapper) on 111/tcp/udp**, CDE (Common Desktop Environment) services on high dynamic RPC ports, and Solaris-specific daemons such as `dtspcd`, `rpc.ttdbserverd`, and `rpc.walld`. These legacy services carried numerous unauthenticated RCE CVEs through the 2000s and 2010s, many of which remain unpatched on long-lived production installations.

**Common exposures.** Solaris boxes in legacy environments frequently run with legacy RPC services enabled, NFS exported shares with `no_root_squash`, telnet enabled alongside SSH, CDE enabled on SPARC workstations, and outdated patch bundles (Oracle's Solaris patch process is distinct from Linux package managers and often neglected). Solaris zones (containers) are widely used but zone-to-global-zone escape vectors exist when shared datasets or network namespaces are misconfigured.

**Safe-first testing.** Begin with banner-grabbing and RPC enumeration (`rpcinfo -p`) — both are read-only and reveal the full catalog of listening RPC services including version numbers. Cross-reference against the Oracle CPU (Critical Patch Update) matrix for known vulnerabilities on the observed Solaris version. After gaining SSH access, enumerate zone context (`zonename`), privilege sets (`ppriv -v all`), and kernel version (`uname -a`) to identify escalation paths.

**Remediation.** Disable all legacy RPC services not required for operations (CDE, walld, ttdbserverd); restrict NFS exports with `root_squash`; migrate from telnet/rsh/rlogin to SSH; apply Oracle CPU patches on the quarterly schedule at minimum; use Solaris Zones with least-privilege configurations; enable Solaris Audit (`auditd`) for privileged operations; and restrict rpcbind access with IP Filter or TCP Wrappers.
