---
id: smb_ad
technology: "Active Directory / SMB"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [445, 139, 389, 636, 88, 464, 3268, 3269]
  banners: ["windows", "samba", "smb", "microsoft-ds", "netbios", "kerberos", "ldap", "active directory"]
  markers: ["krb5", "ldap://", "\\x00SMB", "NTLMSSP", "\x4e\x54\x4c\x4d\x53\x53\x50"]
quick_wins:
  - { cmd: "nmap -p 445 --script smb2-security-mode,smb-security-mode,smb2-capabilities {host}", safety: safe, note: "Detect SMB signing status and dialect; signing-not-required is relay-prerequisite" }
  - { cmd: "nmap -p 445 --script smb-protocols {host}", safety: safe, note: "Enumerate supported SMB dialects including legacy SMBv1" }
  - { cmd: "netexec smb {host} --shares -u '' -p ''", safety: intrusive, note: "Null-session share enumeration; reveals anonymously accessible shares" }
  - { cmd: "netexec smb {host} --rid-brute -u '' -p ''", safety: intrusive, note: "Null-session RID cycling to enumerate domain users and groups" }
  - { cmd: "impacket-rpcdump {host} | grep -i 'samr\\|lsarpc\\|netlogon'", safety: intrusive, note: "Map exposed RPC endpoints useful for further AD enumeration" }
  - { cmd: "impacket-lookupsid {host}/''@{host}", safety: intrusive, note: "Unauthenticated SID lookup to enumerate domain members via null session" }
  - { cmd: "netexec smb {host} -u '' -p '' --pass-pol", safety: intrusive, note: "Retrieve password policy (lockout threshold, min length) without credentials" }
  - { cmd: "impacket-ntlmrelayx -tf targets.txt -smb2support --no-http-server", safety: disruptive, note: "NTLM relay attack — captures and relays credentials; can authenticate to target hosts and execute code. Only run with explicit written authorization." }
references: ["CVE-2017-0144", "CVE-2020-0796", "CVE-2021-36942", "CVE-2019-1040", "CISA KEV CVE-2017-0144", "CISA KEV CVE-2020-0796"]
mitre: "T1021.002, T1557.001, T1110.002, T1078.002"
---
# Active Directory / SMB Guidance

Active Directory (AD) is Microsoft's directory service used by the vast majority of enterprise environments for authentication, authorization, and policy enforcement. Server Message Block (SMB) on TCP 445 is the primary protocol for file sharing and named-pipe RPC communication, and it is deeply integrated with AD authentication via Kerberos and NTLM. Because SMB and AD underpin nearly all Windows lateral movement paths, they are among the highest-value targets in any authorized penetration test.

Begin enumeration with read-only checks: probe SMB signing and dialect negotiation using nmap NSE scripts (smb2-security-mode, smb2-capabilities). SMB signing disabled or not-required is a direct prerequisite for NTLM relay attacks and must be flagged. Follow with null-session probes using NetExec or Impacket — many legacy configurations still allow unauthenticated share listing (IPC$), RID cycling, and password policy retrieval, all of which leak domain topology without any credentials. These intrusive-tier steps require active connection to the target but are non-destructive and should be performed first.

NTLM relay (T1557.001) is the most impactful attack vector: when SMB signing is disabled and an attacker can coerce or intercept NTLM authentication (via LLMNR/NBT-NS poisoning, PetitPotam, or PrinterBug), credentials can be relayed to other hosts — potentially yielding domain-admin access without ever cracking a password. Impacket's ntlmrelayx automates this but is classified disruptive because it actively authenticates to target systems and can execute commands or dump secrets. Gate this step behind explicit written authorization and document every relay target before execution.

Remediation centers on three controls: enforce SMB signing on all hosts via Group Policy (RequireSecuritySignature = 1), disable SMBv1 domain-wide (it has no valid production use), and block inbound NTLM where Kerberos is available (Network Security: Restrict NTLM policy). Null-session access should be removed by setting RestrictAnonymous = 2 in the registry. Patch CVE-2020-0796 (SMBGhost) and CVE-2021-36942 (PetitPotam LSARPC coercion) immediately if unpatched, as both have public exploit code in active use.
