---
id: os-windows-adcs
technology: "Windows Active Directory Certificate Services (AD CS)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: []
  banners: ["Microsoft Active Directory Certificate Services", "certsrv"]
  markers: ["/certsrv/", "certenroll", "Active Directory Certificate Services", "CA Web Enrollment"]
quick_wins:
  - { cmd: "nmap -Pn -p80,443 --script http-title,http-auth-finder {host}", safety: safe, note: "Detect AD CS web enrollment page (/certsrv) from HTTP title — read-only." }
  - { cmd: "certipy find -u 'user@domain.local' -p '<password>' -dc-ip {host} -stdout", safety: safe, note: "Enumerate AD CS configuration, certificate templates, and ESC misconfigurations — read-only LDAP/RPC queries." }
  - { cmd: "certipy find -u 'user@domain.local' -p '<password>' -dc-ip {host} -vulnerable -stdout", safety: safe, note: "Filter enumeration to only show vulnerable certificate templates (ESC1-ESC8) — read-only." }
  - { cmd: "certipy req -u 'user@domain.local' -p '<password>' -ca 'CA-Name' -template 'VulnerableTemplate' -upn 'admin@domain.local' -dc-ip {host}", safety: intrusive, note: "ESC1: request cert with SAN override for domain admin — GATED; active certificate request, leaves audit trail in CA logs." }
references: ["CVE-2022-26923 (Certifried)", "CVE-2021-36942 (PetitPotam NTLM relay to AD CS)", "SpecterOps 'Certified Pre-Owned' whitepaper (ESC1-ESC8)", "KEV CVE-2021-36942"]
mitre: "T1649"
---
# Windows Active Directory Certificate Services (AD CS)

Active Directory Certificate Services (AD CS) is Microsoft's PKI implementation, built into Windows Server and widely deployed in enterprise Active Directory domains to issue certificates for authentication, code signing, email encryption, and VPN. SpecterOps's "Certified Pre-Owned" research (2021) revealed **ESC1–ESC8**: eight classes of misconfiguration that allow domain users to escalate to Domain Admin in minutes by abusing certificate templates, enrollment permissions, and NTLM relay chains. AD CS misconfigurations are now one of the most impactful and widely exploited Windows domain attack vectors.

**Critical ESC classes.** ESC1 (template allows SAN override + any domain user can enroll + authentication EKU set) allows any domain user to request a certificate for any principal including Domain Admins. ESC8 (NTLM relay to AD CS HTTP enrollment endpoint) combined with PetitPotam/PrinterBug coercion forces a Domain Controller to authenticate to an attacker — the NTLM credentials are relayed to AD CS to obtain a DC certificate, enabling DCSync. CVE-2021-36942 (PetitPotam) is in CISA's KEV and directly enables ESC8. CVE-2022-26923 (Certifried) allowed machine-account-based privilege escalation to Domain Admin via certificate subject manipulation.

**Safe-first testing.** Use `certipy find` (by ly4k) to enumerate all AD CS configuration via authenticated LDAP and RPC — it is read-only and produces a comprehensive JSON/Bloodhound-compatible output highlighting all ESC misconfigurations. The `-vulnerable` flag filters to only actionable findings. This is the standard first step in any Windows domain assessment. Exploitation (certificate requests) should only proceed after scope confirmation; certificate requests are logged in the CA's certificate database and Windows Security event logs.

**Remediation.** Run `certipy find` or Microsoft's own ESC audit scripts to inventory all certificate templates; disable the `ENROLLEE_SUPPLIES_SUBJECT` flag on templates unless specifically required; restrict template enrollment to specific security groups rather than "Domain Users" or "Authenticated Users"; enable AD CS audit logging (Event IDs 4886/4887); require CA Manager approval for sensitive templates; protect the AD CS HTTP enrollment endpoint from NTLM relay by enabling Extended Protection for Authentication (EPA); and apply patches for CVE-2021-36942 and CVE-2022-26923.
