---
id: ldap
technology: "LDAP / Global Catalog"
domain: IT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [389, 636, 3268, 3269]
  banners: ["ldap", "active directory", "openldap", "389 directory", "domaincontroller"]
  markers: ["ldap://", "ldaps://", "defaultnamingcontext", "rootdse", "gc._msdcs"]
quick_wins:
  - { cmd: "nmap -p 389,636,3268,3269 --script ldap-rootdse {host}", safety: safe, note: "Pull rootDSE via anonymous bind — reveals domain naming contexts, supported LDAP versions, and domain functional level without authentication" }
  - { cmd: "ldapsearch -x -H ldap://{host} -b '' -s base '(objectClass=*)' namingContexts defaultNamingContext dnsHostName ldapServiceName", safety: safe, note: "Anonymous rootDSE query to extract domain DN, hostname, and Kerberos realm" }
  - { cmd: "ldapsearch -x -H ldap://{host} -b 'DC=example,DC=com' '(objectClass=user)' sAMAccountName userPrincipalName memberOf pwdLastSet", safety: intrusive, note: "Anonymous or low-priv bind enumeration of AD user objects — requires unauthenticated bind to be enabled or valid credentials" }
  - { cmd: "nmap -p 389 --script ldap-search --script-args 'ldap.base=\"dc=example,dc=com\"' {host}", safety: intrusive, note: "NSE-driven LDAP object enumeration across the directory partition" }
  - { cmd: "ldapsearch -x -H ldap://{host}:3268 -b '' -s base '(objectClass=*)' namingContexts", safety: safe, note: "Global Catalog (port 3268) rootDSE probe — enumerates all forest partitions, broader scope than single-domain LDAP" }
  - { cmd: "bloodhound-python -u <user> -p <pass> -d <domain> -dc {host} -c All --zip", safety: intrusive, note: "BloodHound LDAP/RPC collection — maps AD ACL attack paths, Kerberoastable accounts, delegation misconfigs" }
  - { cmd: "netexec ldap {host} -u '' -p '' --users", safety: intrusive, note: "NetExec anonymous LDAP user enumeration; escalate with -u/-p for authenticated queries" }
  - { cmd: "netexec ldap {host} -u <user> -p <pass> --kerberoasting kerberoast.txt", safety: intrusive, note: "Extract Kerberoastable SPNs via authenticated LDAP for offline cracking — do not crack without explicit scope approval" }
references:
  - "CVE-2017-8563"
  - "CVE-2021-42287"
  - "CVE-2021-42278"
  - "CVE-2024-49113"
  - "CISA KEV CVE-2021-42287"
mitre: "T1087.002"
---
# LDAP / Global Catalog guidance

LDAP (Lightweight Directory Access Protocol) runs on TCP 389 (plaintext / STARTTLS) and TCP 636 (LDAPS). In Active Directory environments the Global Catalog extends these to ports 3268/3269, exposing a forest-wide read-only replica of all objects rather than a single domain partition. Every domain controller advertises its capabilities via the rootDSE — a zero-auth entry at the base DN — making it the natural first-touch during enumeration: a single anonymous bind returns the domain naming context, DNS hostname, Kerberos realm, and LDAP schema version without triggering account lockout.

From an authorized pentest perspective, LDAP is the highest-value enumeration channel in Windows environments. Anonymous or guest-level binds (common on misconfigured AD, older OpenLDAP deployments, and some network appliances) expose full user, group, computer, and GPO objects. Even with valid low-privilege credentials, LDAP unlocks BloodHound collection, Kerberoasting (SPN enumeration), ASREPRoasting (accounts with pre-auth disabled), ACL analysis, and trust mapping — all of which feed privilege escalation chains. The Global Catalog at 3268 is especially useful because a single query returns objects from every domain in the forest.

Always start with safe, read-only rootDSE probes before escalating to authenticated enumeration. Confirm the domain DN from rootDSE output before constructing search base arguments to avoid noisy failed queries. When running BloodHound or NetExec collection, use the least-privilege credentials available and avoid write operations (LDAP modify/add/delete) unless the engagement scope explicitly covers AD object manipulation. LDAPS (636/3269) should be preferred when credentials are used to prevent credential sniffing, though self-signed certificates are common and typically must be accepted during testing.

Key exposures include: unauthenticated bind enabled (directory browsable without credentials), null base search returning all objects, cleartext LDAP used by applications passing credentials in-band, weak Kerberos service account passwords surfaced via Kerberoasting, and overly permissive ACLs (GenericAll / WriteDACL) on sensitive objects that allow privilege escalation without any exploit. Remediation centres on enforcing LDAP signing and channel binding (KB4520412), disabling anonymous and guest binds, enforcing LDAPS for application integrations, and auditing SPN registrations and ACL delegations with BloodHound or PingCastle on a regular cadence.
