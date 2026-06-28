---
id: os-windows-winrm
technology: "Windows WinRM / PowerShell Remoting"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [5985, 5986]
  banners: ["WSMan", "WinRM", "PowerShell"]
  markers: ["wsman", "/wsman", "application/soap+xml"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p5985,5986 --script http-auth-finder {host}", safety: safe, note: "Enumerate WinRM HTTP/HTTPS listener and authentication methods — read-only." }
  - { cmd: "curl -s -o /dev/null -w '%{http_code}' http://{host}:5985/wsman", safety: safe, note: "Confirm WinRM HTTP listener presence by HTTP status code." }
  - { cmd: "evil-winrm -i {host} -u Administrator -p '<password>'", safety: intrusive, note: "Authenticated interactive shell — GATED; requires valid credentials." }
  - { cmd: "crackmapexec winrm {host} -u users.txt -p passwords.txt", safety: intrusive, note: "Credential spray over WinRM — GATED; generates auth failures and lockouts." }
references: ["CVE-2021-31166", "MS-WSMV specification", "MITRE T1021.006"]
mitre: "T1021.006"
---
# Windows WinRM / PowerShell Remoting

Windows Remote Management (WinRM) is Microsoft's implementation of WS-Management (WS-Man) and serves as the transport for PowerShell Remoting. It listens on **5985/tcp** (HTTP) and **5986/tcp** (HTTPS). When enabled and reachable, WinRM provides authenticated command execution with full PowerShell access — making it a high-value lateral-movement vector after credential compromise. Unlike RDP, WinRM is commonly enabled on servers by default in modern Windows Server installations.

**Common exposures.** WinRM is frequently enabled on domain-joined servers for remote administration. Misconfigurations include allowing HTTP (plaintext) on 5985, accepting any host in the TrustedHosts list, or exposing it to the internet on cloud VMs. Attackers with valid domain credentials (obtained via phishing, credential dumping, or Kerberoasting) often pivot laterally across the network using `Invoke-Command` or tools like Evil-WinRM and CrackMapExec.

**Safe-first testing.** Confirm the WinRM listener with an HTTP probe or Nmap service scan — both are read-only and produce no authentication events. Check the authentication methods offered (Negotiate/Kerberos/Basic) and whether HTTP or HTTPS is in use. Only proceed to authenticated testing (Evil-WinRM, CrackMapExec) after explicit scope authorization; even a single login generates Windows Security event logs.

**Remediation.** Disable WinRM where not needed; enforce HTTPS (5986) only; restrict listener access with IPSec or Windows Firewall rules to jump hosts and management subnets; require Kerberos authentication (not NTLM or Basic); audit TrustedHosts configuration; and monitor Event IDs 4624/4688 for unexpected PowerShell remoting sessions.
