---
id: os-windows-server-roles
technology: "Windows Server Roles (SCCM / WSUS / Print Spooler / NPS)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [8530, 8531, 135, 445]
  banners: ["WSUS", "SCCM", "Microsoft Configuration Manager", "Windows Server Update Services"]
  markers: ["/SimpleAuthWebService/SimpleAuth.asmx", "CCM_POST", "/ClientWebService/", "MSWSUS", "spoolss"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p8530,8531,135,445 --script http-title {host}", safety: safe, note: "Fingerprint WSUS (8530/8531) and RPC endpoint mapper (135) — read-only service detection." }
  - { cmd: "curl -sk http://{host}:8530/SimpleAuthWebService/SimpleAuth.asmx", safety: safe, note: "Probe WSUS SimpleAuth endpoint to confirm WSUS presence and version — read-only." }
  - { cmd: "SharpWSUS.exe locate /server:{host}", safety: intrusive, note: "Locate WSUS server and enumerate approved updates — GATED; requires domain credentials, generates RPC traffic." }
  - { cmd: "Invoke-WebRequest -Uri http://{host}:8530/iuident.cab -UseBasicParsing", safety: safe, note: "Download WSUS client CAB to confirm WSUS server identity — read-only HTTP fetch." }
references: ["CVE-2020-1048 (Print Spooler EoP)", "CVE-2021-34527 (PrintNightmare)", "CVE-2020-1113 (WSUS MITM)", "WSUXploit research", "SCCM hierarchy takeover research (SpecterOps)"]
mitre: "T1072"
---
# Windows Server Roles (SCCM / WSUS / Print Spooler / NPS)

Windows Server roles that provide infrastructure services — WSUS (Windows Server Update Services), SCCM/Microsoft Endpoint Configuration Manager, Print Spooler, and NPS (Network Policy Server / RADIUS) — represent a class of high-value lateral-movement and privilege-escalation targets in Windows domains. These services run with elevated privileges, have broad network reach, and frequently have weak authentication or are trusted implicitly by all domain members.

**WSUS attacks.** WSUS on **8530/tcp** (HTTP) and **8531/tcp** (HTTPS) distributes Windows updates to domain clients. A WSUS server configured over HTTP (not HTTPS) is vulnerable to MITM: an attacker on the same network path can intercept the update stream and deliver malicious "updates" signed by a trusted Microsoft certificate using PyWSUS or WSUXploit. This yields code execution on every WSUS client. WSUS servers also accept connections from any domain computer by default.

**PrintNightmare (CVE-2021-34527).** The Windows Print Spooler RPC interface (`spoolss`, port 445) allowed low-privileged domain users to install arbitrary printer drivers — yielding SYSTEM code execution on any Windows host running Spooler. It is in CISA's KEV and was weaponized within days of PoC publication. The SpoolFool variant (CVE-2022-21999) extended the attack surface. Print Spooler is also the coercion vector for NTLM relay attacks via SpoolSample / PrinterBug.

**SCCM.** Configuration Manager (SCCM) hierarchy takeover is documented by SpecterOps — a compromised Distribution Point or site server can be leveraged to push malicious applications to all managed clients. SCCM often stores credentials in the site database and has HTTP fallback channels.

**Safe-first testing.** Confirm WSUS with an HTTP probe to `/SimpleAuthWebService/SimpleAuth.asmx` — read-only. Enumerate SCCM with `SharpSCCM` (requires domain credentials) or passive network observation of CCM traffic. Check Print Spooler status via RPC endpoint mapper (135) enumeration. Enumerate NPS/RADIUS with targeted Nmap scripts. Only proceed to exploitation after explicit scope authorization.

**Remediation.** Enforce WSUS over HTTPS only; restrict WSUS to management VLANs; disable Windows Print Spooler on servers that do not function as print servers; apply PrintNightmare patches and enable the Point and Print restrictions GPO; harden SCCM with HTTPS-only communications and NAA account isolation; segment NPS/RADIUS servers from general network access; and monitor for lateral movement via SMB and RPC.
