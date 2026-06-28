---
id: lutron_lip
technology: "Lutron lighting (LIP)"
domain: IoT
safety_class: safe
severity: medium
life_safety: false
match:
  ports: [23]
  banners: ["GNET>", "LUTRON", "Telnet Listener"]
  markers: ["GNET>"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p23 --script telnet-ntlm-info,banner {host}", safety: safe, note: "Grab telnet banner — confirms GNET> prompt and firmware version. Read-only." }
  - { cmd: "telnet {host} 23", safety: intrusive, note: "Connect to LIP shell; authenticates with default creds lutron/integration. Exposes device list and scene assignments." }
  - { cmd: "?DEVICE,<id>,<component>,<action>", safety: intrusive, note: "Query device state (zone level, occupancy) via LIP GET command after login. Read-only but uses default creds." }
  - { cmd: "#OUTPUT,<id>,1,<level>", safety: disruptive, note: "GATED — sets dimmer output level (0-100). Directly controls lighting circuits. Requires explicit authorization." }
references: ["CVE-2019-9451"]
mitre: "T0855"
---
# Lutron Lighting Integration Protocol (LIP)

Lutron's **Lighting Integration Protocol (LIP)** is a plain-text, line-oriented protocol served
over Telnet on **port 23/tcp** by Lutron RadioRA 2, Caséta, and RA2 Select processors. After the
TCP connection is established the device presents a `GNET>` prompt and authenticates via username
and password. The factory defaults — **lutron / integration** — are widely documented and seldom
changed, giving unauthenticated network-adjacent access to the full integration shell on unpatched
deployments.

**Why it matters.** An attacker with LIP access can enumerate every lighting zone, keypad, and
occupancy sensor in a building, query current occupancy state in real time, and issue `#OUTPUT`
commands that silently ramp or extinguish lights — enabling physical reconnaissance, concealing
intrusion activity, or causing nuisance/business disruption. In facilities where lighting state is
used as an occupancy proxy for HVAC or access control, manipulation can have cascading effects
beyond illumination.

**Safe-first testing.** Begin with a banner grab (Nmap port 23 with the `banner` script) to
confirm the `GNET>` marker without authenticating. If engagement scope permits authentication,
read-only `?DEVICE` and `?OUTPUT` GET queries can enumerate zone count and scene assignments
without changing state. **Do not issue `#OUTPUT` write commands against a live system** without
explicit, scoped authorization — lighting changes are immediately visible to occupants and may
affect safety lighting in stairwells, server rooms, or emergency egress routes.

**Remediation.** Change default credentials immediately; restrict Telnet access to a dedicated
integration VLAN with ACLs permitting only the building automation system; prefer Lutron's newer
SSH-based integration or REST API (Caséta Smart Bridge Pro) over plain Telnet where available;
audit integration accounts and rotate credentials periodically; and monitor LIP sessions for
unauthorized login attempts or unexpected `#OUTPUT` commands.
