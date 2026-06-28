---
id: openhab
technology: "openHAB"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [9001]
  banners: ["openHAB", "Eclipse SmartHome"]
  markers: ["/rest/", "X-OpenHAB", "/basicui/", "/habpanel/", "openHAB REST Interface"]
quick_wins:
  - { cmd: "curl -sk http://{host}:8080/rest/ -H 'Accept: application/json'", safety: safe, note: "Enumerate openHAB REST API root — lists API version and available endpoints, no auth needed on default." }
  - { cmd: "curl -sk http://{host}:8080/rest/items | python3 -m json.tool", safety: safe, note: "List all items (devices, sensors, virtual items) with current states — read-only." }
  - { cmd: "curl -sk http://{host}:8080/rest/things | python3 -m json.tool", safety: safe, note: "Enumerate all bound Things (physical devices) and their status — read-only." }
  - { cmd: "curl -sk http://{host}:8080/rest/sitemaps | python3 -m json.tool", safety: safe, note: "List sitemaps — reveals UI layout and device groupings, read-only." }
  - { cmd: "curl -sk -X POST http://{host}:8080/rest/items/<itemName> -H 'Content-Type: text/plain' -d 'ON'", safety: disruptive, note: "GATED — sends a command to an item (switch, lock). Requires written authorization." }
references: ["CVE-2020-9280", "CVE-2023-29229", "openHAB Security Advisory 2020-02"]
mitre: "T1190 / ICS T0866"
---
# openHAB

openHAB (open Home Automation Bus) is an open-source, Java-based home-automation platform
designed around a vendor-neutral binding architecture. It exposes a REST API on **8080/tcp**
(HTTP) and optionally **8443/tcp** (HTTPS), as well as a Karaf OSGi console on **9001/tcp**.
The REST API is **unauthenticated by default** in many community installations, allowing any
LAN host to enumerate and control all items without credentials.

**Why it matters offensively.** An unauthenticated REST API allows direct enumeration of all
devices (Items, Things, Rules) and state changes via simple HTTP POSTs. The Karaf OSGi
console (9001/tcp), if left on its default credentials (`karaf`/`karaf`), provides an
interactive shell with the ability to install bundles — equivalent to OS-level code execution
on the openHAB host. CVE-2020-9280 disclosed a Server-Side Template Injection vulnerability
in openHAB's Sitemap rendering. CVE-2023-29229 affected the REST API's input validation.

**Safe-first testing.** Begin with unauthenticated REST enumeration: `GET /rest/items`,
`GET /rest/things`, `GET /rest/sitemaps`, and `GET /rest/rules`. These reveal the full
device inventory and automation logic. Check for the Karaf console on 9001 with default
credentials before attempting any command operations.

**Key risks.** Default unauthenticated REST API; default Karaf OSGi shell credentials; HTTP
without TLS exposing tokens; binding-specific vulnerabilities in community-maintained plugins;
add-on supply chain. Remediation: enable openHAB authentication (API tokens or basic auth),
disable the Karaf console or change default credentials, enforce HTTPS, segment the hub on
an IoT VLAN, and keep bindings updated via the openHAB Marketplace.
