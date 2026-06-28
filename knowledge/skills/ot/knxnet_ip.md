---
id: knxnet_ip
technology: "KNXnet/IP"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [3671]
  banners: ["KNXnet/IP", "KNX"]
  markers: ["knxnet", "0x0206", "SEARCH_REQUEST", "DESCRIPTION_REQUEST"]
quick_wins:
  - { cmd: "knxmap scan {host}", safety: safe, note: "KNXmap passive Search/Description — enumerates KNXnet/IP routers and tunnelling servers, reads device info and supported services. Read-only." }
  - { cmd: "knxmap scan --search {host}", safety: safe, note: "Send KNXnet/IP SEARCH_REQUEST (UDP 3671) to discover routers on the local segment; returns multicast response with device name, MAC, and supported layers." }
  - { cmd: "knxmap scan --bus {host}", safety: intrusive, note: "Enumerate KNX bus devices via the gateway — polls individual addresses for device descriptors. Active but non-destructive." }
  - { cmd: "knxmap groupwrite {host} <group-addr> <DPT> <value>", safety: disruptive, note: "GATED — sends a KNX Group Write telegram (actuates lights, HVAC, blinds, access control). Requires explicit authorization; can affect physical building systems." }
  - { cmd: "knxmap restart {host} <individual-addr>", safety: disruptive, note: "GATED — sends a KNX Restart request to a bus device; reboots the device and interrupts control of attached loads." }
references: ["CVE-2021-37740", "CVE-2019-17497", "ICSA-18-240-01"]
mitre: "T0885"
---
# KNXnet/IP

KNXnet/IP is the IP-tunnelling and routing layer for the **KNX** building-automation bus, which
controls lighting, HVAC, blinds, access control, and fire/alarm integration in commercial and
residential buildings. The gateway or router listens on **3671/udp** and bridges IP hosts to the
KNX TP (twisted-pair) bus with **no mandatory authentication in the base standard** — any host
that can reach UDP 3671 can issue telegrams to every bus device the gateway serves.

**Reachability equals actuation.** KNXnet/IP's Core and Tunnelling layers (ISO 22510) expose
`SEARCH_REQUEST` and `DESCRIPTION_REQUEST` messages that return device name, MAC address,
multicast address, and supported service families — all without credentials. Progressing from
discovery to Group Write telegrams is trivial with tools like **KNXmap**; a single Group Write
to the right group address can switch off emergency lighting or lock/unlock a door.

**Safe-first testing.** Start with unauthenticated passive discovery: `knxmap scan` sends a
`DESCRIPTION_REQUEST` to the unicast address and reads back the router's device description block.
For segment-wide discovery, `SEARCH_REQUEST` is sent to the KNXnet/IP multicast address
(224.0.23.12) and routers respond with their device info — no state change on any bus device.
Bus enumeration (`knxmap scan --bus`) is active but read-only. **Never** issue Group Write or
Restart commands without explicit, scoped authorization and a human gate — a write telegram can
affect live HVAC loops, open fire-door holds, or cut power to a data centre floor.

**Remediation.** Isolate KNXnet/IP gateways on a dedicated building-automation VLAN with no
inbound access from IT or guest networks; deploy KNX Secure (ISO 22510-2, using AES-128-CCM for
Tunnelling and Routing) where hardware supports it; restrict gateway management to specific
operator IPs via ACL; enable logging of all telegram traffic for anomaly detection; and review
group-address assignments to identify safety-critical actuators (fire, egress, medical) that
warrant additional network segmentation.
