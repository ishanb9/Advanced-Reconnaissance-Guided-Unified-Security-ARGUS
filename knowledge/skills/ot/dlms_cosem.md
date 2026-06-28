---
id: dlms_cosem
technology: "DLMS/COSEM (smart meters)"
domain: OT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [4059]
  banners: ["DLMS", "COSEM", "IEC 62056", "Gurux", "Landis"]
  markers: ["60 36 a1 09 06 07 60 85 74", "\\x60\\x1d\\xa1", "IEC-62056-21", "DLMS-COSEM-AARE"]
quick_wins:
  - { cmd: "nmap -Pn -sT -sU -p4059 --script banner {host}", safety: safe, note: "Probe TCP and UDP on 4059 — DLMS/COSEM servers often accept both; banner may reveal meter model and firmware." }
  - { cmd: "nmap -Pn -sT -p4059 --script dlms-cosem-identify {host}", safety: safe, note: "If NSE script available: sends AARQ with no authentication (lowest security-level) to read association response — exposes device ID and supported ciphering suite without changing meter state." }
  - { cmd: "python3 -c \"import socket,sys; s=socket.create_connection(('{host}',4059),5); aarq=bytes.fromhex('601da109060760857405080101a203020100a305a103020100'); s.sendall(aarq); print(s.recv(256).hex())\"", safety: safe, note: "Send minimal AARQ with security-level 0 (no auth). AARE response reveals association acceptance or rejection — confirms authentication enforcement (or lack thereof). Read-only." }
  - { cmd: "gurux-dlms-client -h {host} -p 4059 -S 16 -C None --obis 0.0.96.1.0.255", safety: intrusive, note: "Read meter serial number via OBIS 0-0:96.1.0.255 (Device ID) using default community/password. Intrusive: establishes authenticated association; log your access." }
  - { cmd: "gurux-dlms-client -h {host} -p 4059 -S 16 -C None --obis 1.0.1.8.0.255", safety: intrusive, note: "Read cumulative active import energy (kWh) — OBIS 1-0:1.8.0.255. Confirms meter data is accessible. Intrusive (authenticated session) but non-destructive." }
  - { cmd: "gurux-dlms-client -h {host} -p 4059 -S 16 -C LowLevel -P '<default-pw>' --obis 0.0.96.3.10.255 --write 0", safety: disruptive, note: "GATED — OBIS 0-0:96.3.10.255 is the Disconnect Control object; writing 0 triggers remote load disconnect. Do NOT run without explicit scoped authorization — cuts power to customer premises." }
references: ["CVE-2019-13594", "CVE-2024-31498", "ICSA-19-190-01", "ICSMA-20-049-01"]
mitre: "ICS T0855 / T0831"
---
# DLMS/COSEM (smart meters)

DLMS (Device Language Message Specification) paired with COSEM (Companion Specification for
Energy Metering) is the dominant application-layer protocol for smart electricity, gas, and
water meters worldwide, standardised as IEC 62056. It runs over **4059/tcp and 4059/udp**
(IANA-assigned). Meter data exchange uses **OBIS codes** (Object Identification System) to
address logical objects such as energy registers, tariff schedules, and the load-disconnect
relay. The protocol supports multiple security levels negotiated in the **AARQ/AARE** association
handshake: No Authentication, Low-Level Security (LLS — a shared password), and High-Level
Security (HLS — challenge-response using AES). Deployed meters vary enormously in which level
is enforced; many field units still accept AARQ with security-level 0 or ship with well-known
default passwords that are never changed.

**Why it matters for security assessments.** A metering head-end that can reach meters over
4059/tcp can also send disconnect commands at scale. The **Disconnect Control object**
(OBIS 0-0:96.3.10.255) allows the utility — or an attacker — to remotely interrupt supply to
thousands of premises with a single authenticated write. Mass remote-disconnect events can
destabilize grid edge infrastructure and have direct safety and economic consequences for
residential and commercial consumers. Exploitation requires only that the attacker can reach the
meter network (RF mesh, PLC, or a poorly segmented AMI back-office LAN) and knows or guesses
the LLS password.

**Safe-first testing.** Start with a bare TCP/UDP probe and banner grab on 4059. Send an AARQ
with security-level 0 and inspect the AARE: if the meter returns a positive result, LLS/HLS is
not enforced — flag it immediately and stop. If rejected, do not brute-force passwords. Reading
OBIS registers (energy totals, meter serial number, clock) via an authenticated LLS session with
a known/provided credential is intrusive but non-destructive; document every association you
open in test logs. Never issue write operations (Disconnect, tariff reprogramming, firmware push)
without explicit, change-window-scoped authorization from the asset owner and a tested rollback
path. Treat the disconnect relay as equivalent to a process actuator in a PLC.

**Remediation.** Enforce HLS (AES-GCM wrapped APDU) at the head-end and reject LLS/no-auth
associations. Rotate default passwords across the meter population using the utility's OMS/OMSI
provisioning flow. Segment the AMI WLAN/PLC mesh from IT and corporate networks; restrict
4059/tcp to known head-end IPs with firewall ACLs. Enable tamper and disconnect event logging
to the MDMS/SIEM. Reference ENISA's *Smart Grid Security Guidelines* and NIST IR 7628 for
programme-level controls.
