---
id: dnp3
technology: "DNP3"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [20000]
  banners: ["dnp3", "dnp 3", "distributed network protocol"]
  markers: ["dnp3", "dnp/tcp"]
quick_wins:
  - { cmd: "nmap -p 20000 --script dnp3-info {host}", safety: safe, note: "Class-0 read poll — enumerates device attributes, vendor, model, and firmware version without writing any state" }
  - { cmd: "nmap -p 20000 --script dnp3-info --script-args dnp3.src=1,dnp3.dst=1 {host}", safety: safe, note: "Targeted Class-0 poll with explicit source/destination addresses to match station addressing scheme" }
  - { cmd: "nmap -p 20000 -sV --version-intensity 5 {host}", safety: safe, note: "Banner grab and service fingerprint to confirm DNP3 listener and vendor stack" }
  - { cmd: "python3 -m scapy -c \"from scapy.contrib.dnp3 import *; pkt=DNP3()/DNP3Transport()/DNP3Application(fc=1); send(IP(dst='{host}')/TCP(dport=20000)/pkt)\"", safety: intrusive, note: "Manual Class-0 data-link layer poll; confirms response and reveals supported function codes" }
  - { cmd: "# GATED — requires explicit written authorisation and change-window approval\nnmap -p 20000 --script dnp3-info --script-args dnp3.function=3 {host}", safety: disruptive, note: "CROB (Control Relay Output Block) operate — changes digital output state; MUST be gated behind change control and operator supervision" }
references:
  - "CVE-2013-2799"
  - "CVE-2014-2378"
  - "CVE-2021-27152"
  - "ICSA-13-011-01"
  - "ICSA-14-084-01"
  - "CISA KEV CVE-2021-27152"
mitre: "T0843"
---
# DNP3 guidance

DNP3 (Distributed Network Protocol 3) is a SCADA/ICS serial-and-TCP protocol standardised under IEEE 1815, widely deployed in electric utilities, water treatment, and oil-and-gas facilities for master-station-to-RTU/IED communication. When exposed over TCP port 20000, a DNP3 master or outstation accepts unsolicited requests by default in many vendor implementations, meaning an attacker on the same network segment can poll live process data or, on vulnerable stacks, issue control commands without authentication.

For an authorised penetration test the first step is always a passive Class-0 integrity poll, which retrieves all static and event data without altering any output state. The Nmap `dnp3-info` NSE script performs this safely and returns device attributes, vendor name, firmware revision, and supported object groups. This read-only enumeration is sufficient to confirm exposure, enumerate the application-layer addressing scheme, and identify the vendor stack for CVE cross-referencing. No write operations should occur outside an approved change window.

The key risks in an exposed DNP3 service are: unauthenticated Class-0/1/2/3 polling leaks real-time process telemetry (voltages, flow rates, valve positions); absence of Secure Authentication v5 (SAv5 per IEEE 1815-2012 Annex A) allows replay and man-in-the-middle attacks; and CROB (Control Relay Output Block, function code 3/4) permits direct digital output manipulation — opening breakers, toggling pumps, or changing set-points — with no credential requirement on legacy firmware. Several RTU/IED stacks carry memory-corruption CVEs triggered by malformed Application Layer fragments that can crash the outstation.

Remediation centres on three controls: enforce SAv5 challenge-response authentication on all DNP3 sessions; place DNP3 listeners behind a unidirectional gateway or protocol-aware firewall that permits only Class-0 polls from authorised master IP addresses; and upgrade RTU/IED firmware to patched versions addressing known parsing CVEs. Any CROB operation during a pentest must be pre-approved in writing, performed inside a maintenance window, and coordinated with the site operator who retains manual override capability.
