---
id: snmp_managed_switch
technology: "SNMP Managed Switches"
domain: IT
category: network
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [161]
  banners: ["snmpd", "SNMP", "net-snmp", "enterprise"]
  markers: ["1.3.6.1.2.1.1.1.0", "SNMPv2-MIB::sysDescr", "iso.3.6.1.2.1.1.1.0", "NET-SNMP", "enterprises.9", "enterprises.2636"]
quick_wins:
  - { cmd: "nmap -Pn -p161 -sU --script snmp-info,snmp-sysdescr,snmp-interfaces,snmp-brute {host}", safety: safe, note: "SNMP v1/v2c enumeration — sysDescr, interface table, and community string brute-force against a short wordlist (public/private/community/monitor). Read-only." }
  - { cmd: "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {host}", safety: safe, note: "Fast SNMP community string brute-force — discovers valid read (RO) and read-write (RW) community strings." }
  - { cmd: "snmpwalk -v2c -c public {host} 1.3.6.1.2.1 2>/dev/null | head -100", safety: safe, note: "Full MIB-II walk with 'public' community — retrieves interfaces, routing table, ARP cache, STP state, and contact info." }
  - { cmd: "snmpget -v2c -c public {host} 1.3.6.1.2.1.1.1.0 2>/dev/null", safety: safe, note: "Single OID sysDescr GET — least invasive version fingerprint; safe on any managed switch." }
  - { cmd: "snmpset -v2c -c private {host} 1.3.6.1.2.1.1.6.0 s 'test'", safety: intrusive, note: "GATED — SNMP write test (sysLocation). Proves RW community access. Never modify port/vlan/routing OIDs." }
references: ["CVE-2017-6736", "CVE-2002-0013", "CVE-2008-0960", "CISA-AA22-257A"]
mitre: "T1602.001"
---
# SNMP Managed Switches

SNMP (Simple Network Management Protocol) is the universal management protocol for enterprise
managed switches from Cisco Catalyst, HP ProCurve, Juniper EX, Dell PowerConnect, Netgear Insight,
D-Link, and virtually every other vendor. SNMPv1/v2c on UDP 161 uses community strings as the
sole authentication mechanism — the default strings `public` (read-only) and `private` (read-write)
remain in deployment on a significant fraction of managed switches worldwide. SNMPv3 adds
authentication and encryption but adoption lags significantly.

**Why it matters.** A valid SNMP community string (especially read-write) gives an attacker
complete visibility into the switch's topology, ARP/MAC tables, routing information, interface
counters, and STP root state — the equivalent of executing `show running-config` on every switch
in the organization simultaneously. With a read-write community string, an attacker can modify
VLANs, disable ports, alter trunking configuration, or poison the ARP cache via SNMP OID writes.
CISA advisory AA22-257A specifically calls out default SNMP community strings as a top initial
access vector. Shodan indexes millions of SNMP-responsive devices.

**Safe-first testing.** Start with `snmpget` on `sysDescr.0` using `public` — this is a single
read-only GET that reveals vendor and OS version without walking the MIB. Proceed to a `snmpwalk`
of MIB-II (1.3.6.1.2.1) to enumerate interfaces, routing table, and ARP cache. Community string
brute-force via `onesixtyone` against a short wordlist (public, private, community, monitor, cisco,
cable-docsis) is standard practice. Never issue SNMP SET operations against production switches
without explicit, scoped change-window authorization.

**Remediation.** Migrate all managed switches to SNMPv3 with authPriv (MD5/SHA auth + AES priv);
disable SNMPv1/v2c; change all community strings from defaults; implement SNMP ACLs restricting
access to authorized management stations only; and audit quarterly for devices still responding
to `public` community strings using your internal scanner.
