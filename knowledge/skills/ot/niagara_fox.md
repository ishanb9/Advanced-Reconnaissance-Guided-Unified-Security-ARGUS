---
id: niagara_fox
technology: "Niagara Fox / Tridium"
domain: OT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [1911, 4911]
  banners: ["fox/", "fox hello", "niagara", "tridium", "foxs/"]
  markers: ["fox:", "niagara4", "/ord?", "/module/kitControl"]
quick_wins:
  - cmd: "nmap -sV -p 1911,4911 --script fox-info {host}"
    safety: safe
    note: "Read-only Fox hello banner grab; returns version, host name, and station IP"
  - cmd: "nmap -p 1911 --script fox-info --script-args fox-info.timeout=5 {host}"
    safety: safe
    note: "Targeted banner enumeration with timeout; pulls Niagara version string unauthenticated"
  - cmd: "nmap -p 4911 -sV {host}"
    safety: safe
    note: "Probe FoxS (TLS Fox) port; version disclosure still occurs before cert exchange on older builds"
  - cmd: "python3 -m niagara_enum --host {host} --port 1911 --list-stations"
    safety: intrusive
    note: "Enumerate exposed station names and module list; requires unauthenticated Fox session (Niagara 3.x default)"
  - cmd: "curl -sk https://{host}:8443/ord?module://kitControl/ -H 'Accept: application/json'"
    safety: intrusive
    note: "Probe Niagara HTTPS management port (8443) for unauthenticated ORD tree traversal (CVE-2023-4486 class); 8443 is the Niagara-specific HTTPS listener distinct from general web traffic"
references:
  - "CVE-2017-16744"
  - "CVE-2017-16748"
  - "CVE-2019-13528"
  - "CVE-2021-44228"
  - "CVE-2023-4486"
  - "CVE-2025-24019"
  - "CVE-2025-24020"
  - "ICSA-17-347-01"
  - "ICSA-19-178-02"
  - "CISA KEV 2021-12-10"
mitre: "T0886"
---
# Niagara Fox / Tridium guidance

Niagara Framework (by Tridium, now Honeywell) is one of the most widely deployed building-automation middleware platforms globally. It runs as a Java-based application station on embedded controllers (JACE) and servers, and exposes the proprietary Fox protocol on TCP/1911 (plaintext) and TCP/4911 (TLS-wrapped FoxS). During the Fox hello handshake the station transmits its software version, host name, and configured IP address in the clear — no authentication is required to read these fields. This single unauthenticated banner disclosure has historically been enough to identify outdated Niagara 3.x (AX) or Niagara 4 builds that carry known critical CVEs.

For an authorized penetration test, start with a read-only nmap `fox-info` NSE script against both ports. The banner response immediately tells you the exact Niagara version, which can be cross-referenced against the Tridium advisory history. Niagara 3.x (AX) builds prior to 3.8.401 and Niagara 4 builds prior to 4.13 carry a dense CVE chain including unauthenticated directory traversal (CVE-2017-16744), credential disclosure (CVE-2017-16748), and session-management flaws (CVE-2019-13528). The 2025 Nozomi-disclosed chain (CVE-2025-24019 / CVE-2025-24020) adds remote code execution via a crafted ORD request against unpatched Niagara 4 web layers, making exposure of port 1911/4911 to untrusted networks a critical finding regardless of authentication state.

Safe enumeration should precede any authenticated testing: record the version from the Fox hello, check whether 4911 (FoxS) is present (absence means Fox runs unencrypted), and probe the Niagara web UI (typically TCP/443 or TCP/8443) for unauthenticated ORD traversal. Intrusive steps — station enumeration, module listing, or ORD tree walking — should be gated behind explicit client approval as they generate log entries in the Niagara audit trail. Never issue write commands (setpoint changes, schedule overrides) against a live building-automation system without explicit written authorization and a tested rollback plan; even read-only control-plane enumeration can trigger watchdog resets on underpowered JACE hardware.

Remediation: upgrade to the latest patched Niagara 4 release, firewall ports 1911/4911 to a dedicated BAS management VLAN, enforce FoxS (TLS) only, rotate all station credentials, and disable legacy Niagara AX (3.x) stations that cannot be patched. CISA ICS-CERT advisories ICSA-17-347-01 and ICSA-19-178-02 provide vendor patch matrices.
