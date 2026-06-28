---
id: s7comm
technology: "Siemens S7comm"
domain: OT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [102]
  banners: ["s7comm", "siemens", "simatic", "s7-300", "s7-400", "s7-1200", "s7-1500"]
  markers: ["cotp", "s7comm-plus", "simatic s7", "s7 plc", "COTP connection request"]
quick_wins:
  - { cmd: "nmap -sV -p 102 --script s7-info {host}", safety: safe, note: "Read PLC module identity, firmware version, hardware version, and plant/module name via COTP+SZL read — no write operations." }
  - { cmd: "nmap -p 102 --script s7-enumerate {host}", safety: safe, note: "Enumerate accessible SZL (System Status List) blocks to determine PLC model, order number, and protection level." }
  - { cmd: "python3 snap7_read.py --host {host} --port 102 --db 1 --start 0 --size 16", safety: intrusive, note: "Read data block contents from the PLC using the snap7 library; may trigger access logs on protected PLCs." }
  - { cmd: "python3 s7comm_stop.py --host {host} --port 102 --stop", safety: disruptive, note: "Send CPU STOP command to halt PLC execution — GATE this behind explicit operator approval; causes immediate process shutdown." }
references:
  - "CVE-2019-13945"
  - "CVE-2019-10943"
  - "CVE-2016-9158"
  - "ICSA-12-245-01"
  - "ICSA-19-253-04"
  - "CISA KEV CVE-2019-13945"
mitre: "T0855"
---
# Siemens S7comm guidance

Siemens S7comm (and its successor S7comm-Plus) is the proprietary protocol used by Siemens SIMATIC S7-series PLCs (S7-300, S7-400, S7-1200, S7-1500) for programming, monitoring, and runtime data exchange. It runs over ISO-on-TCP (COTP, RFC 905) on port 102/tcp. Because S7comm was originally designed for trusted industrial network segments, early generations (S7-300/400) lack authentication entirely — any host that can reach port 102 can read identity information, data blocks, and (if not protected) send STOP or START commands to the CPU.

During an authorized penetration test, begin with passive read-only enumeration: the Nmap `s7-info` NSE script performs a safe COTP connection and SZL read (System Status List subset ID 0x0011) to extract the module order number, firmware version, hardware version, and the operator-configured plant/module name. This alone often reveals whether a PLC has protection levels configured and whether it is running a known vulnerable firmware. No data is written and no process state is altered during this step.

The key exposure on unprotected PLCs is unauthenticated CPU control: an attacker who can reach port 102 may issue STOP or START commands without credentials, halting or restarting PLC execution and directly impacting the controlled physical process. The Stuxnet worm and subsequent ICS threat actors have leveraged this. S7-1200/1500 PLCs with "Full protection" or "Safety" firmware enforce TLS-based S7comm-Plus (port 102 with upgraded session negotiation) and reject legacy S7comm connections, but misconfigurations and mixed fleet deployments often leave older CPUs exposed. Data block reads can also leak process values, setpoints, and recipe data that should be treated as sensitive.

Only escalate to write/control quick_wins (STOP/START, data block writes) after explicit written authorization from the engagement owner and, ideally, coordination with the site OT engineer so that safe process states are confirmed beforehand. Remediation guidance: upgrade to S7-1500 with "Full protection" firmware, segment PLCs behind a firewall permitting port 102 only from authorized engineering workstations, and enable S7comm-Plus with TLS where the firmware supports it.
