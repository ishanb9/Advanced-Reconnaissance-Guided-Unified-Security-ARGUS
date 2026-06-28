---
id: modbus
technology: "Modbus / Modbus-TCP"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [502]
  banners: ["modbus"]
  markers: ["mbap"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p502 --script modbus-discover {host}", safety: safe, note: "Read device ID (FC 43 / MEI 14) — vendor, product, firmware. Read-only." }
  - { cmd: "python3 -c 'from pymodbus.client import ModbusTcpClient as C; c=C(\"{host}\"); c.connect(); print(c.read_holding_registers(0,8))'", safety: intrusive, note: "Read holding registers (FC 0x03) — process values. Read-only but active." }
  - { cmd: "<write single coil FC 0x05 / write register FC 0x06>", safety: disruptive, note: "GATED — actuates the process; can stop a live PLC. Requires explicit authorization." }
references: ["CVE-2018-5443", "ICSA-19-080-02", "OT:ICEFALL"]
mitre: "T0846"
---
# Modbus / Modbus-TCP

Modbus is the most widely deployed industrial control protocol. Modbus/TCP listens on
**502/tcp** and ships with **no authentication, no encryption, and no integrity** — it was
designed for an isolated, trusted serial bus. The threat model is **availability and physical
safety first**: whoever can reach 502/tcp can read process data, and with a single write
function code can command coils and registers — potentially shutting down a running process.

**Reachability equals control.** Tens of thousands of PLCs (Schneider M340/M580, WAGO, and
others) are internet-exposed on Shodan. Treat every Modbus endpoint as fragile.

**Safe-first testing.** Enumerate read-only by default: `modbus-discover` (NSE) issues
**FC 43 / MEI 14 (Read Device Identification)** to recover vendor, product code, and firmware
revision without changing state. Reading coils/registers (FC 0x01/0x02/0x03/0x04) is active but
non-destructive. **Never** issue write function codes (0x05 Write Single Coil, 0x06 Write Single
Register, 0x0F/0x10 Write Multiple) against a live target without explicit, scoped authorization
and a human gate — a single write can trip an interlock or stop a PLC.

**Remediation.** Segment OT onto a dedicated VLAN with no inbound access from IT/user networks;
front Modbus with an authenticating gateway or Modbus/TCP Security (TLS) where supported; disable
unused write access; monitor 502/tcp; and map findings to the relevant CISA ICS advisories rather
than CVE/CVSS alone (which under-represents OT impact).
