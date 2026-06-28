---
id: hl7_mllp
technology: "HL7 v2.x over MLLP"
domain: IoT
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [2575]
  banners: ["MSH|^~\\&|", "MLLP", "HL7 2.", "ACK^A01", "MSA|AA|"]
  markers: ["\x0bMSH|", "MSH|^~\\&|", "MSA|AA|", "HL7 Interface"]
quick_wins:
  - { cmd: "python3 -c \"import socket,time; s=socket.socket(); s.connect(('{host}',2575)); s.settimeout(5); s.send(b'\\x0bMSH|^~\\\\&|PROBE|PROBE|PROBE|PROBE|20240101120000||QRY^Q01|1|P|2.3\\r\\x1c\\r'); d=s.recv(4096); print(d); s.close()\"", safety: safe, note: "Send minimal MSH probe wrapped in MLLP framing (0x0B start-block, 0x1C+0x0D end) and read the ACK. Read-only." }
  - { cmd: "nmap -Pn -sT -p2575 --script banner {host}", safety: safe, note: "TCP banner grab to confirm MLLP listener presence and capture any server greeting." }
  - { cmd: "python3 -c \"import socket; s=socket.socket(); s.connect(('{host}',2575)); s.settimeout(5); msg=b'\\x0bMSH|^~\\\\&|ATTACKER|ATTACKER|EHR|EHR|20240101120000||ORM^O01|9999|P|2.3\\rORC|NW|9999\\rOBR|1|9999||ORDTEST^Order^L\\r\\x1c\\r'; s.send(msg); print(s.recv(4096)); s.close()\"", safety: intrusive, note: "GATED — forged ORM (order message) to test message acceptance. May create a phantom order in a clinical system. Requires explicit written authorization." }
references: ["CVE-2022-39952", "ICSMA-18-347-01", "ICSMA-20-170-01"]
mitre: "T0830"
---
# HL7 v2.x over MLLP

HL7 v2.x is the dominant clinical messaging standard, used to exchange patient admissions,
lab orders, radiology results, and medication records between hospital systems (EHR, LIS, RIS,
pharmacy). It rides a lightweight transport wrapper called **MLLP (Minimal Lower Layer Protocol)**
— typically on **2575/tcp** — whose sole purpose is to delimit variable-length HL7 messages with a
start-block byte (`0x0B`) and an end sequence (`0x1C 0x0D`). MLLP carries **no authentication, no
encryption, and no authorization** by design; the protocol assumes a trusted, isolated hospital
network segment that rarely exists.

**Why it matters.** A reachable MLLP listener gives an attacker a direct channel into clinical
workflows. An unauthenticated sender can inject an **ORM^O01** (order message) to create a
phantom lab or medication order, an **ADT^A01** (patient admission) to pollute census data, or an
**ORU^R01** (result) to alter a stored lab value — all without touching the EHR's web UI or API.
Impact ranges from data integrity corruption through to patient safety events if a forged order
reaches a pharmacist or nurse without secondary verification.

**Safe-first testing.** The baseline safe probe is a minimal **MSH-only** message (QRY^Q01 or a
near-empty MSH with a clearly fake sending application) wrapped in correct MLLP framing. A
well-behaved interface engine will return an **ACK** with MSA-1=`AA` (accepted) or `AE`/`AR`
(error/rejection) — either response confirms the listener is live and what HL7 version it runs
without inserting a real workflow record. Capture the full ACK: MSH-3/MSH-4 fields reveal the
receiving application and facility, and MSH-12 confirms the negotiated HL7 version. Do not
proceed to order-bearing message types (**ORM, ADT, RDE**) without written authorization
because every accepted message may persist in a production clinical database.

**Remediation.** Restrict 2575/tcp to a dedicated integration VLAN; front MLLP with a TLS-
terminating integration engine (Mirth Connect, Rhapsody, Infor Cloverleaf) and enforce
sender-certificate mutual TLS; implement message-level sender ID whitelisting in the interface
engine; enable full audit logging of all incoming MSH segment metadata; and apply available
vendor patches for known parsing CVEs. Reference CISA ICS-CERT medical advisories for
device-specific guidance rather than CVE/CVSS alone, as CVSS consistently under-rates clinical
data-integrity impact.
