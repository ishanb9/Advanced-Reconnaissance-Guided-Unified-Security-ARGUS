---
id: medical_devices
technology: "Networked medical devices"
domain: IoT
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [2575, 4712, 6522, 10001]
  banners: ["DICOM", "HL7", "MSH|", "Philips", "GE Healthcare", "Siemens Healthineers", "Spacelabs", "Mindray", "Alaris", "Baxter", "Nellcor", "Welch Allyn"]
  markers: ["MSH|^~\\&|", "MLLP", "DCM\x00\x00\x01", "0.0.0.0:2575"]
quick_wins:
  - { cmd: "nmap -Pn -sV --script banner -p2575,4712,6522,10001 {host}", safety: safe, note: "Passive banner grab on HL7/DICOM/proprietary ports — read-only, no data sent to device." }
  - { cmd: "snmpwalk -v2c -c public {host} 1.3.6.1.2.1.1", safety: safe, note: "Read sysDescr/sysName/sysLocation via SNMP — reveals vendor, model, firmware. Read-only; standard GET walk." }
  - { cmd: "nmap -Pn --script snmp-info,snmp-sysdescr -sU -p161 {host}", safety: safe, note: "SNMP system description — maps OUI to device model via sysObjectID. Passive GET only." }
  - { cmd: "python3 -c \"import socket; s=socket.create_connection(('{host}',2575),timeout=5); s.send(b'\\x0bMSH|^~\\&|PROBE|PROBE|SRV|SRV|20240101||QRY^A19|1|P|2.3\\x1c\\r'); print(s.recv(1024)); s.close()\"", safety: intrusive, note: "Minimal HL7 v2 ADT query to confirm MLLP listener and read server identity. Does NOT modify records." }
  - { cmd: "<ANY write/SET operation, parameter push, firmware update, or HL7 ORM/OMG order message>", safety: disruptive, note: "GATED — writing to a networked infusion pump, ventilator, or patient monitor can alter drug delivery or alarm thresholds. Never execute without clinical biomedical engineering authorization and device isolation." }
references: ["CVE-2019-10966", "CVE-2021-27410", "CVE-2022-26067", "CVE-2023-22435", "ICSMA-18-058-02", "ICSMA-19-080-01", "ICSMA-21-119-01", "ICSMA-22-013-01"]
mitre: "T0830"
---
# Networked medical devices

Networked medical devices — infusion pumps, patient monitors, ventilators, DICOM imaging
systems, and clinical workstations — are embedded IoT endpoints that communicate over
**HL7 v2/v3** (MLLP on **2575/tcp**), **DICOM** (**11112/tcp**, also seen on 4712/6522),
and vendor-proprietary protocols. Many devices run stripped Linux or Windows CE/XP Embedded
kernels with no patch cadence, default credentials, and SNMP community strings of `public`.
Because these devices directly participate in care delivery — dosing, ventilation, alarm
routing — **any availability impact is a patient-safety event**.

**Fingerprinting without touching the device.** Start with purely passive methods: ARP/mDNS
observation, DHCP hostname capture, and OUI-to-vendor lookup from the device MAC address.
Then issue read-only probes in order of risk: (1) SNMP v2c GET walk on `sysDescr`/`sysObjectID`
to map vendor and model; (2) banner grab on HL7/DICOM ports to confirm the application layer;
(3) DICOM C-ECHO (SCU→SCP ping) only if the clinical network owner has confirmed the AE title
and the device is not actively in use. Do **not** issue HL7 ORM/OMG order messages, DICOM C-STORE,
or any vendor management API write under any circumstances without biomedical engineering sign-off
and the device removed from patient care.

**Key risks.** The FDA and CISA have jointly issued ICS-MEDICAL advisories (ICSMA prefix) for
common vulnerability classes: unauthenticated Telnet/FTP management planes (ICSMA-18-058-02),
hard-coded credentials in infusion pump software (ICSMA-19-080-01), and stack-overflow bugs in
HL7 parsers (ICSMA-21-119-01). Check the device model against the FDA MedWatch database and the
CISA ICS-CERT advisory archive before scoping any active testing. Many advisories have no patch
and only compensating controls (VLAN isolation, firewall, disabling unused network services).
MITRE ATT&CK for ICS **T0830 (Adversary-in-the-Middle)** and **T0881 (Service Stop)** are the
most relevant initial-access and impact techniques.

**Remediation.** Segment clinical device networks onto a dedicated healthcare VLAN with strict
egress filtering and no direct IT-user access. Enforce SNMP v3 with auth+priv and disable
SNMPv1/v2c. Replace default credentials and disable Telnet/FTP in favor of SSH where firmware
supports it. Engage the device manufacturer's PSIRT before patching — many firmware updates
require FDA 510(k) clearance and must be coordinated with biomedical engineering, not applied
via standard IT patch management. Map all findings to the applicable ICSMA advisory rather than
relying on CVSS alone; a low-CVSS unauthenticated information disclosure on a ventilator
management interface carries far higher real-world impact than its score suggests.
