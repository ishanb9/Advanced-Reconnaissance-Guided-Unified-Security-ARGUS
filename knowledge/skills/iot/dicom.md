---
id: dicom
technology: "DICOM (PACS/modalities)"
domain: IoT
safety_class: safe
severity: critical
life_safety: true
match:
  ports: [104, 11112]
  banners: ["DICOM", "dcmtk", "OFFIS", "pynetdicom", "StoreSCP", "PACSSCU"]
  markers: ["0x0000,0x0100", "A-ASSOCIATE-RQ", "Application Context Name"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p104,11112 --script dicom-ping {host}", safety: safe, note: "C-ECHO request (DICOM Verification SOP) — confirms DICOM listener presence without retrieving patient data. Read-only." }
  - { cmd: "python3 -c \"from pynetdicom import AE; ae=AE(ae_title='ECHOSCU'); ae.add_requested_context('1.2.840.10008.1.1'); assoc=ae.associate('{host}',104); print(assoc.is_established); assoc.release()\"", safety: safe, note: "C-ECHO (Verification SOP class) via pynetdicom — confirms open association and records the responding AET. Read-only." }
  - { cmd: "findscu -v -S -k QueryRetrieveLevel=PATIENT -k PatientName='*' {host} 104", safety: intrusive, note: "C-FIND at PATIENT level — enumerates patient name index. Returns PHI (names/IDs) in plaintext; scope with narrow wildcard. Active enumeration." }
  - { cmd: "movescu --aetitle RETRIEVE -k QueryRetrieveLevel=STUDY -k StudyInstanceUID=<uid> {host} 104", safety: intrusive, note: "C-MOVE triggers the PACS to push a DICOM dataset to a caller-supplied AET/port. Active; can initiate large data transfer to an attacker-controlled SCP." }
references: ["CVE-2024-22099", "CVE-2023-43563", "ICSMA-21-110-01", "ICSMA-18-268-01"]
mitre: "T0861 / ICS T0830"
---
# DICOM (PACS/Modalities)

DICOM (Digital Imaging and Communications in Medicine) is the universal wire protocol for
medical imaging — connecting CT scanners, MRI units, X-ray systems, ultrasound machines, and
radiologist workstations (PACS) over TCP. The standard ports are **104/tcp** (legacy, privileged)
and **11112/tcp** (user-space PACS servers); many vendor implementations also proxy on 8042 or
443, but those are shared ports and must be identified by banner or DICOM Application Entity (AE)
negotiation, not port alone. The protocol uses unauthenticated binary TLV associations: any SCU
(Service Class User) that knows the called AE Title can initiate a DICOM association.

**PHI exposure without credentials.** DICOM associations are universally unauthenticated in
practice — TLS-wrapped "DICOM TLS" exists in the standard (RFC 3851 profile) but is rarely
deployed. A C-FIND query at the PATIENT or STUDY level returns Protected Health Information
(patient name, date of birth, MRN, accession number) in plaintext over the wire. A C-MOVE
or C-GET then retrieves full image datasets including embedded DICOM headers containing rich PHI.
HIPAA breach rules apply the moment PHI traverses an unauthenticated channel.

**Safe-first testing.** Begin with the **C-ECHO (Verification SOP: 1.2.840.10008.1.1)** — this
is the DICOM equivalent of ping and does not retrieve any patient data. Nmap's `dicom-ping` NSE
script and `pynetdicom`'s echo SCU both perform C-ECHO only. **Before issuing C-FIND**, confirm
engagement scope explicitly covers patient data enumeration; log only the count or structure, not
actual PHI. **Never issue C-STORE or C-MOVE** without written authorisation — C-STORE can inject
malicious DICOM objects into a live PACS, and C-MOVE can exfiltrate studies or be used to probe
lateral AET routes. AET enumeration (brute-forcing Application Entity Titles) via failed
A-ASSOCIATE-RQ responses is safe and reveals configured SCPs.

**Key risks and remediation.** Unauthenticated DICOM on a network reachable from corporate IT
or the internet is a critical finding: it combines mass PHI exfiltration, lateral movement through
AET routing, and potential patient-safety impact (corrupted or deleted prior imaging studies can
cause misdiagnosis). Remediation priorities: (1) firewall 104/11112 to a dedicated imaging VLAN
with allowlisted AE-title/IP pairs; (2) deploy DICOM TLS where the PACS vendor supports it;
(3) audit AE Title access control lists on the PACS; (4) enable DICOM audit logging per the DICOM
Supplement 95 audit trail standard; (5) map findings to CISA ICSMA advisories rather than
CVSS alone — patient-safety impact exceeds typical CVSS scores for unauthenticated read.
