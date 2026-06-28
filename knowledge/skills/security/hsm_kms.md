---
id: hsm_kms
technology: "Hardware Security Module (HSM) / KMS"
domain: IT
category: security
transport: ip
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [1792, 9004, 9005, 2223]
  banners: ["luna sa", "safenet", "thales luna", "ncipher", "utimaco", "venafi", "keyfactor"]
  markers: ["ntls", "lunacm", "PEDServer", "safenet-keyvault", "HSM-Management"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p1792,9004,9005,2223 --script ssl-cert,banner {host}", safety: safe, note: "Thales Luna SA Network NTLS (1792) and SafeNet management port scan — confirms HSM presence, firmware version from TLS cert." }
  - { cmd: "curl -sk -D - https://{host}:9004/ | grep -i 'luna\\|safenet\\|thales\\|ncipher\\|server'", safety: safe, note: "HSM management web interface fingerprinting — product and firmware generation from HTTP response headers." }
  - { cmd: "nmap -Pn -sT -p2223 --script banner {host}", safety: safe, note: "Luna SA PEDServer port (2223) banner grab — identifies remote PED (PIN Entry Device) daemon presence." }
  - { cmd: "openssl s_client -connect {host}:1792 -showcerts 2>/dev/null | openssl x509 -noout -text | grep -i 'subject\\|issuer\\|before\\|after'", safety: safe, note: "TLS certificate inspection on NTLS port — reveals HSM model, serial number region, and certificate validity window." }
  - { cmd: "lunacm -c 'slot list' 2>/dev/null || cmu list 2>/dev/null", safety: safe, note: "Luna CM / CMU tool slot enumeration — read-only listing of HSM partitions visible on the network (requires network trust but no credentials)." }
references:
  - "CVE-2019-11516"
  - "CVE-2018-16904"
  - "CVE-2015-5350"
  - "NIST SP 800-57"
  - "PCI DSS v4.0 Requirement 3.7 (Key Management)"
mitre: "T1552.004"
---
# Hardware Security Module (HSM) / KMS

Hardware Security Modules (HSMs) are purpose-built cryptographic appliances that generate, store, and protect private keys within tamper-resistant hardware. They are found in banks, payment processors, PKI certificate authorities, government agencies, and cloud providers protecting the most sensitive keys in the enterprise: CA root keys, payment HSM master keys, TLS private keys, and code-signing certificates. Vendors include Thales (Luna Network HSM, formerly SafeNet), Entrust nShield (formerly nCipher), Utimaco, IBM 4769, and Atos. Key Management Systems (KMS) — both on-premise (Venafi, Keyfactor, Townsend) and cloud-native (AWS KMS, Azure Key Vault, GCP Cloud KMS) — sit above HSMs and provide policy-driven key lifecycle management. Compromise of an HSM or KMS represents a catastrophic loss with unlimited downstream impact.

The Thales Luna Network HSM uses the NTLS protocol on port 1792/tcp for client-HSM communication. CVE-2019-11516 is a pre-authentication buffer overflow in Gemalto (Thales) SafeNet Authentication Server. CVE-2018-16904 is a path traversal in the SafeNet management agent. Most HSM vulnerabilities are firmware-level and not remotely exploitable without prior network trust establishment (NTLS client certificate); however, misconfigurations — such as overly permissive NTLS client registration, default administrative PINs, and management interfaces accessible from general networks — are common findings. Cloud KMS services expose IAM policy vulnerabilities where over-privileged roles can decrypt or export sensitive material.

**Safe-first testing.** Enumerate HSM presence by port-scanning for NTLS (1792), SafeNet management (9004/9005), and PEDServer (2223) ports. Inspect TLS certificates on NTLS for model, serial, and firmware metadata — this is entirely passive. Check for management web interfaces with default credentials (Thales Luna default credentials have been publicly known). For cloud KMS, audit IAM policies for `kms:Decrypt`, `kms:GetKeyPolicy`, and `kms:CreateGrant` on broad principals. Never attempt to perform any cryptographic operation, key import/export, or partition modification without explicit authorisation and a formal key custodian present.

**Remediation.** Change all default admin PINs and partition passwords immediately; restrict NTLS registration to explicitly authorised HSM clients by certificate; place the HSM management interface on a dedicated out-of-band management VLAN inaccessible from application networks; require two-person integrity (2PI/dual control) for all sensitive key operations; maintain HSM firmware updates on a tested schedule; and implement FIPS 140-2/3 Level 3 validation as the minimum baseline for CA root and payment HSMs. For cloud KMS: apply least-privilege IAM, enable key usage audit logging (CloudTrail / Azure Monitor), and configure key deletion protection with multi-approver workflows.
