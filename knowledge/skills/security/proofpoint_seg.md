---
id: proofpoint_seg
technology: "Proofpoint Secure Email Gateway"
domain: IT
category: security
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [10000]
  banners: ["proofpoint", "proofpoint protection server", "X-Proofpoint-Spam-Details", "X-Proofpoint-Virus-Version"]
  markers: ["X-Proofpoint-Spam-Details", "X-Proofpoint-Virus-Version", "X-Proofpoint-GUID", "/admin/", "Proofpoint Protection Server"]
quick_wins:
  - { cmd: "curl -sk -D - https://{host}:10000/ | grep -i 'proofpoint\\|server\\|content-type'", safety: safe, note: "Proofpoint management interface (10000/tcp) banner grab — confirms PPS version from HTTP headers or login page." }
  - { cmd: "nmap -Pn -sT -p25,587,465,10000 --script smtp-commands,ssl-cert {host}", safety: safe, note: "SMTP EHLO probe and TLS cert grab — MTA presence, hostname, and Proofpoint identity from certificate SAN." }
  - { cmd: "swaks --server {host} --port 25 --ehlo test --quit-after EHLO 2>&1 | head -20", safety: safe, note: "SMTP EHLO banner grab with swaks — read-only enumeration of MTA capabilities and software banner." }
  - { cmd: "curl -sk -D - https://{host}/admin/ | grep -i 'proofpoint\\|login\\|version'", safety: safe, note: "Proofpoint admin web console fingerprinting — version string or redirect confirms PPS presence." }
  - { cmd: "python3 check_smtp_relay.py --host {host} --from attacker@external.com --to victim@target.com --check-only", safety: intrusive, note: "SMTP open relay check — sends a test message path; gated and logged. Requires explicit scope authorisation." }
references:
  - "CVE-2023-42930"
  - "CVE-2024-33900"
  - "CVE-2021-27253"
  - "Proofpoint Security Advisory 2023-PSA-001"
mitre: "T1566"
---
# Proofpoint Secure Email Gateway

Proofpoint Protection Server (PPS) is the leading enterprise secure email gateway, deployed on-premises or as a virtual appliance to filter inbound and outbound email for spam, phishing, malware, and data loss prevention. It is widely used by large enterprises, financial institutions, healthcare organisations, and government agencies. Proofpoint processes billions of messages globally and sits in the SMTP relay path for inbound email. The PPS management web console is typically on port 10000/tcp; the appliance itself accepts SMTP on standard ports 25, 587, and 465. Proofpoint stamps filtered email with `X-Proofpoint-*` headers, making it trivially detectable from a received email sample.

From a security testing perspective, the Proofpoint management console on port 10000 is the primary administrative attack surface. CVE-2021-27253 is an authentication bypass in Proofpoint's Threat Protection engine. CVE-2024-33900 and CVE-2023-42930 relate to privilege escalation and injection vulnerabilities in the PPS management interface. The SMTP service itself is a standard attack surface for relay testing, user enumeration via VRFY/EXPN, and header injection. Email gateway bypass is a high-value objective — if an attacker can deliver phishing email past a Proofpoint gateway, it directly undermines the organisation's primary email security control.

**Safe-first testing.** Detect Proofpoint via `X-Proofpoint-*` response headers in email headers or by probing the management port (10000/tcp). SMTP EHLO enumeration on port 25 reveals the MTA identity and capabilities without any authentication. TLS certificate CN/SAN from the SMTP connection reveals the gateway hostname and often the organisation name. Open relay testing and SMTP user enumeration (VRFY) require explicit authorisation as they interact with the live mail flow.

**Remediation.** Keep Proofpoint PPS firmware and content updates current (Proofpoint releases regular engine and rule updates via SmartSearch); restrict the management console (10000/tcp) to administrator networks with no external internet access; require multi-factor authentication for PPS admin login; disable SMTP VRFY and EXPN commands; enforce DMARC/DKIM/SPF validation in PPS policy; configure the appliance to reject relay attempts from unauthenticated external senders; and audit PPS quarantine access permissions to prevent sensitive data leakage.
