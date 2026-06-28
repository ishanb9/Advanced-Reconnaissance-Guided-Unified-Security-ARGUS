---
id: os-ios-mdm
technology: "iOS / iPadOS Attack Surface (MDM, Lockdown, Jailbreak)"
domain: IT
category: os
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [62078]
  banners: ["Apple Mobile Device", "lockdownd", "iTunes"]
  markers: ["lockdownd", "Apple_PubKey_Export", "com.apple.mobile"]
quick_wins:
  - { cmd: "nmap -Pn -sV -p62078 --script banner {host}", safety: safe, note: "Detect iOS lockdownd listener (USB-over-TCP / WiFi Sync) — read-only fingerprint." }
  - { cmd: "nmap -Pn -sV -p443,8443 --script http-title,ssl-cert {host}", safety: safe, note: "Fingerprint MDM server certificate and title page for product identification — read-only." }
  - { cmd: "ideviceinfo -n {host}", safety: safe, note: "Query iOS device info via lockdownd protocol (requires trust pairing) — read-only if already paired." }
  - { cmd: "curl -sk https://{host}/enroll | grep -i 'mdm\\|profile\\|mobileconfig'", safety: safe, note: "Probe MDM enrollment endpoint for unauthenticated profile download — read-only HTTP probe." }
references: ["CVE-2023-41064 (BLASTPASS iMessage zero-click)", "CVE-2022-32917 (iOS kernel priv-esc)", "CVE-2021-30807 (IOMobileFrameBuffer)", "Apple Security Advisory HT213988", "NSO Pegasus research (Citizen Lab)"]
mitre: "T1404"
---
# iOS / iPadOS Attack Surface (MDM, Lockdown, Jailbreak)

iOS and iPadOS present a hardened attack surface by design: sandboxed apps, Secure Enclave, signed kernel, Pointer Authentication Codes (PAC), and hardware attestation. However, the platform is a high-value target (executive devices, corporate email, VPN keys) and zero-click exploit chains (BLASTPASS 2023, FORCEDENTRY 2021) demonstrate that pre-authentication RCE is achievable via media-parsing vulnerabilities. The iOS **lockdownd** service on **62078/tcp** provides device management when WiFi Sync is enabled; MDM servers (corporate or adversarial) communicate over **443/tcp** with signed `.mobileconfig` profiles.

**Common exposures.** MDM enrollment endpoints exposed without authentication allow rogue device enrollment or profile download. Malicious `.mobileconfig` files can install CA certificates (enabling MITM), configure VPN to route traffic through attacker infrastructure, or restrict device functionality. Enterprise users side-loading configuration profiles from untrusted sources is a social-engineering vector. Jailbroken devices bypass most iOS security controls; detecting jailbreaks via MDM compliance checks is a key defensive gap. Pegasus-class spyware exploits zero-click iMessage chains targeting specific individuals.

**Safe-first testing.** For MDM infrastructure assessments, probe the enrollment URL (`.mobileconfig` download endpoint) for unauthenticated access and inspect the profile for malicious CA certificates or VPN configurations — read-only HTTP probes. For device-level testing in scope, `ideviceinfo` (libimobiledevice) reads device properties over the lockdown protocol if the device has been previously trust-paired. iOS penetration testing is almost entirely black-box (App Store apps) or MDM-focused; kernel-level testing requires a jailbroken device in a lab environment.

**Remediation.** Enforce MDM enrollment with user authentication and device attestation; restrict `.mobileconfig` installs to MDM-signed profiles; implement MDM compliance checks (jailbreak detection, OS version enforcement); enable Lockdown Mode for high-risk individuals (executives, journalists); apply iOS updates promptly — Apple typically patches zero-click chains within 1-2 weeks of discovery; monitor MDM logs for rogue enrollment attempts; and audit installed CA certificates across the managed fleet.
