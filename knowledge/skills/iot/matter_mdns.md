---
id: matter_mdns
technology: "Matter (mDNS commissioning)"
domain: IoT
safety_class: safe
severity: medium
life_safety: false
match:
  ports: [5353]
  banners: ["_matterc._udp", "_matter._tcp"]
  markers: ["_matterc._udp.local", "_matter._tcp.local", "VP=65521", "CM=1", "CM=2"]
quick_wins:
  - { cmd: "nmap -Pn -sU -p5353 --script dns-service-discovery {host}", safety: safe, note: "Passive mDNS sweep — enumerates _matterc._udp / _matter._tcp service records, extracts discriminator (D=), VID/PID (VP=), commissioning mode (CM=). Read-only." }
  - { cmd: "python3 -c \"from zeroconf import Zeroconf, ServiceBrowser; import time; z=Zeroconf(); h=type('H',(),{'add_service':lambda s,z,t,n:print(z.get_service_info(t,n)),'update_service':lambda*a:None,'remove_service':lambda*a:None})(); b=ServiceBrowser(z,'_matterc._udp.local.',h); time.sleep(5); z.close()\"", safety: safe, note: "Python zeroconf browser — lists all unprovisioned Matter devices advertising _matterc._udp, prints full TXT record (discriminator, VID, PID, commissioning window state)." }
  - { cmd: "chip-tool discover commissionables", safety: safe, note: "CHIP Tool (Matter SDK) — scans for commissionable nodes over mDNS/DNS-SD, prints discriminator, VID, PID, IP/port, and pairing hint without attempting to pair." }
  - { cmd: "chip-tool pairing code-wifi {host} {ssid} {password} <passcode> <discriminator>", safety: intrusive, note: "GATED — attempts open-commissioning with a guessed or default passcode (e.g. 20202021). Pairs the device to a new fabric, which may disrupt legitimate users. Requires explicit authorization." }
references: ["CVE-2023-3024", "CVE-2024-2173"]
mitre: "T1595.001"
---
# Matter (mDNS commissioning)

Matter (formerly Project CHIP) is the cross-vendor IoT interoperability standard backed by the
Connectivity Standards Alliance. Unprovisioned Matter devices advertise themselves on **5353/udp**
via **DNS-SD / mDNS** under the service type `_matterc._udp.local`. The DNS TXT record exposes
plaintext metadata: a short **discriminator** (12-bit, used to distinguish devices during
pairing), the **VID/PID** (Vendor ID / Product ID), and a **CM** flag indicating whether the
commissioning window is open. This data is visible to any host on the same Layer-2 segment
(or multicast-routed VLAN) without authentication.

**Why it matters.** An open commissioning window combined with a guessed or default passcode
(the Matter spec ships with the example passcode `20202021`; many consumer devices never change
it) allows any peer to complete PASE (Password Authenticated Session Establishment) and join the
device to an attacker-controlled fabric. Once commissioned, the attacker holds a fabric identity
and can issue operational commands (on/off, lock/unlock, climate set-point) over the encrypted
Matter operational channel, potentially displacing or shadowing the legitimate controller.
VID/PID in the TXT record enables targeted firmware-downgrade or known-CVE attacks before the
device is paired.

**Safe-first testing.** Begin with passive mDNS enumeration: `nmap --script dns-service-discovery`
or a `zeroconf` / `chip-tool discover` sweep collects discriminator, VID, PID, and commissioning
state without any pairing attempt. Check CM= (0 = closed, 1 = enhanced window open, 2 = basic
window open) — an open window is the prerequisite for unauthenticated commissioning. Cross-reference
the VID/PID against the CSA product database and known-CVE lists. Only attempt a PASE passcode
guess (`chip-tool pairing`) if explicitly scoped and authorized — this is an intrusive action that
pairs the device to a new fabric and may disrupt the owner's home automation.

**Remediation.** Close the commissioning window after initial setup and enforce a non-default
passcode on every device. Segment IoT VLANs to prevent mDNS from leaking to untrusted segments
(use mDNS proxy / gateway rather than open multicast forwarding). Apply vendor firmware updates
promptly — Matter firmware CVEs frequently affect the PASE stack or TLV parsing. Monitor for
unexpected fabric entries via the commissioner's fabric management interface.
