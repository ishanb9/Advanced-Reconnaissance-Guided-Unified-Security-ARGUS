---
id: amazon_alexa_echo
technology: "Amazon Alexa / Echo"
domain: IoT
category: home
transport: ip
safety_class: intrusive
severity: high
life_safety: false
match:
  ports: [4070, 55442, 55443]
  banners: ["Amazon", "Echo", "Alexa"]
  markers: ["api.amazonalexa.com", "alexa.amazon.com", "X-Amzn-RequestId", "_amzn-alexa._tcp", "AVS"]
quick_wins:
  - { cmd: "curl -sk 'https://api.amazonalexa.com/v1/alexaApiEndpoint' -H 'Authorization: Bearer <lwa_token>'", safety: safe, note: "Probe Alexa API endpoint — confirm token validity and API access without device changes." }
  - { cmd: "curl -sk 'https://api.amazonalexa.com/v1/devices/@self' -H 'Authorization: Bearer <lwa_token>'", safety: safe, note: "Enumerate registered Echo devices linked to the account — read-only." }
  - { cmd: "curl -sk 'https://api.amazonalexa.com/v1/smarthome/query' -H 'Authorization: Bearer <lwa_token>' -d '{\"devices\":[]}'", safety: safe, note: "Query Smart Home device states linked through Alexa skills — read-only enumeration." }
  - { cmd: "nmap -Pn -sT -p4070,55442,55443 {host}", safety: safe, note: "Probe Echo local ports — 4070 is used by Amazon Music and local Alexa comms on some Echo versions." }
  - { cmd: "curl -sk -X POST 'https://api.amazonalexa.com/v1/directives' -H 'Authorization: Bearer <lwa_token>' -d '{\"directive\":{\"header\":{\"namespace\":\"Alexa.PowerController\",\"name\":\"TurnOn\"},\"endpoint\":{\"endpointId\":\"<id>\"}}}' ", safety: disruptive, note: "GATED — sends a directive to control a Smart Home device. Requires written authorization." }
references: ["CVE-2019-9979", "CVE-2020-9294", "Alexa Skills Kit Security Review Guidelines"]
mitre: "T1078.004 / ICS T0866"
---
# Amazon Alexa / Echo

Amazon Alexa is a voice-AI and smart-home control platform delivered through Echo hardware
devices and third-party integrations. Alexa communicates with Amazon's cloud via HTTPS and
the Alexa Voice Service (AVS) protocol. Smart Home control is brokered through Alexa Skills
using Lambda-based fulfillment or direct cloud-to-cloud integrations. Login with Amazon (LWA)
OAuth2 tokens authorize API access to the Alexa Smart Home API (`api.amazonalexa.com`).

**Why it matters offensively.** Alexa Skills with the Smart Home capability can link to any
cloud service that implements the Alexa Smart Home API — creating a cloud-to-cloud trust
bridge. A malicious or vulnerable Alexa Skill granted access to a user's home devices can
enumerate and actuate them without physical access. Skills with open redirect vulnerabilities
(OAuth state fixation, redirect_uri manipulation) allow token theft. Voice spoofing attacks
and always-on microphones raise persistent audio surveillance concerns. Echo devices running
outdated firmware have had vulnerabilities including CVE-2019-9979 (insufficient validation
leading to LAN-side SSRF/XSS) and CVE-2020-9294 (malicious skill triggering unexpected
voice phishing).

**Safe-first testing.** Enumerate via the Alexa Smart Home API using GET calls to list
endpoints and query states — no voice commands or directives required. Confirm LWA token
scope (`alexa::ask:skills:readwrite` vs `alexa::smarthome`) before testing command paths.

**Key risks.** Amazon account compromise cascades to all linked Smart Home devices; over-broad
Skill permissions; voice-squatting attacks (malicious skills with similar invocation names);
insecure Skill fulfillment endpoints (Lambda misconfiguration, open webhook); Echo as an
always-on microphone on a compromised LAN. Remediation: enforce MFA on Amazon accounts,
review and remove unused Skills, audit Smart Home device links, update Echo firmware via
automatic updates, and segment Echo devices on an IoT VLAN.
