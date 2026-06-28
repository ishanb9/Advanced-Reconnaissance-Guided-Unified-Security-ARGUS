---
id: efb
technology: "EFB (Electronic Flight Bag)"
domain: OT
category: aviation
transport: ip
safety_class: safe
severity: high
life_safety: true
match:
  ports: []
  banners: ["Lido", "Jeppesen", "ForeFlight", "NaviGraph", "EFB", "FlightBag"]
  markers: ["jeppesen", "foreflight", "lido", "efb-server", "navtech", "X-EFB-Server"]
quick_wins:
  - { cmd: "nmap -Pn -sT -p 8080,8443 --script http-title,http-headers,http-auth-finder {host}", safety: safe, note: "Identify EFB content server — check for unauthenticated chart/nav-data access." }
  - { cmd: "curl -sk https://{host}:8443/api/charts/ -H 'Accept: application/json' | python3 -m json.tool", safety: safe, note: "Probe EFB chart API for unauthenticated enumeration of available chart datasets." }
  - { cmd: "nmap -Pn -sT -p 8080,8443 --script http-methods,http-cors {host}", safety: safe, note: "Check EFB server for unsafe HTTP methods and permissive CORS — read-only recon." }
references: ["CVE-2023-22375", "CVE-2021-36317", "FAA AC 120-76D", "EASA AMC 20-25", "ARINC 834"]
mitre: "T1190 / T1078"
---
# EFB — Electronic Flight Bag

The Electronic Flight Bag (EFB) is a computing platform used by flight crews to replace paper-based flight documentation — aeronautical charts (Jeppesen, Lido, Navtech), aircraft performance tools, runway analysis, weather briefing, mass & balance, and electronic checklists. Class 1/2 EFBs are portable commercial tablets (iPad with ForeFlight, Jeppesen Mobile TC); Class 3 EFBs are installed avionics-grade hardware. Many airlines run a dedicated **EFB content server** on the airline IT network that pushes chart/nav-data updates to crew devices over Wi-Fi or 4G. The FAA-approved software running on an EFB may feed into flight planning computations that influence fuel loads, takeoff speeds (V-speeds), and obstacle clearance calculations.

**Why it matters.** EFBs are a convergence point between IT systems (airline content servers, crew scheduling portals, Wi-Fi networks) and flight-critical data (V-speeds, weight & balance, charts). Attack vectors include: (1) **content server compromise** — an attacker who can write to the chart update server can push corrupted aeronautical charts or false approach plates to all aircraft in a fleet; (2) **EFB tablet compromise** — malware on a crew iPad can exfiltrate credentials, modify performance calculations, or display falsified runway data; (3) **Wi-Fi EFB update intercept** — MitM on the cockpit Wi-Fi EFB update channel (often HTTP or insufficiently validated HTTPS) allows chart injection; (4) **unauthenticated APIs** — several airline EFB server implementations have exposed unauthenticated REST endpoints serving full chart databases.

**Safe-first testing approach.** Treat the EFB content server as a standard web application. Perform read-only reconnaissance first: banner grab, HTTP method enumeration, API endpoint discovery (common paths: /api/charts, /efb/nav-data, /updates, /manifest.json). Check for unauthenticated access, default credentials (vendor documentation often lists these), and directory traversal. If credentials are obtained, verify the scope of accessible chart data and whether write/upload endpoints exist. **Do not modify chart data or nav-data on any system connected to production aircraft operations** — incorrect chart data constitutes a safety hazard. All write-path testing must be in an isolated staging environment with explicit airline authorization.

**Key risks and remediation.** EFB server deployments should enforce TLS with certificate pinning on device-to-server connections, require mutual authentication (certificate-based) for content updates, cryptographically sign all chart update packages (integrity validation before install), and segment the EFB content server from the general airline IT network. EFB tablets should enforce MDM policies, disable sideloading, and run only FAA/EASA-approved software versions. Performance tool inputs (V-speeds, mass & balance) should be independently cross-checked by crew rather than blindly trusted from EFB output.
