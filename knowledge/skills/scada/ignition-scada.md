---
id: ignition-scada
technology: "Inductive Automation Ignition"
domain: OT
category: scada
transport: ip
safety_class: safe
severity: high
life_safety: false
match:
  ports: [8088, 8043, 8060]
  banners: ["Ignition", "inductiveautomation"]
  markers: ["/web/home", "/StatusPing", "Ignition Gateway"]
quick_wins:
  - { cmd: "curl -sk http://{host}:8088/StatusPing", safety: safe, note: "Unauthenticated gateway status check; returns 'RUNNING' or 'REDUNDANT'. Leaks gateway name and version." }
  - { cmd: "nmap -Pn -sT -p8088,8043,8060 -sV --script http-title,http-headers {host}", safety: safe, note: "Banner grab to confirm Ignition version from HTTP headers and title page." }
  - { cmd: "curl -sk http://{host}:8088/main/web/config/ -I", safety: safe, note: "Check for unauthenticated access to the gateway configuration console." }
  - { cmd: "<Attempt default admin/admin credential via /main/web/login>", safety: intrusive, note: "GATED — default credential test; constitutes active authentication attempt." }
references: ["CVE-2023-39476", "CVE-2023-39475", "CVE-2023-39474", "ICSA-23-236-01"]
mitre: "T0817 / ICS T0862"
---
# Inductive Automation Ignition

Ignition is a web-deployed SCADA/HMI platform built on Java and Apache Tomcat, widely used in
manufacturing, water/wastewater, food and beverage, and energy sectors globally. The gateway
server listens on **8088/tcp** (HTTP) and **8043/tcp** (HTTPS) by default, and exposes a
browser-based designer, runtime clients, and a REST-like API. Because clients are delivered via
the browser or Java Web Start, a single gateway can serve an entire plant floor — making it a
high-value lateral-movement target if exposed to untrusted networks.

**Attack surface.** The `/StatusPing` endpoint responds without authentication, leaking gateway
name and version. Pre-authentication deserialization vulnerabilities (CVE-2023-39476,
CVE-2023-39475) in older versions allow RCE as the gateway process user, which typically has
read/write access to PLC tags and historian data. Default credentials (`admin/admin`) remain in
production deployments discovered on Shodan. The built-in scripting engine (Jython) can execute
arbitrary OS commands once authenticated.

**Safe-first testing.** Start with an unauthenticated `GET /StatusPing` and version banner grab.
Review the publicly accessible `/main/web/config/` and `/main/web/status/` endpoints before
any credential attempt. Map exposed modules (OPC-UA, MQTT, SQL Bridge) as each widens the attack
surface. Never write to PLC tags or modify gateway projects without scoped authorization — tag
writes directly actuate the process.

**Remediation.** Upgrade to Ignition 8.1.33+ (patches CVE-2023-3947x). Restrict 8088/8043 to
engineering workstations via firewall ACL. Disable the `StatusPing` endpoint or require
authentication. Enforce strong unique credentials and MFA on the gateway console. Disable unused
modules (e.g., legacy Sepasoft, Legacy Reporting) and enable TLS-only on 8043.
