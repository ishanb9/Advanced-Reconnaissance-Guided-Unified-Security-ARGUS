---
id: onvif_rtsp
technology: "ONVIF / RTSP cameras"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [554, 3702]
  banners: ["rtsp/", "onvif", "hikvision", "dahua", "axis", "vivotek", "rtsp server"]
  markers: ["/onvif/device_service", "/Streaming/Channels/", "WS-Discovery", "onvif/Media"]
quick_wins:
  - { cmd: "nmap -sU -p 3702 --script broadcast-ws-discovery {host}", safety: safe, note: "WS-Discovery probe on UDP 3702 to enumerate ONVIF-capable cameras and retrieve device URNs" }
  - { cmd: "nmap -sV -p 554 --script rtsp-methods,rtsp-url-brute {host}", safety: safe, note: "Fingerprint RTSP server and enumerate allowed methods without authentication" }
  - { cmd: "onvif-util -a {host} --probe", safety: safe, note: "Query ONVIF device service for capabilities, manufacturer, firmware version, and stream URI without credentials" }
  - { cmd: "cameradar -t {host} -p 554", safety: intrusive, note: "Cred-brute RTSP streams using built-in wordlist; attempts default credentials (admin:admin, admin:12345, etc.)" }
  - { cmd: "python3 onvif-cli.py --host {host} --port 80 --user admin --password '' GetDeviceInformation", safety: intrusive, note: "Attempt ONVIF SOAP call with blank or default credentials to pull device info" }
references:
  - "CVE-2021-36260"
  - "CVE-2021-33044"
  - "CVE-2017-7921"
  - "CVE-2021-31955"
  - "ICSA-21-257-01"
  - "CISA KEV CVE-2021-36260"
  - "CISA KEV CVE-2017-7921"
mitre: "T0883"
---
# ONVIF / RTSP Camera Guidance

ONVIF (Open Network Video Interface Forum) is the dominant interoperability standard for IP surveillance cameras, defining a SOAP/HTTP API (default port 80/8080) for device management, media streaming, PTZ control, and event handling. RTSP (Real Time Streaming Protocol) on TCP 554 is the transport-layer channel used to deliver H.264/H.265 video streams. WS-Discovery on UDP 3702 allows cameras to broadcast their presence on the local network, making them trivially enumerable without any credentials. In authorized pentests, exposed camera infrastructure is a common source of credential reuse, firmware exploitation, and network pivot opportunities.

Begin with safe, read-only enumeration: send a WS-Discovery multicast probe on UDP 3702 to harvest device URNs and endpoints, then use nmap RTSP scripts to fingerprint the server version and check which methods (DESCRIBE, SETUP, PLAY) are accessible unauthenticated. ONVIF device service endpoints (`/onvif/device_service`) frequently respond to unauthenticated GetDeviceInformation and GetCapabilities SOAP calls, leaking firmware version, model, and stream URIs. Only escalate to credential bruting (Cameradar or onvif-cli with wordlists) after confirming scope authorization for intrusive activity, as repeated auth attempts may lock accounts or generate alerts.

Key risk exposures include: unauthenticated RTSP stream access (live video without credentials); Hikvision backdoor authentication bypass (CVE-2021-36260, critical RCE via crafted HTTP request to `/SDK/webLanguage`, CISA KEV); Hikvision unauthenticated user enumeration and auth bypass (CVE-2017-7921); Dahua authentication bypass allowing arbitrary admin account creation (CVE-2021-33044, also CISA KEV); and hardcoded/default credentials (`admin:admin`, `admin:12345`, `admin:password`) present across dozens of vendors including Axis, Vivotek, and Amcrest. Chained, these allow silent live-view access, credential dumping, and network traversal using the camera as a pivot host.

Remediation: disable WS-Discovery if not required, restrict RTSP access to authenticated sessions with strong unique credentials, segment camera VLANs from corporate networks, apply vendor firmware patches immediately (Hikvision and Dahua both have critical KEV-listed vulns with public PoCs), and disable the ONVIF API if PTZ or integration features are unused.
