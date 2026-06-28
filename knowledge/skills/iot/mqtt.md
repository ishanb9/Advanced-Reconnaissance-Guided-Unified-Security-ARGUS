---
id: mqtt
technology: "MQTT"
domain: IoT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [1883, 8883]
  banners: ["mqtt", "mosquitto", "emqx", "hivemq", "vernemq", "activemq"]
  markers: ["CONNECT", "CONNACK", "PUBLISH", "SUBSCRIBE"]
quick_wins:
  - { cmd: "nmap -sV -p 1883,8883 --script mqtt-subscribe {host}", safety: safe, note: "Detect MQTT service version and attempt anonymous subscription to # wildcard" }
  - { cmd: "mosquitto_sub -h {host} -p 1883 -t '#' -v --timeout 30", safety: safe, note: "Anonymous subscribe to all topics using # wildcard; read-only passive enumeration" }
  - { cmd: "mosquitto_sub -h {host} -p 1883 -t '$SYS/#' -v --timeout 15", safety: safe, note: "Read broker system metrics and connected-client info via $SYS reserved topics" }
  - { cmd: "mosquitto_sub -h {host} -p 8883 --cafile /etc/ssl/certs/ca-certificates.crt -t '#' -v --timeout 30", safety: safe, note: "TLS-wrapped anonymous subscribe on port 8883; enumerate exposed topic hierarchy" }
  - { cmd: "nmap -p 1883 --script mqtt-subscribe --script-args mqtt-subscribe.topic='#',mqtt-subscribe.timeout=20 {host}", safety: intrusive, note: "NSE mqtt-subscribe with forced wildcard; generates broker-side subscription load" }
  - { cmd: "mosquitto_pub -h {host} -p 1883 -t 'test/argus/probe' -m 'ARGUS-PROBE-$(date +%s)' -q 0", safety: intrusive, note: "Publish a benign test message to verify unauthenticated write access; confirm before use" }
references: ["CVE-2017-7279", "CVE-2018-12543", "CVE-2020-13849", "CVE-2023-28366", "ICSA-20-105-02", "CISA KEV CVE-2020-13849"]
mitre: "T0830"
---
# MQTT guidance

MQTT (Message Queuing Telemetry Transport) is a publish-subscribe messaging protocol optimised for constrained IoT devices and unreliable networks. Brokers (Mosquitto, EMQX, HiveMQ, VerneMQ, ActiveMQ) listen on TCP 1883 (plaintext) and 8883 (TLS). Clients authenticate with an optional username/password in the CONNECT packet; many deployments ship with authentication disabled, allowing any client to connect anonymously and subscribe to every topic using the `#` multilevel wildcard.

During an authorised engagement, begin with passive read-only enumeration: connect anonymously on port 1883 and subscribe to `#` using `mosquitto_sub`. This reveals the full topic hierarchy — device IDs, sensor readings, telemetry streams, command channels, and sometimes credentials embedded in payloads. The `$SYS/#` reserved namespace exposes broker internals: version, uptime, connected clients, and message throughput, all without generating operational traffic. Record all discovered topic paths and payload structures before escalating.

The key risk is unauthenticated publish access. On a broker with open ACLs, an attacker can inject arbitrary commands onto actuator topics (e.g. `devices/<id>/cmd`), potentially triggering state changes in physical equipment such as smart meters, HVAC, industrial PLCs that relay MQTT, or building automation systems. Wildcard subscriptions may also surface credentials, PII, or internal network topology. TLS on 8883 does not imply authentication — brokers commonly accept any TLS client anonymously, so always test 8883 as well as 1883. Only escalate to `mosquitto_pub` write tests after explicit operator approval, and use clearly namespaced test topics to avoid collisions with live device channels.

Remediation: enable authentication (username/password or mutual TLS client certificates), apply per-client ACLs restricting publish and subscribe to required topics only, disable the `$SYS` topic namespace for untrusted clients, and bind the broker to internal interfaces rather than 0.0.0.0.
