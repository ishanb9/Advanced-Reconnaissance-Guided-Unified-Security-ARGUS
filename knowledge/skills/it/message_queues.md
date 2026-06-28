---
id: message_queues
technology: "Message queues (AMQP/Kafka/Redis)"
domain: IT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [5672, 15672, 9092, 29092, 6379, 6380]
  banners:
    - "amqp"
    - "rabbitmq"
    - "kafka"
    - "redis_version"
    - "activemq"
    - "amqp0-9-1"
    - "rabbitmq_management"
  markers:
    - "/api/overview"
    - "/api/queues"
    - "/api/exchanges"
    - "/api/vhosts"
    - "kafka.server"
    - "kafka.controller"
    - "redis_version"
    - "redis_mode"
quick_wins:
  - cmd: "nmap -sV -p 5672,15672,9092,6379 --script banner {host}"
    safety: safe
    note: "Banner grab across common MQ ports; reveals broker type and version"
  - cmd: "curl -s -u guest:guest http://{host}:15672/api/overview | python3 -m json.tool"
    safety: safe
    note: "RabbitMQ management API — read cluster metadata with default credentials (guest:guest)"
  - cmd: "curl -s -u guest:guest http://{host}:15672/api/queues | python3 -m json.tool"
    safety: safe
    note: "List all RabbitMQ queues, message counts, and consumer counts"
  - cmd: "curl -s -u guest:guest http://{host}:15672/api/exchanges | python3 -m json.tool"
    safety: safe
    note: "Enumerate RabbitMQ exchanges and bindings — reveals topic/routing structure"
  - cmd: "redis-cli -h {host} -p 6379 INFO server"
    safety: safe
    note: "Redis INFO — version, OS, connected clients, memory; no auth required if misconfigured"
  - cmd: "redis-cli -h {host} -p 6379 CONFIG GET bind"
    safety: safe
    note: "Check Redis bind address to confirm network exposure"
  - cmd: "redis-cli -h {host} -p 6379 KEYS '*'"
    safety: intrusive
    note: "Enumerate all Redis keys (can block large instances; use SCAN in production)"
  - cmd: "kafka-topics.sh --bootstrap-server {host}:9092 --list"
    safety: safe
    note: "List Kafka topics without authentication (Kafka pre-2.x or misconfigured PLAINTEXT listener)"
  - cmd: "kafka-console-consumer.sh --bootstrap-server {host}:9092 --topic <topic> --from-beginning --max-messages 10"
    safety: intrusive
    note: "Read messages from a Kafka topic — confirms unauthenticated read access and message content"
  - cmd: "kafka-console-producer.sh --bootstrap-server {host}:9092 --topic <topic>"
    safety: intrusive
    note: "Write test message to Kafka topic — confirms unauthenticated write access"
  - cmd: "curl -s -u guest:guest -X POST http://{host}:15672/api/exchanges/%2F/amq.default/publish -H 'Content-Type: application/json' -d '{\"properties\":{},\"routing_key\":\"pentest-probe\",\"payload\":\"ARGUS-probe\",\"payload_encoding\":\"string\"}'"
    safety: intrusive
    note: "Publish a test message via RabbitMQ management API — confirms write access with default credentials"
references:
  - "CVE-2023-46604"
  - "CVE-2022-33891"
  - "CVE-2022-0543"
  - "CVE-2021-26291"
  - "CISA KEV CVE-2023-46604"
mitre: "T1071.001"
---
# Message Queue guidance

Message queue brokers — RabbitMQ (AMQP, port 5672; HTTP management UI, port 15672), Apache Kafka (port 9092), and Redis used as a queue backend (port 6379) — form the nervous system of modern microservice architectures. They carry inter-service commands, event streams, job payloads, secrets, and session tokens. Exposure on a pentest typically means the broker is network-reachable from a segment it should not be, or that authentication has been left at factory defaults.

RabbitMQ ships with a `guest:guest` superuser that is restricted to localhost in recent versions but is frequently re-enabled or replicated to an admin account during deployment. The management REST API at port 15672 allows full queue/exchange inspection, message publishing, and virtual-host enumeration with only HTTP Basic auth. Start read-only: `/api/overview`, `/api/queues`, `/api/exchanges`. If default credentials work, enumerate all vhosts and sample queue message payloads via `/api/queues/%2F/<name>/get`.

Kafka listeners configured as `PLAINTEXT` (no TLS, no SASL) allow any client to list topics and consume or produce messages without credentials. CVE-2023-46604 (CVSS 10.0, actively exploited) allows unauthenticated RCE against the Kafka broker via a crafted `OpenChannel` request on port 9092 and is on the CISA KEV list — banner-only detection is sufficient to flag this; do not attempt exploitation without explicit scope approval. Redis without `requirepass` or `bind 127.0.0.1` exposes all data and the `CONFIG SET` / `SLAVEOF` / `DEBUG` commands; CVE-2022-0543 (Lua sandbox escape) permits RCE on Debian/Ubuntu builds where the Lua library is dynamically linked.

For authorized testing, lead with safe read-only enumeration: banner grab all known ports, test default credentials against the management API, list Kafka topics, and run `INFO` against Redis. Escalate to intrusive only after confirming exposure: read topic/queue message samples, then — if write access is in scope — publish a clearly-labelled probe message. Remediation focus: enforce authentication on all listeners, remove or disable `guest` accounts, bind brokers to loopback or internal VLANs, apply TLS to AMQP/Kafka transports, and patch CVE-2023-46604 immediately.
