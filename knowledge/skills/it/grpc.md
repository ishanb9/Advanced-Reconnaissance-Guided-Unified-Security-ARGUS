---
id: grpc
technology: "gRPC / Protobuf"
domain: IT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [50051]
  banners: ["application/grpc", "grpc-status", "content-type: application/grpc", "grpc-message"]
  markers: ["application/grpc", "grpc-status", "grpc-message", "/grpc.reflection.v1alpha.ServerReflection/"]
quick_wins:
  - { cmd: "grpcurl -plaintext {host}:50051 list", safety: safe, note: "List all gRPC services via server reflection (read-only enumeration)" }
  - { cmd: "grpcurl -plaintext {host}:50051 grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", safety: safe, note: "Directly probe ServerReflection endpoint to confirm reflection is enabled" }
  - { cmd: "grpcurl -plaintext {host}:50051 describe", safety: safe, note: "Dump full service/method/message descriptors for all reflected services" }
  - { cmd: "nmap -p 50051 --script=grpc-detect {host}", safety: safe, note: "Confirm gRPC over HTTP/2 on port 50051 with nmap banner probe" }
  - { cmd: "grpcurl -plaintext -d '{}' {host}:50051 <ServiceName>/<MethodName>", safety: intrusive, note: "Send empty request to a reflected method to probe for unauthenticated access or information disclosure" }
  - { cmd: "grpcurl -plaintext -H 'Authorization: Bearer invalid' -d '{}' {host}:50051 <ServiceName>/<MethodName>", safety: intrusive, note: "Test authentication bypass/error disclosure by sending malformed auth header" }
references: ["CVE-2023-44487", "CVE-2023-33953", "CVE-2023-32732"]
mitre: "T1046"
---
# gRPC / Protobuf guidance

gRPC is a high-performance RPC framework developed by Google that uses HTTP/2 as its transport and Protocol Buffers (Protobuf) as its default serialization format. It is commonly exposed on port 50051 and is identifiable by the `Content-Type: application/grpc` header present on all gRPC traffic. It is widely used in microservices, cloud-native backends, and internal service meshes, making exposed or misconfigured gRPC endpoints a valuable target during authorized assessments of modern application infrastructure.

The primary foothold for enumeration is the `grpc.reflection.v1alpha.ServerReflection` service. When Server Reflection is enabled (a common developer convenience that is frequently left on in production), an unauthenticated caller can enumerate all registered services, their methods, and full Protobuf message schemas using `grpcurl`. This effectively eliminates the need for `.proto` files and allows an operator to discover and interact with internal APIs that were never intended to be publicly documented. Begin with `grpcurl -plaintext {host}:50051 list` to confirm reflection is available before proceeding to method-level probing.

Key risks beyond enumeration include unauthenticated method invocation (many internal gRPC services assume network-level trust and omit per-call authentication), insecure use of plaintext (non-TLS) gRPC in production, exposure of administrative or privileged methods through reflection, and susceptibility to HTTP/2 Rapid Reset attacks (CVE-2023-44487) that can cause denial-of-service on unpatched server implementations. Protobuf deserialization of attacker-supplied payloads can also trigger bugs in generated code. Always confirm whether TLS mutual authentication (mTLS) is enforced; its absence on an internet-facing endpoint is a critical finding.

Remediation: disable Server Reflection in production deployments, enforce mTLS for all gRPC channels, apply per-RPC authentication (token or certificate-bound), and ensure the gRPC server runtime is patched against HTTP/2 Rapid Reset (CVE-2023-44487). Restrict port 50051 to internal network segments or VPN via firewall policy.
