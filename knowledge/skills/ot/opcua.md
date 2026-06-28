---
id: opcua
technology: "OPC-UA"
domain: OT
safety_class: safe
severity: high
life_safety: false
match:
  ports: [4840, 4843]
  banners: ["opc.tcp", "opcua", "opc ua", "open62541", "unified automation", "prosys"]
  markers: ["opc.tcp://", "HEL\x00\x00\x00\x00"]
quick_wins:
  - cmd: "nmap -sV -p 4840,4843 --script opcua-info {host}"
    safety: safe
    note: "Read-only OPC-UA endpoint discovery; retrieves server description, application URI, and security policy list"
  - cmd: "python3 -c \"from opcua import Client; c=Client('opc.tcp://{host}:4840'); c.connect(); print(c.get_endpoints()); c.disconnect()\""
    safety: safe
    note: "GetEndpoints unauthenticated call; enumerates all endpoint URLs, MessageSecurityMode, and policy URIs without authenticating"
  - cmd: "nmap -p 4840 --script opcua-info --script-args 'opcua-info.anon=true' {host}"
    safety: safe
    note: "Attempt anonymous session on SecurityPolicy None; confirms whether anonymous access is permitted"
  - cmd: "python3 -c \"from opcua import Client; c=Client('opc.tcp://{host}:4840'); c.connect(); ns=c.get_namespace_array(); print(ns); [print(c.get_node(n).get_browse_name()) for n in c.get_root_node().get_children()]; c.disconnect()\""
    safety: intrusive
    note: "Browse OPC-UA address space as anonymous user; enumerates namespaces, objects, and variable nodes — confirm scope before use"
  - cmd: "python3 -c \"from opcua import Client; c=Client('opc.tcp://{host}:4840'); c.connect(); node=c.get_node('ns=2;i=1'); print(node.get_value()); c.disconnect()\""
    safety: intrusive
    note: "Read a specific node value by NodeId; adjust ns/i to target; read-only but may trigger process alarms on some PLCs"
references:
  - "CVE-2022-44725"
  - "CVE-2023-27321"
  - "CVE-2021-40142"
  - "ICSA-22-354-01"
  - "CISA KEV CVE-2023-27321"
mitre: "T0852"
---
# OPC-UA guidance

OPC Unified Architecture (OPC-UA) is the dominant M2M communication protocol in modern ICS/SCADA environments, used to exchange real-time process data between PLCs, HMIs, historians, and SCADA servers. It runs primarily over opc.tcp on port 4840 (plain) and 4843 (HTTPS transport). Unlike its OPC Classic predecessor, OPC-UA supports structured security via message signing and encryption, but many production deployments leave SecurityPolicy set to None with anonymous authentication enabled — a finding on its own in an OT engagement.

During an authorized pentest the first safe step is always a passive GetEndpoints call, which requires no session and reveals the server's supported security policies, endpoint URLs, and application certificate. If the response lists SecurityPolicy None alongside anonymous UserTokenPolicy, the server accepts unauthenticated plain-text sessions; document this immediately. Certificate trust is a second common gap: OPC-UA servers that accept any client certificate (no trust list enforcement) allow trivial impersonation of legitimate SCADA clients. Check the server's application URI against the certificate's SAN — mismatch or self-signed with no trust-list validation is a medium finding.

Always lead with read-only operations when probing OPC-UA. Browse the address space to identify exposed process variables, alarms, and method nodes before attempting any reads or writes. Many OPC-UA servers expose Methods (analogous to RPC) that can directly command field devices; never call a Method node without explicit written authorization. Intrusive enumeration (deep node browsing, value reads on sensor/actuator nodes) should be gated behind a scope confirmation because reading certain nodes on safety-instrumented systems can inject spurious values into historian baselines or trigger alarms that operators must respond to.

Key risks in exposed OPC-UA deployments: unauthenticated process-data read (confidentiality), anonymous method calls that write setpoints or force digital outputs (integrity/availability), plaintext sessions susceptible to MitM replay (CVE-2022-44725 class), and stack vulnerabilities in popular OPC-UA SDKs such as open62541 and Unified Automation .NET stack. Remediation pointer: enforce SecurityPolicy Basic256Sha256 or Aes256Sha256Rsa4096, enable certificate trust lists, disable anonymous token policies, and segment OPC-UA servers behind a DMZ so they are not reachable from IT networks.
