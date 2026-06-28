---
id: graphql
technology: "GraphQL APIs"
domain: IT
safety_class: safe
severity: high
life_safety: false
match:
  ports: []
  banners: ["graphql", "apollo-server", "graphene", "strawberry-graphql", "hasura"]
  markers: ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "content-type: application/graphql", "x-hasura-", "__schema", "__typename", "apollo-server", "graphql-ws"]
quick_wins:
  - { cmd: "curl -s -X POST http://{host}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{__typename}\"}' | jq .", safety: safe, note: "confirm GraphQL endpoint is alive and responsive" }
  - { cmd: "curl -s -X POST http://{host}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }\"}' | jq .", safety: safe, note: "partial schema introspection to enumerate root types" }
  - { cmd: "python3 -m graphw00f -d -t http://{host}/graphql", safety: safe, note: "fingerprint GraphQL engine (graphw00f)" }
  - { cmd: "graphql-cop -t http://{host}/graphql -o json", safety: intrusive, note: "active security audit: introspection, field suggestions, batching, CSRF, DoS vectors" }
  - { cmd: "python3 -m clairvoyance -u http://{host}/graphql -o schema.json", safety: intrusive, note: "blind schema reconstruction when introspection is disabled — infers types via field-suggestion errors" }
  - { cmd: "curl -s -X POST http://{host}/graphql -H 'Content-Type: application/json' -d '{\"query\":\"{ __schema { types { name fields { name args { name type { name kind ofType { name kind } } } } } } }\"}' | jq .", safety: intrusive, note: "full introspection dump — reveals all types, fields, arguments; basis for BOLA/BFLA mapping" }
  - { cmd: "curl -s -X POST http://{host}/graphql -H 'Content-Type: application/json' -d '[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]' | jq .", safety: intrusive, note: "test query batching (enables amplification and brute-force of rate limits)" }
references: ["CVE-2021-41248", "CVE-2023-26108", "CVE-2022-21689", "CVE-2023-28442"]
mitre: "T1590.005"
---
# GraphQL APIs guidance

GraphQL is a query language and runtime for APIs that allows clients to request exactly the data they need via a single flexible endpoint. Unlike REST, a single GraphQL endpoint (commonly `/graphql`, `/graphiql`, or `/v1/graphql`) handles all operations — queries (read), mutations (write), and subscriptions (real-time). Because it consolidates data access into one endpoint and exposes a self-describing schema, a misconfigured GraphQL deployment is a high-value target during authorized pentests: full schema discovery, relationship mapping, and abuse of business logic are all achievable from a single entry point.

The primary detection signal is the presence of GraphQL-specific path markers (`/graphql`, `/graphiql`, `/playground`) and response headers or body fragments (`__typename`, `__schema`, `x-hasura-`). These markers appear on shared ports (80, 443, 8080, etc.), so port lists are intentionally omitted — rely on marker-based detection exclusively. Start with a safe `{__typename}` probe to confirm the endpoint exists, then fingerprint the engine with graphw00f before proceeding to introspection.

The two highest-severity GraphQL risks on a pentest are Broken Object-Level Authorization (BOLA) and Broken Function/Field-Level Authorization (BFLA). BOLA manifests when a query can retrieve another user's objects by supplying a different `id` argument (e.g., `user(id: 2)` returning data that should be scoped to the authenticated user). BFLA manifests when mutations or privileged fields (admin resolvers, `deleteUser`, `updateRole`) are accessible to low-privilege tokens because resolver-level authorization is missing or inconsistently applied. Both require the full schema (obtained via introspection or clairvoyance) to map attack surface before manual probing. Also test for query batching (array POST body), deep/recursive queries, and alias-based query amplification, which bypass rate limiting and can be used for credential stuffing or DoS.

Remediation priorities: disable or authenticate introspection in production (`NODE_ENV=production` disables it by default in Apollo); implement per-resolver authorization checks rather than relying solely on endpoint-level auth middleware; enforce query depth limits, query complexity limits, and disable batching unless required; deploy a GraphQL-aware WAF rule set or persisted-query allowlist.
