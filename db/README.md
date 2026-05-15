# ARGUS Data Layer

ARGUS keeps engagement-related data across **four distinct stores**,
each chosen because it's the right tool for its job. This module
abstracts them so callers don't need to know which one holds what.

```
                            ┌──────────────────────────────────────────┐
                            │             Caller code                  │
                            └──┬─────────────────┬──────────────────┬──┘
                               │                 │                  │
                               ▼                 ▼                  ▼
                      ┌────────────────┐  ┌──────────────┐  ┌─────────────┐
                      │ mongo_client.py│  │neo4j_client.py│  │  cache.py   │
                      │ (operational)  │  │ (attack graph)│  │ (TTL+LRU)   │
                      └───────┬────────┘  └───────┬───────┘  └──────┬──────┘
                              │                  │                 │
                              ▼                  ▼                 ▼
                        ┌─────────┐         ┌────────┐        ┌─────────┐
                        │ MongoDB │         │ Neo4j  │        │ In-RAM  │
                        │ argus_  │         │ argus  │        │(cache-  │
                        │ pentest │         │        │        │ tools)  │
                        └─────────┘         └────────┘        └─────────┘
```

Plus a fifth store handled by the **auth module** in its own folder:

```
                                                    ┌──────────────────┐
                                                    │ ../auth/db.py    │
                                                    │  SQLAlchemy 2.0  │
                                                    └────────┬─────────┘
                                                             │
                                                             ▼
                                                    ┌──────────────────┐
                                                    │ SQLite (dev) or  │
                                                    │ PostgreSQL (prod)│
                                                    │  argus_auth.db   │
                                                    └──────────────────┘
```

---

## Contents

1. [Why four stores?](#why-four-stores)
2. [Files](#files)
3. [What lives where](#what-lives-where)
4. [Schemas](#schemas)
5. [Cache layer (`cache.py`)](#cache-layer)
6. [MongoDB client (`mongo_client.py`)](#mongodb-client)
7. [Neo4j client (`neo4j_client.py`)](#neo4j-client)
8. [Configuration](#configuration)
9. [Backups](#backups)

---

## Why four stores?

| Store | Justification |
|-------|---------------|
| **MongoDB** | Engagement state is document-shaped, schema-evolves frequently as new finding types appear, and ops teams already have backup procedures for it. Native JSON-as-row beats serialising into a relational model. |
| **Neo4j** *(optional)* | The attack graph is fundamentally a graph (nodes = hosts/users/creds/services, edges = "has-credential-for", "exploitable-via", "lateral-route-to"). Cypher beats writing graph traversal in SQL or doing it in Python. |
| **In-process cache** | Hot-path lookups (recent CVE → CVSS, target → ASN, agent → bus subscription) live here. No Redis dependency means no extra service to babysit. |
| **SQLite / PostgreSQL (via auth)** | Auth tables need strict relational integrity (foreign keys, unique constraints, transactions). Mongo's flexibility is a liability when you need referential guarantees on `sessions → refresh_tokens → users`. |

When you only have a hammer, every problem looks like a nail. We
deliberately don't.

---

## Files

| File | Role |
|------|------|
| `mongo_client.py` | Async Motor client + every CRUD method for engagement state, findings, scan results, agents, shells, payloads. |
| `neo4j_client.py` | Async Neo4j driver wrapper for the semantic attack graph. Graceful degradation when Neo4j isn't running. |
| `cache.py` | In-process TTL + LRU cache (cachetools-backed, pure-Python fallback). |
| `schemas.py` | Pydantic models mapping to MongoDB collections (the SOURCE OF TRUTH for document shape). |
| `__init__.py` | Re-exports + module-level `setup()` / `teardown()` for the FastAPI lifespan. |

---

## What lives where

### MongoDB — `argus_pentest` database

| Collection | Purpose |
|------------|---------|
| `sessions` | Engagement metadata: target, scope, status, mode, start/end |
| `findings` | Every vulnerability, exposure, weakness — full provenance + evidence |
| `scan_results` | Raw tool output (nmap XML, nuclei JSON, sqlmap log, …) keyed by session+tool |
| `agents` | Live agent state: phase, current tool, last finding, ETA |
| `shells` | Active reverse-shell metadata (PID, tty, target, dropped via) |
| `payloads` | Generated payloads + their encoder ladder + AV-scan results |
| `credentials` | Harvested + cracked + sprayed credentials (operational, not auth users) |
| `reports` | Generated report drafts + final exports |
| `playbook_runs` | Deterministic playbook execution traces (links to `knowledge/playbooks/`) |

### Neo4j — `argus` database *(optional)*

| Node label | Properties |
|------------|-----------|
| `:Host` | ip, hostname, os, services |
| `:Service` | host, port, version, vulns |
| `:Credential` | user, hash, plaintext, domain |
| `:User` | name, domain, group_memberships, privs |
| `:Vulnerability` | cve, cvss, exploit_chain |
| `:Tool` | name, version, profile |

| Relationship | Meaning |
|--------------|---------|
| `(:Host)-[:RUNS]->(:Service)` | host serves this service |
| `(:Service)-[:VULNERABLE_TO]->(:Vulnerability)` | exploitability assertion |
| `(:Credential)-[:VALID_ON]->(:Host)` | tested + working creds |
| `(:User)-[:HAS_CREDENTIAL]->(:Credential)` | identity → secret |
| `(:Vulnerability)-[:EXPLOITED_BY]->(:Tool)` | confirmed payload |
| `(:Host)-[:LATERAL_TO {via, cost}]->(:Host)` | reachable from |

The frontend's `AttackGraph.jsx` view reads this graph and renders an
interactive D3-force layout.

### Cache (`cache.py`)

Hot lookups with short TTL. Eviction is LRU when capacity hits, plus
per-entry expiry. **No persistence**.

Typical entries:

| Key | TTL | Source |
|-----|-----|--------|
| `cvss:CVE-2024-1234` | 24 h | `utils/cvss_scorer.py` |
| `asn:1.2.3.4` | 1 h | OSINT subagent |
| `agent_bus_sub:vuln` | 1 min | `agents/base_agent.py` |
| `llm_response:<sha256(prompt)>` | 5 min | MasterAgent (idempotency cache) |

### Auth DB (SQLite / PostgreSQL) — *see `../auth/README.md`*

`users`, `auth_sessions`, `auth_audit_log`, `auth_session_states`,
`auth_role_assignments`, `auth_mfa_factors`, `auth_scim_bearer_tokens`,
`auth_identity_providers`, etc. The auth module manages its own
schema independently; this folder doesn't touch it.

---

## Schemas

Every MongoDB collection has a matching Pydantic model in `schemas.py`.
Callers should ALWAYS go through the model, not raw `dict`s:

```python
from db.schemas import Finding, ScanSession

async def add_finding(session_id, **kwargs):
    f = Finding(session_id=session_id, **kwargs)
    return await mongo.findings.insert_one(f.model_dump(mode="json"))
```

Why bother:
- Catches typos at the boundary (`severity="CRITCIAL"` → ValidationError)
- Enforces enums (`severity ∈ {CRITICAL, HIGH, MEDIUM, LOW, INFO}`)
- Round-trips datetimes correctly
- Lets the API layer serialize for /api responses without re-validation

---

## Cache layer

Public API:

```python
from db.cache import cache_get, cache_set, cache_invalidate, cached

# Get / set
val = cache_get("cvss:CVE-2024-1234")
cache_set("cvss:CVE-2024-1234", 9.8, ttl_sec=86400)

# Decorator form
@cached(ttl_sec=300, key=lambda asn: f"asn_lookup:{asn}")
async def lookup_asn(asn: int) -> dict:
    return await whois_client.lookup(asn)

# Invalidate (single key or prefix)
cache_invalidate("cvss:CVE-2024-1234")
cache_invalidate_prefix("agent_bus_sub:")
```

Eviction is automatic. Total cache size is bounded by `CACHE_MAX_ITEMS`
(default 50 000); LRU evicts when exceeded.

---

## MongoDB client

```python
from db import mongo

# CRUD
await mongo.sessions.insert_one({...})
session = await mongo.sessions.find_one({"_id": session_id})
await mongo.findings.update_one({"_id": fid}, {"$set": {"validated": True}})

# Aggregation
pipeline = [
    {"$match": {"session_id": sid}},
    {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
]
counts = await mongo.findings.aggregate(pipeline).to_list(None)

# Index management (called by db.setup() on boot — idempotent)
await mongo.findings.create_index([("session_id", 1), ("severity", -1)])
```

`db.setup()` is called from `agent_server.py`'s lifespan; it creates
indexes + verifies connectivity.

---

## Neo4j client

```python
from db import neo4j

if neo4j.available():
    async with neo4j.session() as s:
        await s.run("""
            MERGE (h:Host {ip: $ip})
            SET h.os = $os
        """, ip="10.0.0.5", os="Windows Server 2019")

        result = await s.run("""
            MATCH path = (:Host {ip: $start})-[:LATERAL_TO*1..3]->(:Host {ip: $end})
            RETURN path
        """, start="10.0.0.5", end="10.0.0.99")
```

`neo4j.available()` returns False when the driver is missing OR the
service is unreachable, so callers degrade gracefully (write
operations become no-ops, reads return empty lists).

---

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `MONGO_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `MONGO_DB` | `argus_pentest` | Database name |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j auth |
| `NEO4J_PASS` | *(unset)* | Neo4j auth |
| `CACHE_MAX_ITEMS` | `50000` | In-process cache capacity |
| `AUTH_DATABASE_URL` | `sqlite:///argus_auth.db` | Auth tables (see `../auth/README.md`) |

---

## Backups

Backing up an ARGUS deployment means snapshotting **all** four
stores at roughly the same time. There's no transactional consistency
across them, but findings + attack-graph diverge only briefly
(typically < 1 s) because writes go through the AgentBus in order.

| Store | Backup command |
|-------|----------------|
| MongoDB | `mongodump --uri="$MONGO_URI" --out /backup/$(date +%F)` |
| Neo4j | `neo4j-admin database dump argus --to-path=/backup/$(date +%F)` |
| Auth (SQLite) | `cp argus_auth.db /backup/$(date +%F)/auth.db` |
| Auth (PostgreSQL) | `pg_dump -Fc argus_auth > /backup/$(date +%F)/auth.dump` |
| Cache | Not backed up — it rebuilds itself in < 5 minutes |

The audit-log JSONL export (see `../auth/README.md §6`) provides an
independent retention path that survives even a full-DB loss.

---

## Further reading

- [`../README.md`](../README.md) — project front page
- [`../auth/README.md`](../auth/README.md) — auth tables (5th data store)
- [`../knowledge/README.md`](../knowledge/README.md) — ChromaDB vector store (6th data store, RAG)
- [`schemas.py`](schemas.py) — Pydantic models that define every MongoDB document
