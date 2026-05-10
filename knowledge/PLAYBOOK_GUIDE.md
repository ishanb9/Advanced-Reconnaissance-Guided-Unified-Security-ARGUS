# Playbook Authoring Guide

> Playbooks are how your team's tribal knowledge becomes deterministic
> retrieval that beats fuzzy semantic search every time.

This guide is for operators who want to **add** playbooks to ARGUS.
For day-to-day RAG usage see [`README.md`](./README.md).

---

## Contents

1. [Why playbooks exist](#why-playbooks-exist)
2. [Where they live](#where-they-live)
3. [Full schema reference](#full-schema-reference)
4. [Trigger semantics](#trigger-semantics)
5. [Scoring rules](#scoring-rules)
6. [Authoring template](#authoring-template)
7. [Style guide](#style-guide)
8. [Validation](#validation)
9. [Testing your playbook](#testing-your-playbook)
10. [Common mistakes](#common-mistakes)

---

## Why playbooks exist

The vector-search corpus contains thousands of writeup paragraphs that
*describe* offensive techniques.  When the agent needs to know "how do I
enumerate SMB without creds", embedding-based retrieval returns 6 fuzzy
paraphrases of the same idea, in non-deterministic order, sometimes
including off-topic noise.

A playbook fixes this:

- **Deterministic match** against the live intel (no embedding fuzziness)
- **Verbatim return** in the order you wrote it
- **Explicit fallbacks** when the primary chain fails
- **Tribal knowledge encoded** — your team's lessons survive turnover

When the live intel matches a playbook's `trigger`, that playbook is
returned **above** any vector-search result.

---

## Where they live

```
knowledge/data/playbooks/<your_playbook_id>.yml
```

Drop them in any subfolder under `knowledge/data/` if you want; the
loader scans recursively and identifies playbooks by **schema**, not
location.  A YAML file is treated as a playbook iff it has all three top-
level keys: `id`, `trigger`, `steps`.

**No re-ingest is needed** — playbooks are loaded fresh on every
retrieval call.  Save the file → it's live.

---

## Full schema reference

```yaml
# REQUIRED ─────────────────────────────────────────────────────────────
id:    <string>           # Unique snake_case identifier.  By convention:
                          #   service_*  for port-keyed primitives
                          #   tech_*     for application stacks
                          #   ad_*       for Active Directory
                          #   auth_*     for auth bypasses
                          #   privesc_*  for local PE
                          #   cloud_*    for AWS / Azure / GCP / k8s
                          #   web_*      for browser-side / API web bugs

trigger:                  # ALL members are OR-overlap with live intel.
                          # Empty / missing facets are wildcards.
  services:     [list]    # service names: "smb", "http", "ssh", …
  ports:        [list]    # integers: 80, 443, 22, … (exact match)
  os_any:       [list]    # OS keywords: "linux", "windows", "windows server", "bsd"
  technologies: [list]    # framework / product strings: "wordpress", "apache 2.4.49"
  cves:         [list]    # CVE-IDs: "CVE-2021-41773"

steps:                    # Returned VERBATIM in this order.
  - tool: <string>        # Name of the tool (nmap, curl, msfconsole, …)
    cmd:  <string>        # Exact command — supports {target}, {LHOST},
                          # {port}, {domain}, {dc_ip}, {base_url} placeholders
    why:  <string>        # ONE LINE explaining why this step matters

# RECOMMENDED ──────────────────────────────────────────────────────────
title: <string>           # Human-readable title (shown in UI / prompts)
phase: <string>           # recon | exploit | privesc | web | post | lateral
mitre: [list]             # MITRE ATT&CK technique IDs: "T1135", "T1558.003"
keywords: [list]          # Free-text terms used for query keyword matching

# OPTIONAL ─────────────────────────────────────────────────────────────
preconditions:    [list]  # What must be true BEFORE these steps will work
expected_outcome: <string> # ONE LINE describing success state
fallbacks:        [list]  # Free-text alternatives when primary chain fails
references:       [list]  # External URLs (HackTricks, NVD, GitHub PoCs)
```

---

## Trigger semantics

### How matching works

For each playbook, the matcher computes a relevance score in [0, 1] by
comparing each `trigger` facet to the corresponding intel field.

- **Empty facets are wildcards.**  An empty `cves: []` does NOT mean
  "only match when there are no CVEs" — it means "ignore CVEs".
- **CVE / technology / mitre matches are EXACT** (token-set overlap).
- **Port matches are NUMERIC EXACT** — `80` will NOT match `8080`.
- **Service matches use token-Jaccard ≥ 0.5** — `apache 2.4.49` matches
  `apache/2.4.49`.
- **OS matches are substring** — `os_any: ["windows"]` matches
  `os_guess: "windows server 2019"`.

### Score weights

| Facet | Weight per match |
|---|---|
| `cves`                 | **+1.00** |
| `technologies`         | **+0.45** |
| `services`             | **+0.40** |
| `ports`                | **+0.30** |
| `os_any`               | **+0.20** |
| `mitre` (vs intel mitre)| **+0.15** |
| `keywords` (vs query)   | **+0.20 per match, capped at 5** |
| `phase` (vs intel phase)| **+0.10** |

The raw score is normalised by 2.0 so most matches land in [0, 1].

### Specificity gate

If a playbook matches **only** on generic facets (services + ports) with
**no** CVE / technology / keyword / MITRE signal, its final score is
multiplied by 0.35.  This prevents every web-related playbook from tying
at the top of any HTTP target query.

To break the gate, your playbook needs at least one of:
- A specific `cves` entry that the intel has
- A specific `technologies` entry that the intel has
- A keyword overlap with the user's query

### Minimum score

`min_score=0.20` (default) — playbooks below this aren't returned at all.
A pure port-only match (single match × 0.30 × 0.35 specificity gate =
0.10) is filtered out.

---

## Authoring template

Copy this verbatim and edit:

```yaml
id: <category>_<short_name>
title: "Human title"
phase: recon                # adjust
mitre: ["T####"]            # ATT&CK IDs

trigger:
  services: []
  ports:    []
  os_any:   []
  technologies: []
  cves: []

keywords:
  - "primary keyword"
  - "alt phrasing"

preconditions:
  - "What must be true before these steps work"

steps:
  - tool: <tool_name>
    cmd:  "<exact command, with {target} placeholders>"
    why:  "One-line rationale"

expected_outcome: "What 'success' looks like"

fallbacks:
  - "If <thing> fails → try <alt>"

references:
  - "https://primary-source.example.com"
```

For a complete production-grade example see
`data/playbooks/service_smb_anonymous.yml`.

---

## Style guide

### `id`
- snake_case, all lowercase
- Prefix by category: `service_`, `tech_`, `ad_`, `auth_`, `privesc_`,
  `cloud_`, `web_`, `api_`, `mobile_`
- Example: `service_redis_unauth`, `tech_grafana`, `ad_kerberoast`

### `title`
- Short noun phrase, descriptive
- Avoid marketing language ("badass", "awesome")
- Good: `"SMB anonymous / null-session enumeration"`
- Bad:  `"Best SMB enum techniques"`

### `phase`
- Pick exactly one from the recognised set:
  - `recon` — discovery / fingerprinting
  - `exploit` — initial foothold
  - `privesc` — local privilege escalation post-foothold
  - `web` — browser-side or API web bugs
  - `post` — post-exploitation, exfil, persistence
  - `lateral` — moving between hosts / domains

### `trigger`
- Be tight.  An overly-permissive trigger creates noise.
- Don't add a service / port / OS unless your steps actually require it.
- For multi-version vulns, list **specific versions** in `technologies`,
  not generic product names.

### `keywords`
- Include common synonyms users would search for
- Include tool names (`enum4linux`, `crackmapexec`)
- Include CVE numbers as keywords (in addition to the `trigger.cves`)

### `steps`
- **Order matters** — return is verbatim.  List in execution order.
- Each step is **one shell-runnable command**, not a paragraph.
- Use `{placeholder}` for things the agent fills in: `{target}`,
  `{base_url}`, `{LHOST}`, `{LPORT}`, `{port}`, `{user}`, `{password}`,
  `{dc_ip}`, `{domain}`.
- The `why` field is one line.  No paragraphs.
- Quote any command containing `{` / `}` / `:` to keep YAML happy.

### `expected_outcome`
- One line.  Concrete: "Shell as `www-data`", "List of shares + users".

### `fallbacks`
- Free-text bullets.  These survive when the primary chain fails.
- Order by likelihood of working.

### `references`
- HackTricks page, NVD entry, official advisory, GitHub PoC repo.
- Avoid linking to short-lived blog posts.

---

## Validation

### Quick syntactic check

```bash
python -c "
from knowledge.build_kb import load_playbooks
pbs = load_playbooks(force_reload=True)
print(f'{len(pbs)} playbooks load cleanly')
for p in pbs:
    if not p.steps:        print(f'WARN no steps:        {p.id}')
    if not p.trigger:      print(f'WARN empty trigger:   {p.id}')
    if not p.expected_outcome: print(f'INFO no expected_outcome: {p.id}')
"
```

A correctly-authored playbook produces no warnings.

### YAML syntax check

```bash
python -c "
import yaml
yaml.safe_load(open('knowledge/data/playbooks/<your_file>.yml', encoding='utf-8'))
print('YAML OK')
"
```

If this errors with `mapping values are not allowed here` or similar,
you have an unquoted colon or bracket in a `cmd` field.  Wrap the value
in double quotes.

---

## Testing your playbook

After authoring, simulate the engagement scenario your playbook is meant
for and confirm it ranks #1:

```bash
python -c "
import asyncio
from knowledge.build_kb import retrieve

async def t():
    # Adjust query + intel to mimic the scenario where YOUR playbook should win
    r = await retrieve(
        'redis unauth ssh authorized_keys write rce',
        intel={'services':['redis'], 'open_ports':[6379]},
        top_k=3, use_rerank=False,
    )
    for p in r.playbooks:
        print(f'{p.playbook.id:<35} {p.relevance:.2f}  {p.matched_on}')

asyncio.run(t())
"
```

Expect your playbook's `id` to appear in position 1 with relevance ≥ 0.50
when the intel correctly matches the trigger.

If a different playbook outranks it: tighten yours or look at its
trigger to understand the false positive.

---

## Common mistakes

### Trigger too broad

```yaml
trigger:
  services: ["http", "https"]    # matches EVERY web target
  ports: [80, 443, 8080, 8443]
```

This will surface for every HTTP query, drowning out specific playbooks.
Add a `technologies` entry, a CVE, or unique `keywords`.

### Forgot to add MITRE / phase

```yaml
# missing phase: …
# missing mitre: …
```

These are recommended.  Without `phase`, the playbook can't claim the
`+0.10` phase bonus.  Without `mitre`, the agent can't correlate the
playbook to ATT&CK matrix rendering in the UI.

### Step contains multiple commands

```yaml
- tool: bash
  cmd:  "id; uname -a; cat /etc/os-release"   # OK — quick recon snapshot
- tool: bash
  cmd:  "for x in *; do exploit $x; done"     # AVOID — too complex
```

Steps that loop / branch should be **scripts** in their own files,
referenced from the `cmd`.  Inline complexity hurts readability and
prevents agents from substituting placeholders correctly.

### Forgot to quote a `cmd` with `:` in it

```yaml
# BAD — YAML reads "user:" as a key
- tool: curl
  cmd:  curl -u user:pass http://target/

# GOOD
- tool: curl
  cmd:  "curl -u user:pass http://target/"
```

When in doubt, quote.

### Using full URLs instead of `{base_url}` placeholders

```yaml
# BAD — playbook is target-specific and can't be reused
- tool: curl
  cmd:  "curl http://10.10.10.5/login"

# GOOD — agent fills in the placeholder per-engagement
- tool: curl
  cmd:  "curl {base_url}/login"
```

### Missing `expected_outcome`

```yaml
# Functional but produces a thin entry
expected_outcome: ""
```

Always write what success looks like.  This is what tells the agent when
to stop running steps and pivot to the next phase.

### Steps in wrong order

```yaml
steps:
  - tool: msfconsole
    cmd:  "msfconsole -qx 'use exploit/...; run'"     # exploit
  - tool: nmap
    cmd:  "nmap -sV {target}"                          # ...AFTER the exploit?
```

Order is execution order.  Recon before exploit before post-ex.

---

## When NOT to write a playbook

- **One-off CTF tricks** that don't generalise — these belong in
  `ingest_tip()` (free-text, embedded into the corpus).
- **General methodology** — those belong as markdown files in `data/`,
  to be embedded normally.
- **Things you're not sure work** — playbooks should encode VALIDATED
  techniques.  Use a tip for "I think this might work…".

A playbook is field-validated tribal knowledge.  Treat the bar
accordingly — every entry is a contract that says "this works".

---

*See also: [`README.md`](./README.md) for general RAG usage,
[`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) for problem diagnosis.*
