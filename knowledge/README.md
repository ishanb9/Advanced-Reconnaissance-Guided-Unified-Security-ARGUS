# ARGUS Knowledge Base — User Guide

> The retrieval-augmented brain that makes ARGUS act like a senior pentester
> instead of a fuzzy autocomplete.

This guide covers everything you need to use, extend, and operate the
RAG (Retrieval-Augmented Generation) knowledge base shipped with ARGUS.

---

## Contents

1. [What it is](#what-it-is)
2. [Quick start](#quick-start)
3. [Folder layout](#folder-layout)
4. [The data folder](#the-data-folder)
5. [Playbooks — the deterministic layer](#playbooks--the-deterministic-layer)
6. [Building / refreshing the index](#building--refreshing-the-index)
7. [How retrieval actually works](#how-retrieval-actually-works)
8. [Configuration](#configuration)
9. [Sizing & performance](#sizing--performance)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)
12. [Further reading](#further-reading)

---

## What it is

When an ARGUS agent needs to decide *what to do next* during an
engagement (e.g. "I see SMB on 445, OS=Windows — what now?"), it queries
the knowledge base.  The KB returns:

- **Curated playbooks** that match the live intel exactly (deterministic)
- **Embedded chunks** from your writeups / docs / notes (semantic search)

Both signals are merged, reranked, and fed into the agent's prompt so its
plan reflects field-validated experience, not just LLM priors.

```
                ┌─────────────────────────┐
                │   Agent's question       │
                │  + current intel dict    │
                └──────────┬──────────────┘
                           ▼
        ┌───────────────────────────────────────────┐
        │  Tier 0 — Playbook lookup (YAML)          │  knowledge/data/playbooks/
        │  Tier 1 — Hybrid: vectors + BM25 + RRF    │  knowledge/db/
        │  Tier 2 — HyDE query rewrite (LLM)        │
        │  Tier 3 — BGE cross-encoder + MMR         │
        │  Tier 4 — Outcome / recency boost         │
        └──────────┬────────────────────────────────┘
                   ▼
            Top-K context  →  agent's prompt
```

Everything runs locally — no data leaves your box.

---

## Quick start

### 1. Install dependencies (one-time)

```bash
pip install -r requirements.txt
```

This pulls `chromadb`, `sentence-transformers`, `pypdf`, `beautifulsoup4`,
`lxml`, `tqdm`, `pyyaml`, plus the rest of the ARGUS stack.

### 2. Drop content into `knowledge/data/`

Anything goes: PDFs, markdown, YAMLs, text files.  Any subfolder structure.

```
knowledge/data/
├── playbooks/                    (43 ship by default; add your own)
├── my-htb-writeups/
│   ├── lame.pdf
│   └── jerry.md
├── client-X-notes.txt
└── nuclei-templates-cves/        (e.g. cloned from upstream)
```

### 3. Build the index

```bash
python knowledge/build_kb.py
```

First run downloads ~1.1 GB of models (`bge-m3` embedder + `bge-reranker-v2-m3`
cross-encoder) and ingests every supported file under `knowledge/data/`.
Typical first build on a laptop: **20–60 minutes** depending on corpus size.

### 4. Verify

```bash
python knowledge/build_kb.py --stats
```

You should see the chunk count, source-file count, and breakdown by chunk
type.  If `chunks: 0`, your `data/` is empty or unsupported.

That's it.  ARGUS will pick up the KB automatically on the next engagement.

---

## Folder layout

```
knowledge/
├── README.md                     (this file)
├── PLAYBOOK_GUIDE.md             (how to author playbooks)
├── TROUBLESHOOTING.md            (common problems + fixes)
│
├── data/                         <-- USER DROP ZONE
│   ├── README.md                 (short version of this guide)
│   ├── playbooks/                (43 curated YAMLs ship by default)
│   │   ├── service_smb_anonymous.yml
│   │   └── ...                   (drop your own here too)
│   └── (anything else: PDFs, MD, TXT, JSON, HTML…)
│
├── db/                           <-- BUILT ARTEFACT (auto-created)
│   ├── chroma.sqlite3            (the vector store)
│   └── ingest_manifest.json      (file-hash tracking for incremental)
│
├── build_kb.py                   <-- THE script (CLI + ingest + 4-tier retriever)
└── knowledge_base.py             (legacy sync API; kept for back-compat)
```

**Rule of thumb:** you only ever touch `data/`.  Everything else is the
product's internals.

---

## The data folder

`knowledge/data/` is the **single drop zone** for everything you want
ARGUS to learn from.  Subfolder structure is up to you.

### Supported file types

| Extension | Notes |
|---|---|
| `.pdf`              | Text-extractable PDFs (scanned PDFs need OCR first) |
| `.md` / `.markdown` | Headers / code blocks preserved; ideal format |
| `.txt`              | Plain text — your engagement notes work great |
| `.html` / `.htm`    | Web-page exports |
| `.mhtml`            | HackTheBox 0xdf-style writeup archives |
| `.json`             | Structured data (e.g. nuclei template JSON exports) |
| `.yaml` / `.yml`    | Plain YAML *or* playbook YAML (auto-detected by schema) |

### What to drop here

- **Pentest writeups** — HTB, THM, Vulnhub, blog posts (PDF or markdown)
- **Vendor pentest reports** you have permission to use as reference material
- **CVE PoCs / nuclei templates** — markdown or YAML
- **Internal tribal knowledge** — your own `.txt` / `.md` notes
- **Methodology docs** — HackTricks export, PayloadsAllTheThings, OWASP cheat sheets
  → see [Bulk-fetch curated external sources](#bulk-fetch-curated-external-sources) below for a one-command shortcut
- **Custom playbooks** (see [Playbooks](#playbooks--the-deterministic-layer))

### Bulk-fetch curated external sources

For getting started fast, ARGUS ships a helper that clones ~20 high-signal
repos (HackTricks, PayloadsAllTheThings, nuclei-templates, GTFOBins,
LOLBAS, MITRE ATT&CK, OWASP cheats, etc.) into `data/external/`:

```bash
bash knowledge/fetch_sources.sh           # tier A + B (~3-5 GB)
bash knowledge/fetch_sources.sh --full    # also include large CVE PoC hub
bash knowledge/fetch_sources.sh --list    # just print the repo list
python knowledge/build_kb.py              # ingest everything that landed
```

The script is **idempotent** — re-running pulls latest changes (only diffs
transfer).  Per-repo failures don't stop the rest.  Edit the script if
you want to add or remove sources.

### What NOT to drop here

- **Secrets** — credentials, API keys, internal hostnames in any writeup.
  Strip them first.  The KB is searchable; secrets in there are secrets
  any compromised agent process can read.
- **Copyrighted content** you can't legally redistribute.
- **Tool binaries** — only docs about them.
- **Anything > 50 MB per file** — chunking quality degrades; split first.

### Two kinds of content

The ingester treats them differently based on what they are:

| Type | Location | Processing |
|---|---|---|
| Playbook YAMLs (id + trigger + steps schema) | `data/playbooks/*.yml` | **NOT embedded** — loaded directly by the Tier-0 retriever at query time |
| Everything else | anywhere under `data/` | Chunked, embedded with `bge-m3`, stored in `knowledge/db/` |

---

## Playbooks — the deterministic layer

A playbook is a hand-authored YAML file describing one offensive
technique.  When the live intel matches a playbook's `trigger`, the
retriever returns the playbook **verbatim**, ranked above any fuzzy
chunk match.

Why?  Because "if SMB anonymous is open, run `enum4linux-ng -A`" is a
fact.  You don't want the agent fuzzy-searching that — you want it
returned exactly, every time, in the order you wrote.

### Anatomy of a playbook

```yaml
id: service_smb_anonymous
title: "SMB anonymous / null-session enumeration"
phase: recon                          # recon | exploit | privesc | web | post | lateral
mitre: ["T1135", "T1018"]             # MITRE ATT&CK technique IDs

trigger:                              # ALL must overlap with live intel
  services: ["smb", "microsoft-ds"]
  ports:    [139, 445]
  os_any:   ["windows", "linux"]      # any-of match
  technologies: []
  cves: []

keywords: ["smb anonymous", "null session", "enum4linux"]
preconditions:
  - "TCP/445 reachable from attacker"

steps:                                # returned in order, verbatim
  - tool: nmap
    cmd:  "nmap -sV -p139,445 --script=smb-enum-shares {target}"
    why:  "Fingerprint SMB version and probe for null shares"
  - tool: enum4linux-ng
    cmd:  "enum4linux-ng -A {target}"
    why:  "Comprehensive null-session enum"

expected_outcome: "Share list, RID-cycled user list, version + signing requirement"

fallbacks:
  - "If null sessions denied → guess weak creds: guest:'', admin:admin"
  - "If SMB signing not required → consider responder + ntlmrelayx relay"

references:
  - "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb"
```

### Adding your own playbooks

1. Copy any of the 43 existing playbooks as a template:
   ```bash
   cp knowledge/data/playbooks/service_smb_anonymous.yml \
      knowledge/data/playbooks/my_custom_play.yml
   ```
2. Edit the file — change `id`, `title`, `trigger`, `steps`, etc.
3. **No re-build needed.**  Playbooks are loaded fresh on every query.

For the full schema reference, matching rules, and authoring tips, see
[`PLAYBOOK_GUIDE.md`](./PLAYBOOK_GUIDE.md).

### Sharing playbooks with your team

Playbooks are plain text files — `git add` and commit them.  When your
teammate pulls and re-runs ARGUS, the new playbook is live immediately.

---

## Building / refreshing the index

### First build (or after `--reset`)

```bash
python knowledge/build_kb.py
```

- Walks `knowledge/data/` recursively
- Skips playbook YAMLs (loaded directly at query time)
- Embeds everything else into `knowledge/db/`
- Writes a manifest (`knowledge/db/ingest_manifest.json`) tracking each
  file's SHA-256

### Incremental update (the common case)

Just re-run the same command:

```bash
python knowledge/build_kb.py
```

- The manifest skips files whose hash hasn't changed
- Only new / modified files are re-embedded
- Typical refresh after dropping a few PDFs: **30 seconds to 2 minutes**

### Wipe and rebuild

```bash
python knowledge/build_kb.py --reset
```

Use this when:
- You change the embedder model (different vector dimensions)
- You suspect index corruption
- You want to re-process every file with updated chunking logic

### Just print stats

```bash
python knowledge/build_kb.py --stats
```

Outputs JSON with: total chunks, source files, by-phase breakdown,
by-chunk-type breakdown, embedder + reranker model names.

### Test a query

```bash
python knowledge/build_kb.py --search "apache 2.4.49 path traversal"
```

Returns the top-3 results formatted for human review.  Useful for
sanity-checking after a new ingest.

### Ingest a single file (without touching the rest)

```bash
python knowledge/build_kb.py /path/to/specific/file.pdf
```

Ingests just that file (still respects the manifest — re-running on the
same file is a no-op unless the file changed).

---

## How retrieval actually works

When ARGUS asks a question, the request flows through 4 tiers.  This is
useful to understand for tuning, not required for daily use.

### Tier 0 — Curated playbook lookup (deterministic)

- Source: `knowledge/data/playbooks/*.yml`
- Method: Token-overlap matching of YAML `trigger` against live `intel`
- Speed: < 50 ms regardless of corpus size
- When it wins: SMB seen → playbook returned verbatim, no fuzziness

### Tier 1 — Hybrid retrieval (vector + BM25 with RRF)

- Source: `knowledge/db/` (ChromaDB)
- Two parallel searches per query:
  - **Dense vectors** via `bge-m3` (1024-dim, cosine similarity)
  - **BM25** via SQLite FTS5 (keyword matching)
- Merged with **Reciprocal Rank Fusion** (k=60), Cormack et al.
- Optional pre-filter on `intel`-derived metadata (phase, OS, technology)

### Tier 2 — HyDE query rewrite (optional, LLM-driven)

- The agent's `think()` LLM writes a hypothetical 3-5 sentence answer
- That answer's prose is embedded and used as a SECOND query
- Boosts recall ~10-20% on technical queries (Gao et al., 2022)
- Skipped silently when no LLM is configured

### Tier 3 — Cross-encoder rerank + MMR diversity

- The top-N candidates are rescored with `bge-reranker-v2-m3`
- **Maximal Marginal Relevance** (λ=0.65) ensures the final top-K aren't
  6 paraphrases of the same writeup paragraph

### Tier 4 — Outcome × recency boost

- Chunks where outcome was "shell obtained" / "root" / "user flag" get
  a 1.2-1.5× multiplier
- Failed-attempt chunks get 0.65-0.7×
- Recency decay (365-day half-life) slightly favours newer writeups

The combined score is what ranks the final results.

---

## Configuration

Everything is overridable via environment variables.  Defaults are
production-sane.

| Variable | Default | Effect |
|---|---|---|
| `KB_EMBED_MODEL`  | `BAAI/bge-m3`              | Embedder.  **Changing requires `--reset`** (different vector dims). |
| `KB_RERANK_MODEL` | `BAAI/bge-reranker-v2-m3`  | Cross-encoder.  Query-time only. |
| `KB_MIN_RELEVANCE`| `0.40`                     | Cosine floor.  Lower → more recall, more noise. |
| `KB_RERANK_FETCH` | `40`                       | Candidates fed to the reranker.  Higher → better top-K, slower. |
| `KB_MMR_LAMBDA`   | `0.65`                     | MMR balance.  Lower → more diversity, less raw relevance. |
| `KB_DB_PATH`      | `knowledge/db`             | Override the index location (per-engagement scoping). |

### Per-engagement scoped collections

For sensitive engagements you can isolate the KB to a per-engagement
location:

```bash
export KB_DB_PATH=/secure/engagement-XYZ/db
python knowledge/build_kb.py --reset
```

The retriever auto-detects this var and uses that location for both
ingest and query.  Switch back to the shared KB by unsetting the var.

---

## Sizing & performance

### Disk

| Component | Typical size |
|---|---|
| `knowledge/data/`               | depends on what you drop (10-1000 MB) |
| `knowledge/db/` (built index)   | ~3-5× the source text size |
| Cached embedder + reranker      | ~1.1 GB (in `~/.cache/huggingface/`) |

Example: 10,000 chunks of pentest content = ~50 MB DB, ~1.5 MB manifest.

### RAM

- Embedder loaded: ~1.5 GB
- Reranker loaded: ~600 MB
- ChromaDB query: <100 MB
- **Recommended: 4 GB free RAM** during ingest (uses both models concurrently)

### CPU vs GPU

- CPU works fine for both ingest and query.
- GPU (CUDA / MPS) is auto-detected by `sentence-transformers` and gives
  3-10× speedup on ingest.  No code change needed.

### Indexing throughput

| Hardware | Approx |
|---|---|
| Modern laptop CPU only      | 80-150 chunks/sec |
| Laptop CPU + GPU (4 GB)     | 400-800 chunks/sec |
| Server with GPU (16 GB)     | 1500-3000 chunks/sec |

For a typical pentest-team corpus (5k-20k chunks), full re-ingest is
2-30 minutes.  Incremental refresh after adding a few files is seconds.

---

## Troubleshooting

For an exhaustive list see [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md).
The fast lookups:

| Symptom | Fix |
|---|---|
| `No module named 'chromadb'` | `pip install -r requirements.txt` |
| `Path does not exist: …/data` | Drop at least one supported file into `knowledge/data/` |
| First run hangs at "Loading model" | Be patient — downloading 1.1 GB.  Watch `~/.cache/huggingface/` grow. |
| Eval / search returns nothing | Run `python knowledge/build_kb.py --stats` — total_chunks should be > 0. |
| `chroma.sqlite3 locked` | Another process (probably `agent_server.py`) is holding it.  Stop that first. |
| Re-ingest re-processes every file | Manifest got wiped.  This is normal after `--reset`. |
| Wrong playbook ranked top | Re-check the playbook's `trigger.services` / `ports` — most often a typo. |

---

## FAQ

**Q: Should I re-build the index after every new file?**
A: No.  Re-running `python knowledge/build_kb.py` is safe at any time —
it's incremental.  Only changed files are re-embedded.

**Q: Can I delete files from `knowledge/data/` after building?**
A: Yes — but the chunks they produced will remain in `db/` until next
`--reset`.  For now this is OK; a future version may add a
`--prune-orphans` flag.

**Q: Does the data leave my machine?**
A: No.  ChromaDB is local SQLite.  The embedder runs locally.  The only
network call is the one-time download of model weights from HuggingFace,
and even that can be air-gapped (pre-cache and copy `~/.cache/huggingface/`).

**Q: Can multiple users share one KB?**
A: Yes — point them all at the same `KB_DB_PATH`.  ChromaDB's SQLite
backend handles concurrent reads fine.  Concurrent writes (two ingests at
once) — don't.  Run ingest from one operator at a time.

**Q: How do I know if my new playbook is being matched?**
A: Run a test:
```bash
python knowledge/build_kb.py --search "<keyword from your playbook>"
```
Or inspect via the retriever directly:
```bash
python -c "
import asyncio
from knowledge.build_kb import retrieve
async def t():
    r = await retrieve('<your test query>',
                       intel={'services':['<svc>'],'open_ports':[<port>]},
                       top_k=3, use_rerank=False)
    for p in r.playbooks: print(p.playbook.id, p.relevance, p.matched_on)
asyncio.run(t())
"
```

**Q: How do I scope the KB to one engagement?**
A: Set `KB_DB_PATH` before running ARGUS:
```bash
export KB_DB_PATH=/path/to/engagement-XYZ/db
python knowledge/build_kb.py --reset    # build the scoped index
python agent_server.py                  # ARGUS uses the scoped KB
```

**Q: Can I use a different embedder?**
A: Yes — set `KB_EMBED_MODEL` to any model on HuggingFace that
`sentence-transformers` supports.  **Then `--reset` is mandatory** because
vector dimensions differ between models.

**Q: How big can the KB get before retrieval slows down?**
A: ChromaDB scales well to ~100,000 chunks (~5 GB DB).  Beyond that,
look at the per-engagement `KB_DB_PATH` pattern instead of one
ever-growing index.

**Q: Can I disable HyDE / reranking for speed?**
A: Yes — the agent layer passes `use_rerank=False` / `use_hyde=False`.
Or set `KB_RERANK_MODEL=""` to disable reranker model loading entirely.

**Q: My team uses non-English writeups.  Will it work?**
A: Yes.  `bge-m3` is multilingual (100+ languages).
`bge-reranker-v2-m3` is also multilingual.  Just drop the files in
`knowledge/data/` like anything else.

---

## Further reading

- **[`PLAYBOOK_GUIDE.md`](./PLAYBOOK_GUIDE.md)** — Full schema reference,
  matching internals, authoring tips and tricks
- **[`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md)** — Long-form diagnosis
  for ingest / retrieval / model issues
- **[`data/README.md`](./data/README.md)** — Drop-zone quick reference
  (subset of this guide aimed at end users who only look in `data/`)
- **Reasoning behind the architecture** — see
  `docs/project-state/PROGRESS.md` for the design rationale and rejected
  alternatives

---

*Last updated: 2026-05-09  ·  RAG v3*
