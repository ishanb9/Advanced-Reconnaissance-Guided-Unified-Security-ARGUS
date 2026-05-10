# Troubleshooting Guide

Long-form diagnosis for ARGUS RAG issues, organised by symptom.
For everyday usage see [`README.md`](./README.md).

---

## Contents

1. [Installation issues](#installation-issues)
2. [Build / ingest issues](#build--ingest-issues)
3. [Retrieval issues](#retrieval-issues)
4. [Playbook issues](#playbook-issues)
5. [Performance issues](#performance-issues)
6. [Concurrency / locking issues](#concurrency--locking-issues)
7. [Model / GPU issues](#model--gpu-issues)
8. [Data hygiene issues](#data-hygiene-issues)
9. [Diagnostic commands cheat sheet](#diagnostic-commands-cheat-sheet)

---

## Installation issues

### `No module named 'chromadb'` / `'sentence_transformers'`

Dependencies aren't installed.

```bash
pip install -r requirements.txt
```

If you get `error: externally-managed-environment` on a recent
Debian/Kali:

```bash
pip install --break-system-packages -r requirements.txt
# or, preferred:
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### `pip install torch` fails

Possible causes:

- **Outdated pip** — `pip install --upgrade pip` then retry.
- **Disk space** — torch needs ~3 GB free.  `df -h ~` to check.
- **Restricted network** — torch wheels pull from `download.pytorch.org`.
  Whitelist that host or use `--index-url https://download.pytorch.org/whl/cpu`
  for the CPU-only build (~600 MB instead of 3 GB).

### `chromadb` install pulls in old `pydantic`

ARGUS uses `pydantic==2.7.1`.  ChromaDB declares a wider range; pip
should resolve OK.  If you see `pydantic` getting downgraded:

```bash
pip install --upgrade chromadb pydantic==2.7.1
```

### `huggingface_hub` errors during model download

```text
HfHubHTTPError: 401 Client Error: Unauthorized
```

The model isn't gated, but some networks proxy HuggingFace and break
auth headers.  Workaround:

```bash
export HF_ENDPOINT=https://hf-mirror.com
python knowledge/build_kb.py
```

For full air-gap installs: pre-download models on a connected machine
and copy the entire `~/.cache/huggingface/` directory across.

---

## Build / ingest issues

### `Path does not exist: …/data`

```bash
mkdir -p knowledge/data
# Drop at least one supported file (.pdf, .md, .txt, .yaml, .html, .json)
python knowledge/build_kb.py
```

### `Total chunks: 0` after a successful build

You either have:

- An empty `data/` folder (only `data/README.md` doesn't count — it has
  one chunk).
- Files only in unsupported formats — confirm the extensions are in
  `[.pdf .md .markdown .html .htm .mhtml .txt .json .yaml .yml]`.
- All YAML files were detected as playbooks (which are not embedded).
  Check the build log for `Skipped N playbook YAML(s)`.

### `Re-ingesting every file every time`

You have one of:

- The manifest at `knowledge/db/ingest_manifest.json` was deleted /
  corrupted.  This is normal after `--reset` or a manual `rm -rf db/`.
- You're using `--force` — drop that flag.
- You're calling with different absolute paths each time — the manifest
  keys are absolute paths.  Use the same invocation each run.

### PDF chunks contain Unicode garbage (`�`, `�C0ld�`)

The PDF was extracted poorly.  Possible fixes:

1. **Source quality** — many writeup PDFs are PDF/A-3 with embedded
   bitmap fonts; `pypdf` can't extract those reliably.  Convert to
   markdown first:
   ```bash
   pip install marker-pdf      # or pymupdf4llm
   marker_single bad.pdf knowledge/data/converted/
   python knowledge/build_kb.py
   ```
2. **OCR for scanned PDFs** — `pypdf` can't extract text from scans.
   Use `ocrmypdf bad.pdf clean.pdf` first.

### `Ingest hangs forever on one PDF`

One PDF has an enormous embedded image / corrupt page tree.

- Move the offending file aside:
  ```bash
  mv knowledge/data/<offender>.pdf /tmp/
  python knowledge/build_kb.py
  ```
- The build log prints the file name BEFORE processing — check the last
  log line to know which file is the offender.

### `Out of memory` mid-ingest

The embedder loaded ~1.5 GB; in low-RAM environments this is tight.
Workarounds:

- Close other heavy processes.
- Set `KB_EMBED_MODEL=BAAI/bge-small-en-v1.5` (~130 MB, 384-dim).
  **Requires `--reset`.**

---

## Retrieval issues

### `--search` returns "(no results found)"

Likely causes, in order of probability:

1. The index is empty — confirm with `--stats`.
2. `KB_MIN_RELEVANCE` is too high — try lowering temporarily:
   ```bash
   KB_MIN_RELEVANCE=0.20 python knowledge/build_kb.py --search "..."
   ```
3. The query is too short / generic.  Use 4+ specific tokens.

### Wrong playbook ranks #1

Typical reasons:

- **Trigger too broad** in the unwanted playbook.  Tighten its
  `services` / `ports` / add specific `cves` or `technologies`.
- **Trigger too narrow** in the wanted playbook.  Widen its `keywords`
  or add the specific service+port combo.
- **Specificity gate is firing** on your wanted playbook (only generic
  match) — add a unique keyword or a CVE so the gate is broken.

Verify with:

```bash
python -c "
import asyncio
from knowledge.build_kb import retrieve
async def t():
    r = await retrieve('<your query>',
                       intel={'services':['<svc>'],'open_ports':[<port>]},
                       top_k=5, use_rerank=False)
    for p in r.playbooks:
        print(f'{p.playbook.id:<35} {p.relevance:.2f}  {p.matched_on}')
asyncio.run(t())
"
```

The `matched_on` list shows EXACTLY what facets matched.

### Reranker step is slow (> 5 s)

Cross-encoder inference is the bottleneck.  Mitigations:

- **GPU** — sentence-transformers auto-detects CUDA / MPS.  No code change.
- **Fewer candidates** — set `KB_RERANK_FETCH=20` (default 40).
- **Smaller model** — `KB_RERANK_MODEL=cross-encoder/ms-marco-MiniLM-L-6-v2`
  (~70 MB vs 570 MB).  Lower quality but 5× faster on CPU.
- **Disable for time-critical loops** — pass `use_rerank=False` from
  the agent caller.

---

## Playbook issues

### A new playbook YAML isn't being picked up

The loader scans `knowledge/data/` recursively for files with all three
top-level keys: `id`, `trigger`, `steps`.  If yours isn't loading:

1. Confirm file lives anywhere under `knowledge/data/`:
   ```bash
   ls knowledge/data/playbooks/<your_file>.yml
   ```
2. Check it has the required keys:
   ```bash
   python -c "
   import yaml
   d = yaml.safe_load(open('knowledge/data/playbooks/<your_file>.yml', encoding='utf-8'))
   print({k: bool(d.get(k)) for k in ('id','trigger','steps')})
   "
   ```
   All three must be `True`.
3. Force-reload the cache (otherwise tests use stale data):
   ```bash
   python -c "
   from knowledge.build_kb import load_playbooks
   pbs = load_playbooks(force_reload=True)
   print([p.id for p in pbs if 'YOUR_ID' in p.id])
   "
   ```

### `mapping values are not allowed here` on YAML load

Unquoted special character in a value.  Most often:

```yaml
# BAD — YAML reads "test" as a key inside the cmd
- cmd: curl -u test:pass http://example.com

# GOOD
- cmd: "curl -u test:pass http://example.com"
```

Wrap any value containing `: { } [ ] # & * ?` in double quotes.

### Playbook has steps but `relevance: 0.0`

The trigger doesn't match the intel you passed in.  Inspect:

```bash
python -c "
from knowledge.build_kb import load_playbooks
pb = next(p for p in load_playbooks(True) if p.id == 'YOUR_ID')
print('trigger:', pb.trigger)
print('keywords:', pb.keywords)
"
```

Then compare each facet to what your test intel sends in.

---

## Performance issues

### First build takes hours

Expected on first run because:

- Models download (~1.1 GB)
- Every chunk is embedded (slow on CPU)

Real benchmarks:

| Hardware | 5,000-chunk corpus |
|---|---|
| Modern laptop CPU only       | ~30 min |
| Laptop CPU + GPU (4 GB VRAM) | ~5 min |
| Server with GPU (16 GB)      | ~90 sec |

If your build is much slower than the table suggests, check:

- Are you on CPU when a GPU is available?  Verify with:
  ```bash
  python -c "import torch; print(torch.cuda.is_available(), torch.backends.mps.is_available())"
  ```
  If both are `False` and you have a GPU, install the right `torch` build
  for your hardware (see PyTorch docs).

### Subsequent builds are also slow

Manifest may be losing track.  Confirm it exists and is non-empty:

```bash
ls -la knowledge/db/ingest_manifest.json
python -c "import json; print(len(json.load(open('knowledge/db/ingest_manifest.json'))))"
```

If the manifest is missing, the next build re-embeds everything.  After
that build, the manifest should persist.

### Retrieval feels slow even with small KB

Two likely causes:

1. **Cold model load** — first query after starting the process loads
   embedder + reranker.  Subsequent queries are fast.  This is normal.
2. **Reranker on every query** — see [Reranker step is slow](#reranker-step-is-slow--5-s).

---

## Concurrency / locking issues

### `database is locked` / `chroma.sqlite3 locked`

Two writers on the same SQLite file — ChromaDB doesn't support
concurrent writes.

- If `agent_server.py` is running and you start `build_kb.py --reset`,
  one of them holds the file.  Stop the agent first:
  ```bash
  pkill -f agent_server.py
  python knowledge/build_kb.py --reset
  ```
- For CI / scripted use: serialise ingest jobs with a flock:
  ```bash
  flock /tmp/argus-kb.lock python knowledge/build_kb.py
  ```

### Multiple operators ingesting concurrently

Pick one operator to own ingest.  Concurrent reads from `agent_server.py`
processes are fine; concurrent writes are not.

For team setups, use per-engagement scoped collections:

```bash
export KB_DB_PATH=/path/to/engagement-XYZ/db
```

Each engagement has its own SQLite file — no cross-contention.

---

## Model / GPU issues

### `RuntimeError: CUDA out of memory`

Ingestion batched too aggressively for your GPU.  Workarounds:

- Force CPU: `CUDA_VISIBLE_DEVICES="" python knowledge/build_kb.py`
- Or use the smaller embedder: `KB_EMBED_MODEL=BAAI/bge-small-en-v1.5`
  (requires `--reset`).

### `MPS backend out of memory` (macOS Apple Silicon)

Same fix as CUDA.  Apple Silicon often has unified memory pressure;
8 GB Macs may need to fall back to CPU.

### Model download stalls

```bash
ls -la ~/.cache/huggingface/hub/   # is the dir growing?
```

If the cache isn't growing, you have a network issue — check proxy /
firewall rules for `huggingface.co` and `cdn-lfs.huggingface.co`.

### `OSError: [Errno 28] No space left on device`

Models + corpus exceed disk quota.

```bash
df -h ~
```

Free up cache:

```bash
rm -rf ~/.cache/huggingface/hub/    # nuclear: re-downloads ~1.1 GB next run
```

---

## Data hygiene issues

### Index contains content from a file I deleted

Currently expected — the manifest tracks files, but ChromaDB doesn't
reverse-prune chunks when source files vanish.

Workaround: full rebuild.

```bash
python knowledge/build_kb.py --reset
```

Future versions may add `--prune-orphans`.

### Duplicate content from two near-identical writeups

Set `KB_MMR_LAMBDA` lower (more diversity penalty):

```bash
export KB_MMR_LAMBDA=0.45      # default 0.65 — more aggressive de-dup
```

This is query-time only, no re-ingest needed.

### One source dominates results

Most often a book / vendor report contributes hundreds of chunks.  Drop
that source and `--reset`:

```bash
mv "knowledge/data/<dominant-source>.pdf" ~/argus-pruned/
python knowledge/build_kb.py --reset
```

To delete chunks WITHOUT dropping the source file, use SQL surgery:

```bash
sqlite3 knowledge/db/chroma.sqlite3 <<'SQL'
BEGIN;
DELETE FROM embedding_metadata WHERE id IN (
  SELECT id FROM embedding_metadata
  WHERE key='source_file' AND string_value = '<exact-filename>.pdf'
);
DELETE FROM embeddings WHERE id NOT IN (SELECT DISTINCT id FROM embedding_metadata);
COMMIT;
VACUUM;
SQL
```

### I want to start over completely

```bash
rm -rf knowledge/db/                  # nuke the index
rm -rf ~/.cache/huggingface/          # nuke the model cache (re-downloads)
python knowledge/build_kb.py --reset  # fresh build from data/
```

---

## Diagnostic commands cheat sheet

```bash
# How many chunks? Which sources?
sqlite3 knowledge/db/chroma.sqlite3 \
  "SELECT 'chunks',  COUNT(*) FROM embeddings;
   SELECT 'sources', COUNT(DISTINCT string_value) FROM embedding_metadata WHERE key='source_file';"

# Top 10 sources by chunk count
sqlite3 knowledge/db/chroma.sqlite3 \
  "SELECT string_value, COUNT(*) c FROM embedding_metadata
   WHERE key='source_file' GROUP BY string_value ORDER BY c DESC LIMIT 10;"

# Verify chunk_type metadata is being stored (was a known bug)
sqlite3 knowledge/db/chroma.sqlite3 \
  "SELECT string_value, COUNT(*) FROM embedding_metadata
   WHERE key='chunk_type' GROUP BY string_value;"

# CVE coverage
sqlite3 knowledge/db/chroma.sqlite3 \
  "SELECT COUNT(DISTINCT string_value) FROM embedding_metadata
   WHERE key='cves' AND string_value LIKE '%CVE-%';"

# How many playbooks load?
python -c "
from knowledge.build_kb import load_playbooks
print(len(load_playbooks(True)), 'playbooks')"

# What does the live retriever return?
python -c "
import asyncio
from knowledge.build_kb import retrieve
asyncio.run(retrieve('apache 2.4.49', intel={'cves':['CVE-2021-41773']}, top_k=3, use_rerank=False))
"

# Test a search (with or without LLM)
python knowledge/build_kb.py --search "apache rce"

# Print full KB stats
python knowledge/build_kb.py --stats
```

---

## Still stuck?

Capture this and share with the team:

```bash
{
  echo "=== ARGUS RAG diagnosis $(date -u) ==="
  python --version
  pip show chromadb sentence-transformers pypdf 2>/dev/null | grep -E "^Name|^Version"
  echo "--- env vars ---"
  env | grep -E "^KB_|^HF_|^PYTHONUTF8"
  echo "--- index ---"
  ls -lh knowledge/db/ 2>&1
  echo "--- index counts ---"
  sqlite3 knowledge/db/chroma.sqlite3 \
    "SELECT 'chunks', COUNT(*) FROM embeddings;
     SELECT 'sources', COUNT(DISTINCT string_value) FROM embedding_metadata WHERE key='source_file';" 2>&1
  echo "--- playbooks ---"
  python -c "from knowledge.build_kb import load_playbooks; print(len(load_playbooks(True)),'playbooks')" 2>&1
  echo "--- last build log ---"
  ls -t logs/ 2>/dev/null | head -3
} > /tmp/argus-rag-diag.txt 2>&1

# Attach /tmp/argus-rag-diag.txt to your bug report.
```

---

*See also: [`README.md`](./README.md) for usage,
[`PLAYBOOK_GUIDE.md`](./PLAYBOOK_GUIDE.md) for authoring playbooks.*
