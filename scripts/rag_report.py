#!/usr/bin/env python3
"""scripts/rag_report.py — analyse the RAG trace: are the chunks worth it?

Reads ``logs/rag_trace.jsonl`` (produced by knowledge/rag_logger.py) and reports:
  - ingest: how many chunks were added vs deduped vs too-short, by chunk_type
  - queries: how many returned nothing (EMPTY), low-relevance hits (WEAK), or
    good hits (OK); the top-relevance distribution; latency; per-caller breakdown
  - retrieval effectiveness PER chunk_type — so you can see whether `skill`
    chunks are actually getting retrieved with good relevance, or are dead weight
  - cold chunks: ingested but never retrieved
  - a plain-English verdict + enhancement hints

Usage:
  python -X utf8 scripts/rag_report.py                 # human summary
  python -X utf8 scripts/rag_report.py --json          # machine-readable
  python -X utf8 scripts/rag_report.py --type skill    # focus one chunk_type
  python -X utf8 scripts/rag_report.py --trace path.jsonl
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_TRACE = _REPO / "logs" / "rag_trace.jsonl"


def load_trace(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _pct(rows: List[Dict[str, Any]], key: str, ps=(0, 25, 50, 75, 100)) -> Dict[str, float]:
    vals = sorted(float(r.get(key, 0) or 0) for r in rows)
    if not vals:
        return {f"p{p}": 0.0 for p in ps}
    out = {}
    for p in ps:
        idx = min(len(vals) - 1, max(0, int(round((p / 100.0) * (len(vals) - 1)))))
        out[f"p{p}"] = round(vals[idx], 4)
    out["avg"] = round(statistics.fmean(vals), 4)
    return out


def analyse(trace: List[Dict[str, Any]], focus_type: Optional[str] = None) -> Dict[str, Any]:
    ingest = [t for t in trace if t.get("kind") == "ingest"]
    search = [t for t in trace if t.get("kind") == "search"]

    ing_by_type = Counter(t.get("chunk_type", "?") for t in ingest if t.get("added"))
    ing_reasons = Counter((t.get("reason") or "added") for t in ingest)
    ingested_sources = {t.get("source") for t in ingest if t.get("added")}

    verdicts = Counter(t.get("verdict", "?") for t in search)
    callers = Counter(t.get("caller", "?") for t in search)
    lat = _pct(search, "elapsed_ms") if search else {}
    toprel = _pct(search, "top") if search else {}

    # Retrieval effectiveness per chunk_type (from the result snippets).
    retrieved_count: Counter = Counter()
    retrieved_rel: Dict[str, List[float]] = defaultdict(list)
    retrieved_sources: set = set()
    for s in search:
        for r in (s.get("results") or []):
            ct = r.get("type", "?")
            retrieved_count[ct] += 1
            try:
                retrieved_rel[ct].append(float(r.get("rel", 0)))
            except Exception:
                pass
            if r.get("source"):
                retrieved_sources.add(r.get("source"))

    eff = {}
    for ct, n in retrieved_count.items():
        rels = retrieved_rel.get(ct, [])
        useful = sum(1 for r in rels if r > 0)   # cross-encoder >0 = judged relevant
        eff[ct] = {"retrieved": n, "useful": useful,
                   "useful_rate": round(useful / len(rels), 3) if rels else 0.0,
                   "avg_rel": round(statistics.fmean(rels), 4) if rels else 0.0}

    cold = sorted(s for s in ingested_sources if s and s not in retrieved_sources)

    weak_or_empty = [{"q": s.get("query", "")[:120], "verdict": s.get("verdict"),
                      "top": s.get("top"), "caller": s.get("caller")}
                     for s in search if s.get("verdict") in ("EMPTY", "WEAK")]

    n_search = len(search)
    summary = {
        "ingest_events": len(ingest),
        "ingest_added_by_type": dict(ing_by_type),
        "ingest_outcomes": dict(ing_reasons),
        "queries": n_search,
        "verdicts": dict(verdicts),
        "empty_pct": round(100 * verdicts.get("EMPTY", 0) / n_search, 1) if n_search else 0.0,
        "weak_pct": round(100 * verdicts.get("WEAK", 0) / n_search, 1) if n_search else 0.0,
        "ok_pct": round(100 * verdicts.get("OK", 0) / n_search, 1) if n_search else 0.0,
        "top_relevance": toprel,
        "latency_ms": lat,
        "by_caller": dict(callers.most_common(12)),
        "effectiveness_by_type": eff,
        "cold_chunks": cold[:60],
        "cold_count": len(cold),
        "weak_or_empty_sample": weak_or_empty[:25],
    }
    if focus_type:
        summary["focus"] = {
            "type": focus_type,
            "ingested": ing_by_type.get(focus_type, 0),
            "retrieved": retrieved_count.get(focus_type, 0),
            "avg_rel": eff.get(focus_type, {}).get("avg_rel", 0.0),
        }
    return summary


def _verdict_text(s: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    q = s["queries"]
    if q == 0:
        out.append("No queries traced yet — run an engagement (or some kb.search calls), then re-run.")
        return out
    if s["empty_pct"] >= 25:
        out.append(f"⚠ {s['empty_pct']}% of queries returned NOTHING — corpus gaps or query/embedding mismatch.")
    if s["weak_pct"] >= 30:
        out.append(f"⚠ {s['weak_pct']}% of queries returned only WEAK matches — chunks need enhancement "
                   "(richer text, better chunking, or a stronger embedding model).")
    if s["ok_pct"] >= 60:
        out.append(f"✓ {s['ok_pct']}% of queries returned good matches — RAG is pulling its weight.")
    sk = s["effectiveness_by_type"].get("skill")
    if sk:
        out.append(f"skill chunks: retrieved {sk['retrieved']}×, {sk.get('useful', 0)} judged relevant "
                   f"(score>0); avg score {sk['avg_rel']} "
                   + ("(healthy)" if sk.get("useful", 0) > 0
                      else "(LOW — retrieved but not judged relevant; enhance guidance / chunking)"))
    elif s["ingest_added_by_type"].get("skill"):
        out.append("⚠ skill chunks were ingested but NEVER retrieved — the operator isn't querying for "
                   "them, or they don't match its queries. Consider adding skill guidance to the query path.")
    if s["cold_count"]:
        out.append(f"{s['cold_count']} ingested source(s) were never retrieved (dead weight candidates).")
    return out or ["RAG looks healthy on the traced sample."]


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Analyse the ARGUS RAG trace")
    ap.add_argument("--trace", default=str(_DEFAULT_TRACE), help="path to rag_trace.jsonl")
    ap.add_argument("--type", help="focus one chunk_type (e.g. skill)")
    ap.add_argument("--json", action="store_true", help="print the full JSON report")
    args = ap.parse_args(argv)

    path = Path(args.trace)
    trace = load_trace(path)
    if not trace:
        print(f"no RAG trace found at {path} — has ARGUS_RAG_DEBUG been on during a run?")
        return 0
    s = analyse(trace, focus_type=args.type)
    if args.json:
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0

    print(f"=== RAG TRACE REPORT ({path}) ===")
    print(f"Ingest: {s['ingest_events']} events | outcomes={s['ingest_outcomes']}")
    print(f"        added by type: {s['ingest_added_by_type']}")
    print(f"Queries: {s['queries']} | EMPTY {s['empty_pct']}% | WEAK {s['weak_pct']}% | OK {s['ok_pct']}%")
    print(f"        top-relevance: {s['top_relevance']}")
    print(f"        latency ms:    {s['latency_ms']}")
    print(f"        by caller:     {s['by_caller']}")
    print("Retrieval effectiveness by chunk_type:")
    for ct, e in sorted(s["effectiveness_by_type"].items(), key=lambda kv: -kv[1]["retrieved"]):
        print(f"        {ct:14} retrieved {e['retrieved']:5}×  avg_rel {e['avg_rel']}")
    if s.get("focus"):
        print(f"Focus [{s['focus']['type']}]: ingested {s['focus']['ingested']} | "
              f"retrieved {s['focus']['retrieved']} | avg_rel {s['focus']['avg_rel']}")
    if s["cold_count"]:
        print(f"Cold (ingested, never retrieved): {s['cold_count']} — e.g. {s['cold_chunks'][:8]}")
    if s["weak_or_empty_sample"]:
        print("Weak/empty queries (sample):")
        for w in s["weak_or_empty_sample"][:10]:
            print(f"        [{w['verdict']}] top={w['top']} caller={w['caller']} :: {w['q']}")
    print("VERDICT:")
    for line in _verdict_text(s):
        print(f"   {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
