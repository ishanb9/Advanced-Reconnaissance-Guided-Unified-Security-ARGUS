"""Defensive posture fingerprinting (Improvement #12).

The agent's behaviour should depend on what's *watching*.  Hammering a
target with sqlmap or hydra is a fine plan against an unmonitored CTF
box, and a career-ending plan against a CrowdStrike-instrumented prod
endpoint behind a Cloudflare WAF.

This module is a **passive interpreter**: it never fires its own probes.
It mines the intel dict — raw tool outputs, banners, HTTP headers,
service versions, captured processes — for known defensive product
fingerprints, then surfaces a structured ``DefensivePosture`` record so:

* the LLM phase planners see "EDR detected: CrowdStrike Falcon" in
  ``_intel_summary`` and pivot tradecraft accordingly,
* the noise budget (#11) auto-downshifts toward stealth when a SIEM or
  EDR is found,
* the operator gets a clear feed entry the moment a defender is
  identified.

Detection categories
--------------------
* **EDR**         — endpoint detection & response (CrowdStrike, SentinelOne,
                    Carbon Black, Defender for Endpoint, Cylance, Sophos
                    Intercept X, McAfee MVISION, Cortex XDR, Elastic).
* **AV**          — traditional antivirus markers (Defender, Symantec,
                    Trend Micro, Bitdefender, Kaspersky, ESET).
* **WAF**         — perimeter web protection (Cloudflare, Akamai, AWS
                    WAF, Imperva, F5 BIG-IP ASM, ModSecurity, Sucuri,
                    Fortinet FortiWeb, Barracuda).
* **SIEM/Logger** — log shippers / agents (Splunk Universal Forwarder,
                    Elastic Beats, Wazuh, Sysmon, OSSEC, NXLog).
* **IDS/IPS**     — network-level (Snort, Suricata, Palo Alto, Cisco
                    Firepower).
* **DLP / honey** — data-loss & deception markers.

Each fingerprint contributes evidence to a category; categories with
non-zero evidence are emitted with their concrete product names and the
strings that triggered the match (so the operator can audit).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


logger = logging.getLogger(__name__)


__all__ = [
    "DefensivePosture", "fingerprint_posture", "render_posture_for_prompt",
    "stealth_recommended", "DEFENDER_PATTERNS",
]


# ── Fingerprint table ────────────────────────────────────────────────────
# Each entry: (category, product_name, regex, weight)
# Weight is 1 for soft hints (headers, banners) and 2 for strong tells
# (process names, signed binary paths, exact agent strings).

DEFENDER_PATTERNS: List[Tuple[str, str, "re.Pattern[str]", int]] = [
    # ── EDR ──────────────────────────────────────────────────────────
    ("edr", "CrowdStrike Falcon",
     re.compile(r"\b(?:csagent\.exe|csfalconservice|falcon-sensor|crowdstrike)\b", re.I), 2),
    ("edr", "SentinelOne",
     re.compile(r"\b(?:sentinelagent|sentinelone|s1agent|s1service)\b", re.I), 2),
    ("edr", "Carbon Black",
     re.compile(r"\b(?:cb defense|carbonblack|cbdaemon|cb\.exe|repmgr)\b", re.I), 2),
    ("edr", "Microsoft Defender for Endpoint",
     re.compile(r"\b(?:msmpeng|mssense|defender for endpoint|mdeclient|mde-?atp)\b", re.I), 2),
    ("edr", "Cylance",
     re.compile(r"\b(?:cylance|cylancesvc|cyprotect)\b", re.I), 2),
    ("edr", "Sophos Intercept X",
     re.compile(r"\b(?:sophos|hitman ?pro|sophosed|interceptx|sav\b|sed\.exe)\b", re.I), 2),
    ("edr", "McAfee MVISION / ENS",
     re.compile(r"\b(?:mcafee|mfeavsvc|mfemms|mfecanary|trellix)\b", re.I), 2),
    ("edr", "Cortex XDR",
     re.compile(r"\b(?:cortex\s*xdr|cyserver|cyveraservice|traps)\b", re.I), 2),
    ("edr", "Elastic Endpoint",
     re.compile(r"\b(?:elastic-?endpoint|endgame)\b", re.I), 2),
    ("edr", "Tanium",
     re.compile(r"\btanium(?:client|service)?\b", re.I), 2),

    # ── AV (signature-based) ─────────────────────────────────────────
    ("av", "Symantec Endpoint Protection",
     re.compile(r"\b(?:symantec|sepmasterservice|smc\.exe|sepm)\b", re.I), 1),
    ("av", "Trend Micro",
     re.compile(r"\btrend\s*micro|tmlisten|tmccsf\b", re.I), 1),
    ("av", "Bitdefender",
     re.compile(r"\bbitdefender|bdservicehost|epsecurityservice\b", re.I), 1),
    ("av", "Kaspersky",
     re.compile(r"\bkaspersky|avp\.exe|klnagent\b", re.I), 1),
    ("av", "ESET",
     re.compile(r"\beset|ekrn\.exe|egui\.exe\b", re.I), 1),
    ("av", "Windows Defender (consumer)",
     re.compile(r"\b(?:windows defender|msmpeng\.exe|mpcmdrun)\b", re.I), 1),

    # ── WAF ──────────────────────────────────────────────────────────
    ("waf", "Cloudflare",
     re.compile(r"\b(?:cloudflare|cf-ray|__cfduid|__cf_bm|server:\s*cloudflare)\b", re.I), 2),
    ("waf", "Akamai",
     re.compile(r"\b(?:akamai|akamaighost|x-akamai|aka\.io)\b", re.I), 2),
    ("waf", "AWS WAF / CloudFront",
     re.compile(r"\b(?:awselb|x-amz-cf-|cloudfront|x-amzn-requestid|aws-?waf)\b", re.I), 1),
    ("waf", "Imperva Incapsula",
     re.compile(r"\b(?:incap_ses|visid_incap|x-iinfo|incapsula|imperva)\b", re.I), 2),
    ("waf", "F5 BIG-IP / ASM",
     re.compile(r"\b(?:bigip|big-?ip|f5-?asm|tmui|x-waf-event-info)\b", re.I), 2),
    ("waf", "ModSecurity",
     re.compile(r"\b(?:mod_security|modsecurity|owasp\s*crs)\b", re.I), 2),
    ("waf", "Sucuri",
     re.compile(r"\b(?:sucuri|x-sucuri-id|cloudproxy)\b", re.I), 2),
    ("waf", "FortiWeb",
     re.compile(r"\bfortiweb|fortigate\b", re.I), 2),
    ("waf", "Barracuda WAF",
     re.compile(r"\bbarra(?:cuda)?[-_ ]?waf\b", re.I), 2),
    ("waf", "Generic WAF (403/406 spike)",
     re.compile(r"\b403\s*forbidden\b.*\bwaf\b|\bwaf-?cookie\b", re.I), 1),

    # ── SIEM / log-shipper agents ────────────────────────────────────
    ("siem", "Splunk Universal Forwarder",
     re.compile(r"\b(?:splunkd|splunkforwarder|universalforwarder)\b", re.I), 2),
    ("siem", "Elastic Beats",
     re.compile(r"\b(?:filebeat|winlogbeat|metricbeat|auditbeat|packetbeat)\b", re.I), 2),
    ("siem", "Wazuh",
     re.compile(r"\b(?:wazuh|ossec-agentd|ossec-?syscheckd)\b", re.I), 2),
    ("siem", "Sysmon",
     re.compile(r"\b(?:sysmon|sysmondrv)\b", re.I), 2),
    ("siem", "NXLog",
     re.compile(r"\bnxlog\b", re.I), 2),
    ("siem", "Datadog Agent",
     re.compile(r"\b(?:datadog-?agent|dd-?agent)\b", re.I), 1),
    ("siem", "Rapid7 InsightAgent",
     re.compile(r"\b(?:rapid7|insightagent|ir_agent)\b", re.I), 2),

    # ── IDS / IPS ────────────────────────────────────────────────────
    ("ids", "Snort",
     re.compile(r"\bsnort\b", re.I), 2),
    ("ids", "Suricata",
     re.compile(r"\bsuricata\b", re.I), 2),
    ("ids", "Palo Alto",
     re.compile(r"\b(?:palo\s*alto|pan-?os)\b", re.I), 1),
    ("ids", "Cisco Firepower",
     re.compile(r"\b(?:firepower|cisco\s*ftd|cisco\s*ips)\b", re.I), 1),
    ("ids", "Zeek/Bro",
     re.compile(r"\b(?:zeek|bro\s*ids)\b", re.I), 2),

    # ── Honey / deception ────────────────────────────────────────────
    ("honey", "Cowrie / Kippo honeypot",
     re.compile(r"\b(?:cowrie|kippo)\b", re.I), 2),
    ("honey", "Canarytokens",
     re.compile(r"\bcanary(?:token)?s?\b", re.I), 1),
    ("honey", "T-Pot / Conpot",
     re.compile(r"\b(?:t-?pot|conpot|dionaea|glastopf)\b", re.I), 2),
]


# Header-only fingerprints — searched against intel["http_headers"] when present
_HTTP_HEADER_HINTS: List[Tuple[str, str, "re.Pattern[str]"]] = [
    ("waf", "Cloudflare",            re.compile(r"^cf-ray:|^server:\s*cloudflare", re.I | re.M)),
    ("waf", "Akamai",                re.compile(r"^x-akamai|^server:\s*akamaighost", re.I | re.M)),
    ("waf", "AWS CloudFront",        re.compile(r"^x-amz-cf-|^via:.*cloudfront", re.I | re.M)),
    ("waf", "Imperva Incapsula",     re.compile(r"^x-iinfo|^x-cdn:\s*incapsula", re.I | re.M)),
    ("waf", "F5 BIG-IP",             re.compile(r"^x-waf-event-info|^bigipserver", re.I | re.M)),
    ("waf", "Sucuri",                re.compile(r"^x-sucuri-id", re.I | re.M)),
]


# When evidence-weight ≥ this for SIEM or EDR, recommend stealth budget
_STEALTH_WEIGHT_THRESHOLD = 2


# ── Data class ───────────────────────────────────────────────────────────

@dataclass
class DefensivePosture:
    products:    Dict[str, List[str]] = field(default_factory=dict)  # category → [product, …]
    evidence:    List[Dict[str, Any]] = field(default_factory=list)  # per-match audit
    weight:      int = 0
    iteration:   int = 0
    stealth_recommended: bool = False
    summary:     str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "products":            dict(self.products),
            "evidence":            list(self.evidence[:30]),
            "weight":              self.weight,
            "iteration":           self.iteration,
            "stealth_recommended": self.stealth_recommended,
            "summary":             self.summary,
        }

    def signature(self) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
        """Stable identity for change-detection — only product set matters."""
        return tuple(sorted(
            (cat, tuple(sorted(set(prods)))) for cat, prods in self.products.items()
        ))


# ── Public API ───────────────────────────────────────────────────────────

def _iter_searchable_blobs(intel: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """Yield (source, text) tuples drawn from the intel dict's looser fields."""
    if not isinstance(intel, dict):
        return

    raw = intel.get("raw_outputs") or {}
    if isinstance(raw, dict):
        for tool, output in raw.items():
            if output:
                yield (f"raw:{tool}", str(output))

    for key in ("banners", "service_versions"):
        section = intel.get(key) or {}
        if isinstance(section, dict):
            for k, v in section.items():
                if v:
                    yield (f"{key}:{k}", str(v))

    for key in ("technologies", "users", "shares", "interesting_files",
                "enum_findings", "login_pages", "web_paths"):
        items = intel.get(key) or []
        if isinstance(items, list):
            for it in items[:60]:
                yield (f"{key}", str(it))

    headers = intel.get("http_headers")
    if isinstance(headers, dict):
        for host, hdrs in headers.items():
            if hdrs:
                yield (f"http_headers:{host}", str(hdrs))
    elif isinstance(headers, str) and headers:
        yield ("http_headers", headers)

    for key in ("attack_surface_notes", "os_guess"):
        v = intel.get(key)
        if v:
            yield (key, str(v))


def fingerprint_posture(
    intel: Dict[str, Any],
    *, iteration: int = 0,
    prior_mode: str = "default",
) -> DefensivePosture:
    """Walk the intel dict and produce a ``DefensivePosture`` record."""
    posture = DefensivePosture(iteration=iteration)
    if not isinstance(intel, dict):
        return posture

    seen_evidence: set = set()  # (category, product, source) dedup

    for source, blob in _iter_searchable_blobs(intel):
        if not blob:
            continue
        for category, product, pattern, weight in DEFENDER_PATTERNS:
            m = pattern.search(blob)
            if not m:
                continue
            key = (category, product, source)
            if key in seen_evidence:
                continue
            seen_evidence.add(key)
            posture.products.setdefault(category, [])
            if product not in posture.products[category]:
                posture.products[category].append(product)
            posture.weight += weight
            posture.evidence.append({
                "category": category,
                "product":  product,
                "source":   source,
                "match":    m.group(0)[:120],
                "weight":   weight,
            })

    # HTTP-header pass (more structured)
    headers = intel.get("http_headers")
    if isinstance(headers, dict):
        for host, hdrs in headers.items():
            blob = str(hdrs or "")
            if not blob:
                continue
            for category, product, pattern in _HTTP_HEADER_HINTS:
                m = pattern.search(blob)
                if not m:
                    continue
                key = (category, product, f"http_headers:{host}")
                if key in seen_evidence:
                    continue
                seen_evidence.add(key)
                posture.products.setdefault(category, [])
                if product not in posture.products[category]:
                    posture.products[category].append(product)
                posture.weight += 2
                posture.evidence.append({
                    "category": category,
                    "product":  product,
                    "source":   f"http_headers:{host}",
                    "match":    m.group(0)[:120],
                    "weight":   2,
                })

    # Stealth recommendation logic
    edr_weight  = sum(e["weight"] for e in posture.evidence if e["category"] == "edr")
    siem_weight = sum(e["weight"] for e in posture.evidence if e["category"] == "siem")
    ids_weight  = sum(e["weight"] for e in posture.evidence if e["category"] == "ids")
    posture.stealth_recommended = (
        max(edr_weight, siem_weight, ids_weight) >= _STEALTH_WEIGHT_THRESHOLD
        and prior_mode != "stealth"
    )

    # One-line human summary
    if posture.products:
        bits = []
        for cat in ("edr", "siem", "ids", "waf", "av", "honey"):
            prods = posture.products.get(cat) or []
            if prods:
                bits.append(f"{cat.upper()}: {', '.join(prods[:2])}")
        posture.summary = " | ".join(bits)
    else:
        posture.summary = "no defenders fingerprinted"

    return posture


def stealth_recommended(posture: DefensivePosture) -> bool:
    """Convenience predicate."""
    return bool(posture and posture.stealth_recommended)


def render_posture_for_prompt(posture: Optional[DefensivePosture]) -> str:
    """Compact LLM-prompt block.  Returns '' if no defenders detected."""
    if posture is None or not posture.products:
        return ""
    lines = ["--- Defensive posture (fingerprinted from recon) ---"]
    cat_label = {
        "edr":   "EDR",
        "av":    "AV",
        "waf":   "WAF",
        "siem":  "SIEM/log-agent",
        "ids":   "IDS/IPS",
        "honey": "Honeypot",
    }
    for cat in ("edr", "siem", "ids", "waf", "av", "honey"):
        prods = posture.products.get(cat) or []
        if not prods:
            continue
        lines.append(f"  {cat_label.get(cat, cat):14s}: {', '.join(prods[:3])}")
    if posture.evidence:
        ev = posture.evidence[0]
        lines.append(
            f"  Top evidence  : [{ev['source']}] '{ev['match']}'"
        )
    if posture.stealth_recommended:
        lines.append(
            "  → STEALTH RECOMMENDED: avoid loud scanners, brute force, and "
            "noisy nmap profiles; prefer surgical, low-volume probes."
        )
    else:
        lines.append(
            "  → Adjust tradecraft to evade these specific products "
            "(e.g. encoded payloads vs. WAF, LOLBins vs. EDR)."
        )
    lines.append("---")
    return "\n".join(lines)
