"""knowledge/identifier_scrub.py — keep TTPs, drop client identity.

WHY THIS EXISTS
===============
ARGUS is allowed to get faster by remembering TOOLS, TECHNIQUES and PROCEDURES:
which tool and flags worked against a service, which technique suited a product
version, what failed and why.  It is NOT allowed to remember WHO it was pointed
at.  Client IPs, CIDRs, hostnames, URLs, organisation names and other system
identifiers are engagement-confidential; they are also worthless as TTPs, because
the reusable part of "sqlmap --batch beat that login form" is never the address.

That line was not enforced.  Episodic memory keyed each record on the target
address and rendered it straight into the next engagement's prompt:

    OTHER ENGAGEMENT: unknown -> 192.168.50.44 (svcs=cisco-sccp?)

so during a bank's external assessment the model was shown a DIFFERENT client's
lab range.  It reasoned from it — concluding the bank was out of scope and the
other client's subnet was the authorized one — and next_commands for the bank's
hosts came out containing `nmap ... 192.168.50.43` and `fping -g 192.168.50.0/24`.
One client's engagement generated commands aimed at another client's network.

DESIGN
======
* PURE.  Text in, text out; no I/O, no state.  Trivially testable, and safe to
  call from any writer on any path.
* FAIL TOWARDS SILENCE.  When a token is ambiguous, remove it.  Over-scrubbing
  costs a little recall quality; under-scrubbing is a confidentiality breach.
  A redacted TTP is still a usable TTP.
* TECHNOLOGY IS NOT IDENTITY.  Product names, versions, CVE ids, ports, protocol
  and tool names are what makes a memory useful, so they are deliberately kept:
  "apache 2.4.49", "CVE-2021-41773", "port 8080", "sqlmap --batch" all survive.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

#: What a removed identifier is replaced with.  Visible on purpose — a reader
#: should be able to tell that something was withheld rather than absent.
REDACTED = "[redacted]"

# ── Identifier patterns ──────────────────────────────────────────────────────
# IPv4 with optional CIDR.  Four dotted octets, each 0-255, so a three-part
# version like "2.4.49" is untouched.  A four-part version ("1.2.3.4") is
# indistinguishable from an address and is redacted — the safe direction.
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?\b"
)
# IPv6, loose but anchored on the ':: ' / multi-group shape.
_IPV6 = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?\b", re.I)
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.I)
#: A CVE id embedded anywhere (including inside a reference URL).  Extracted and
#: kept when the surrounding URL is removed — the id is the TTP.
_CVE_IN = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_MAC = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
# Long hex blobs: session ids, mongo _ids, tokens, hashes.
_HEXID = re.compile(r"\b[0-9a-f]{24,}\b", re.I)

# A dotted name whose last label looks like a TLD.  Deliberately broad: any
# hostname in a memory is a client system identifier.
_FQDN = re.compile(
    r"\b(?=[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+\b)"
    r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b", re.I
)
# Names that are TECHNOLOGY, not client identity — never redact these even though
# they match the FQDN shape.  NOTE: this applies to BARE names only.  A full URL is
# always removed whichever host it names, because a URL in a memory is a location
# rather than a technique — "https://nmap.org/submit/" in a service banner is noise,
# and allowing URLs through per-host would need the allowlist to be exhaustive to be
# safe, which it cannot be.
_TECH_ALLOW = frozenset({
    "nmap.org", "openssl.org", "apache.org", "nginx.org", "python.org",
    "microsoft.com", "oracle.com", "mysql.com", "postgresql.org", "php.net",
    "cve.mitre.org", "nvd.nist.gov", "exploit-db.com", "github.com",
    "kernel.org", "debian.org", "ubuntu.com", "redhat.com", "openbsd.org",
    "localhost", "example.com",
})
# File-ish endings that the FQDN pattern would otherwise eat.
_FILE_EXT = frozenset({
    "py", "js", "json", "yaml", "yml", "txt", "log", "conf", "cfg", "sh", "xml",
    "html", "htm", "php", "asp", "aspx", "jsp", "war", "jar", "so", "dll", "exe",
    "md", "csv", "ini", "pem", "crt", "key", "db", "sql", "gz", "zip", "tar",
})


def _fqdn_sub(m: "re.Match") -> str:
    tok = m.group(0)
    low = tok.lower()
    if low in _TECH_ALLOW:
        return tok
    tail = low.rsplit(".", 1)[-1]
    if tail in _FILE_EXT:            # "settings.py", "web.config"
        return tok
    return REDACTED


def scrub_text(text: Any) -> str:
    """Return ``text`` with every client identifier replaced by ``REDACTED``.

    Technology, versions, CVE ids, ports and tool invocations are preserved —
    those are the reusable part of a TTP.
    """
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s
    # A URL that names a VULNERABILITY keeps its identifier and loses the rest:
    # "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" -> "CVE-2021-44228".
    # The CVE is the reusable TTP; the URL around it is not, and blanket URL
    # removal was destroying the CVE along with it.  Done by extraction rather
    # than by host-allowlisting, so it is safe even for a URL on a host that
    # could name the client (github.com/<clientorg>/... keeps nothing).
    s = _URL.sub(lambda m: (_CVE_IN.search(m.group(0)).group(0).upper()
                            if _CVE_IN.search(m.group(0)) else REDACTED), s)
    s = _EMAIL.sub(REDACTED, s)
    s = _MAC.sub(REDACTED, s)
    s = _IPV4.sub(REDACTED, s)
    s = _IPV6.sub(REDACTED, s)
    s = _HEXID.sub(REDACTED, s)
    s = _FQDN.sub(_fqdn_sub, s)
    return s


def contains_identifier(text: Any) -> bool:
    """True when ``text`` still carries something that identifies a client system.

    The assertion used by the boundary tests: nothing crossing into
    cross-engagement storage may satisfy this.
    """
    if text is None:
        return False
    s = str(text)
    if not s:
        return False
    return scrub_text(s) != s


def scrub_list(values: Optional[List[Any]]) -> List[str]:
    """Scrub every entry, dropping ones that were nothing BUT an identifier."""
    out: List[str] = []
    for v in (values or []):
        c = scrub_text(v).strip()
        if c and c != REDACTED:
            out.append(c)
    return out


#: Fields that may never be persisted to cross-engagement storage at all —
#: scrubbing them leaves nothing of value, so they are dropped outright.
IDENTIFYING_FIELDS = frozenset({
    "target", "target_ip", "target_host", "target_url", "target_hostname",
    "host", "hosts", "ip", "ips", "address", "addresses", "url", "urls",
    "domain", "fqdn", "cidr", "scope", "target_scope", "dc_ip", "vhost",
    "vhosts", "credentials", "creds", "username", "password", "org",
    "organisation", "organization", "client",
})


#: Internal keys that are ARGUS's OWN identifiers, not the client's — a random
#: per-scan id, a Mongo _id.  They are opaque, never rendered into any LLM prompt,
#: and required as storage keys (the engagement_episodes `session_id` is a UNIQUE
#: index).  They must survive verbatim: a session_id is a 24-char hex string, so
#: scrubbing its VALUE collapses every record to the same "[redacted]" and the
#: unique index then rejects the second write — which is exactly what broke the
#: purge.  Preserving them is safe precisely because they do not name the client.
PRESERVE_FIELDS = frozenset({"session_id", "_id", "id"})


def scrub_payload(payload: Dict[str, Any], *,
                  drop: Optional[frozenset] = None) -> Dict[str, Any]:
    """Sanitise a record bound for storage that OUTLIVES one engagement.

    Identifying fields are removed entirely; every remaining string (and string
    inside a list) is scrubbed.  Numbers and booleans — ports, counts, outcome
    flags — pass through untouched: a port is a technique detail, not identity.
    ``PRESERVE_FIELDS`` (ARGUS's own opaque keys) pass through verbatim so a hex
    session id / _id is never mistaken for a client identifier.
    """
    drop = IDENTIFYING_FIELDS if drop is None else drop
    out: Dict[str, Any] = {}
    for k, v in (payload or {}).items():
        if k in PRESERVE_FIELDS:
            out[k] = v          # internal key: never dropped, never scrubbed
            continue
        if k in drop:
            continue
        if isinstance(v, str):
            out[k] = scrub_text(v)
        elif isinstance(v, list):
            out[k] = [scrub_text(x) if isinstance(x, str) else x for x in v]
        elif isinstance(v, dict):
            out[k] = scrub_payload(v, drop=drop)
        else:
            out[k] = v
    return out


__all__ = ["REDACTED", "IDENTIFYING_FIELDS", "PRESERVE_FIELDS",
           "scrub_text", "scrub_list",
           "scrub_payload", "contains_identifier"]
