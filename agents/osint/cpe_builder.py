"""
cpe_builder.py — Map discovered service banners to CPE 2.3 strings + relevance scoring.

Why this exists
===============
The OSINT NVD search was using `keywordSearch=OpenSSH` which returned
CVE-1999-0661 (Solaris telnet from 1999), CVE-2000-0525 (OpenSSH 1.x)
and other ancient noise against modern targets.  NVD's preferred
search method is CPE-based: `cpeName=cpe:2.3:a:openbsd:openssh:7.6p1`
returns ONLY the CVEs that apply to that exact version.

This module converts the messy real-world banner strings produced by
nmap/whatweb/etc. into well-formed CPE 2.3 identifiers, plus provides
version-comparison helpers so the OSINT pipeline can filter out
results that don't apply to the discovered version.

Supports the products we actually encounter in pentest engagements:
SSH, web servers, databases, app servers, runtimes, CMS, exotic
services.  Extensible — add a vendor:product entry to PRODUCT_MAP.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────
#  Product → CPE vendor:product mapping
# ─────────────────────────────────────────────────────────────────────
#
# Each entry maps a normalised lower-case product token (as it appears
# in service banners) to the NVD-canonical (vendor, product) pair.
# Where multiple banners can refer to the same product (e.g. "ssh" /
# "openssh" / "ssh-2.0-openssh"), all the aliases are listed.

PRODUCT_MAP: Dict[str, Tuple[str, str]] = {
    # ── SSH ──
    "openssh":             ("openbsd", "openssh"),
    "ssh":                 ("openbsd", "openssh"),
    "openssh_server":      ("openbsd", "openssh"),
    "dropbear":            ("matt_johnston", "dropbear_ssh"),

    # ── Web servers ──
    "apache":              ("apache", "http_server"),
    "apache httpd":        ("apache", "http_server"),
    "apache_httpd":        ("apache", "http_server"),
    "httpd":               ("apache", "http_server"),
    "nginx":               ("f5",     "nginx"),
    "iis":                 ("microsoft", "internet_information_services"),
    "microsoft-iis":       ("microsoft", "internet_information_services"),
    "lighttpd":            ("lighttpd", "lighttpd"),
    "caddy":               ("caddyserver", "caddy"),

    # ── App servers / containers ──
    "tomcat":              ("apache", "tomcat"),
    "apache tomcat":       ("apache", "tomcat"),
    "jetty":               ("eclipse", "jetty"),
    "weblogic":            ("oracle", "weblogic_server"),
    "websphere":           ("ibm", "websphere_application_server"),
    "jboss":               ("redhat", "jboss_enterprise_application_platform"),
    "wildfly":             ("redhat", "wildfly"),
    "express":             ("openjsf", "express"),

    # ── Runtime / framework banners ──
    "werkzeug":            ("palletsprojects", "werkzeug"),
    "flask":               ("palletsprojects", "flask"),
    "django":              ("djangoproject", "django"),
    "rails":               ("rubyonrails", "ruby_on_rails"),
    "node.js":             ("nodejs", "node.js"),
    "node":                ("nodejs", "node.js"),
    "python":              ("python", "python"),
    "php":                 ("php", "php"),
    "perl":                ("perl", "perl"),

    # ── Databases ──
    "mysql":               ("oracle", "mysql"),
    "mariadb":             ("mariadb", "mariadb"),
    "postgresql":          ("postgresql", "postgresql"),
    "mssql":               ("microsoft", "sql_server"),
    "microsoft sql server":("microsoft", "sql_server"),
    "mongodb":             ("mongodb", "mongodb"),
    "redis":               ("redis", "redis"),
    "memcached":           ("memcached", "memcached"),
    "elasticsearch":       ("elastic", "elasticsearch"),
    "couchdb":             ("apache", "couchdb"),
    "cassandra":           ("apache", "cassandra"),
    "oracle":              ("oracle", "database_server"),

    # ── Windows-specific ──
    "windows kerberos":    ("microsoft", "windows_kerberos"),
    "smbv2":               ("microsoft", "windows"),
    "windows":             ("microsoft", "windows"),
    "active directory":    ("microsoft", "active_directory"),
    "windows rpc":         ("microsoft", "windows"),
    "winrm":               ("microsoft", "windows_remote_management"),

    # ── CMS / Apps ──
    "wordpress":           ("wordpress", "wordpress"),
    "drupal":              ("drupal", "drupal"),
    "joomla":              ("joomla", "joomla\\!"),
    "magento":             ("magento", "magento"),
    "phpmyadmin":          ("phpmyadmin", "phpmyadmin"),
    "moodle":              ("moodle", "moodle"),
    "gitlab":              ("gitlab", "gitlab"),
    "jenkins":             ("jenkins", "jenkins"),
    "confluence":          ("atlassian", "confluence_server"),
    "jira":                ("atlassian", "jira_server"),
    "bitbucket":           ("atlassian", "bitbucket_server"),
    "minio":               ("minio", "minio"),
    "elastic stack":       ("elastic", "kibana"),
    "kibana":              ("elastic", "kibana"),
    "grafana":             ("grafana", "grafana"),
    "nextcloud":           ("nextcloud", "nextcloud_server"),
    "owncloud":            ("owncloud", "owncloud_server"),

    # ── Other services seen in pentest contexts ──
    "vsftpd":              ("vsftpd", "vsftpd"),
    "proftpd":             ("proftpd", "proftpd"),
    "pure-ftpd":           ("pureftpd", "pure-ftpd"),
    "filezilla":           ("filezilla-project", "filezilla_server"),
    "samba":               ("samba", "samba"),
    "openldap":            ("openldap", "openldap"),
    "bind":                ("isc", "bind"),
    "exim":                ("exim", "exim"),
    "postfix":             ("postfix", "postfix"),
    "sendmail":            ("sendmail", "sendmail"),
    "openvpn":             ("openvpn", "openvpn"),
    "strongswan":          ("strongswan", "strongswan"),
    "haproxy":             ("haproxy", "haproxy"),
    "varnish":             ("varnish-cache", "varnish_cache"),
    "rabbitmq":            ("vmware", "rabbitmq"),
    "kafka":               ("apache", "kafka"),
    "zookeeper":           ("apache", "zookeeper"),
    "activemq":            ("apache", "activemq"),
    "rsync":               ("rsync", "rsync"),
    "vnc":                 ("realvnc", "vnc"),
    "tightvnc":            ("tightvnc", "tightvnc"),
    "telnet":              ("inetutils", "telnetd"),
    "rdp":                 ("microsoft", "remote_desktop_protocol"),

    # ── Pentest-target HBR (highly banner-recognisable) ──
    "simple dns plus":     ("jhsoft", "simple_dns_plus"),
    "exim4":               ("exim", "exim"),
    "openssl":             ("openssl", "openssl"),
}


# Banner tokens we want to ignore (they're not real products)
_BANNER_NOISE = re.compile(
    r"\b(?:linux|ubuntu|debian|centos|kali|service|server|httpd?|"
    r"protocol|version|service|microsoft|the|and|or|x86_64|"
    r"i386|build|rev|sp\d+|patch|update)\b", re.IGNORECASE,
)

# Version-string extractor:
#   "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3"   → 7.6p1
#   "Apache/2.4.66 (Debian)"            → 2.4.66
#   "nginx/1.18.0"                      → 1.18.0
#   "Werkzeug httpd 0.14.1 Python 3.6.9"→ 0.14.1   (picks first)
#   "Microsoft-IIS/10.0"                → 10.0
_VERSION_RE = re.compile(
    r"(?:[/_ ])"                             # leading sep
    r"(\d+(?:\.\d+){1,4}(?:[pPrRbBaA]\d+)?)"  # 1.2 / 1.2.3 / 1.2.3p1
    r"(?=$|[\s,;)\]/_-])",
)


@dataclass
class CPEMatch:
    """A constructed CPE 2.3 identifier with confidence."""
    vendor:   str
    product:  str
    version:  Optional[str]
    cpe_uri:  str
    raw_banner: str
    confidence: float = 1.0       # 0.0–1.0


def normalise_banner(banner: str) -> str:
    """Lowercase + trim noise tokens so PRODUCT_MAP lookup hits."""
    if not banner:
        return ""
    lowered = banner.lower().strip()
    # Strip noise but keep product names + versions intact
    return lowered


def extract_versions(banner: str) -> List[str]:
    """Return all plausible version strings found in the banner."""
    if not banner:
        return []
    versions: List[str] = []
    for m in _VERSION_RE.finditer(" " + banner + " "):
        v = m.group(1).strip()
        if v and v not in versions:
            versions.append(v)
    return versions


def build_cpe(vendor: str, product: str,
                version: Optional[str] = None) -> str:
    """Return a CPE 2.3 URI for the given vendor:product:version."""
    v = version.replace(" ", "_") if version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def map_banner_to_cpe(banner: str) -> Optional[CPEMatch]:
    """Best-effort: convert a service banner string into a CPEMatch.

    Returns None when no product can be identified (we should NOT
    blindly send keyword=banner to NVD in that case).
    """
    if not banner or len(banner) > 400:
        return None
    lc = banner.lower()
    matched_key: Optional[str] = None
    # Look for the longest matching product alias (so "apache tomcat"
    # matches before "apache" alone).
    keys = sorted(PRODUCT_MAP.keys(), key=len, reverse=True)
    for k in keys:
        if k in lc:
            matched_key = k
            break
    if matched_key is None:
        return None
    vendor, product = PRODUCT_MAP[matched_key]
    versions = extract_versions(banner)
    version = versions[0] if versions else None
    confidence = 0.95 if version else 0.60
    return CPEMatch(
        vendor     = vendor,
        product    = product,
        version    = version,
        cpe_uri    = build_cpe(vendor, product, version),
        raw_banner = banner[:200],
        confidence = confidence,
    )


def map_search_term_to_cpe(term: str) -> Optional[CPEMatch]:
    """Same as map_banner_to_cpe but for the search_terms list used by
    the master agent.  Handles strings like "Apache 2.4.66",
    "OpenSSH 7.6p1", "nginx 1.18.0"."""
    return map_banner_to_cpe(term)


# ─────────────────────────────────────────────────────────────────────
#  Version comparison utilities (used to filter CVE applicability)
# ─────────────────────────────────────────────────────────────────────

_VER_TOKEN = re.compile(r"(\d+)([a-zA-Z]*)")


def version_tuple(v: str) -> Tuple:
    """Tokenise '7.6p1' → (7, 6, 'p', 1).  Sortable / comparable."""
    if not v:
        return ()
    parts = v.replace("_", ".").split(".")
    out: List = []
    for p in parts:
        for m in _VER_TOKEN.finditer(p):
            num, suf = m.groups()
            out.append(int(num))
            if suf:
                out.append(suf.lower())
    return tuple(out)


def version_compare(a: str, b: str) -> int:
    """Return -1 / 0 / 1 for a vs b.  Tolerates malformed input."""
    ta, tb = version_tuple(a), version_tuple(b)
    if not ta or not tb:
        return 0
    # Compare element-wise; coerce types so int↔str doesn't crash
    for x, y in zip(ta, tb):
        try:
            if x == y:
                continue
            if isinstance(x, int) and isinstance(y, int):
                return -1 if x < y else 1
            return -1 if str(x) < str(y) else 1
        except Exception:
            continue
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


def in_version_range(actual: str, vuln_text: str) -> Optional[bool]:
    """Heuristic: does `actual` fall inside the range mentioned in `vuln_text`?

    `vuln_text` is typically an ExploitDB / CVE title like:
      - "OpenSSH 2.3 < 7.7 — Username Enumeration"
      - "Apache 2.4.49 — Path Traversal"
      - "OpenSSH 1.2 - '.scp' File Create/Overwrite"
      - "FreeBSD OpenSSH 3.5p1 — Remote Command Execution"

    Returns:
      True  → applies to actual version
      False → known NOT to apply
      None  → can't tell (fall back to LLM)
    """
    if not actual or not vuln_text:
        return None
    lc = vuln_text.lower()
    # "X < Y" — affects everything below Y
    m = re.search(r"(\d+(?:\.\d+)*[a-z]?\d*)\s*<\s*(\d+(?:\.\d+)*[a-z]?\d*)",
                    lc)
    if m:
        low_str, high_str = m.group(1), m.group(2)
        cmp_low  = version_compare(actual, low_str)
        cmp_high = version_compare(actual, high_str)
        # Actual must be >= low AND < high
        return (cmp_low >= 0) and (cmp_high < 0)
    # "X.Y.Z — vuln description" — usually means exactly this version
    versions = extract_versions(vuln_text)
    if versions:
        # If actual is much newer than the mentioned version, drop
        cmp_v = version_compare(actual, versions[0])
        # If actual is at least one major version newer → not applicable
        try:
            actual_major = int(actual.split(".")[0])
            vuln_major   = int(versions[0].split(".")[0])
            if actual_major > vuln_major + 1:
                return False
        except Exception:
            pass
        if cmp_v == 0:
            return True
    return None


__all__ = [
    "CPEMatch", "PRODUCT_MAP",
    "build_cpe", "extract_versions",
    "map_banner_to_cpe", "map_search_term_to_cpe",
    "version_tuple", "version_compare", "in_version_range",
]
