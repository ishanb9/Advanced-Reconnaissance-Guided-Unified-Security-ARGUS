#!/usr/bin/env python3
"""
build_kb.py — Build / refresh the ARGUS RAG knowledge base.

Drop ANY supported files into ``knowledge/data/`` (PDFs, markdown, YAML
playbooks, HTML, text, JSON — any subfolder structure).  Then run:

    python knowledge/build_kb.py                # incremental — only changed files
    python knowledge/build_kb.py --reset        # wipe and rebuild from scratch
    python knowledge/build_kb.py --stats        # print KB stats and exit
    python knowledge/build_kb.py --search "..." # test a query against the live KB
    python knowledge/build_kb.py /custom/path   # ingest a different folder

What lives where:
    knowledge/data/                       <- your source content (anything)
    knowledge/data/playbooks/*.yml        <- Tier-0 playbooks (NOT embedded —
                                             loaded directly at query time)
    knowledge/db/                         <- built ChromaDB vector store

Supported types: .pdf .md .markdown .html .htm .mhtml .txt .json .yaml .yml

Install once:
    pip install -r requirements.txt
"""

import os
import re
import sys
import json
import time
import email
import hashlib
import logging
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any, Generator, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("build_kb")

# ── Chunk size config (in approximate words) ────────────────────────────────────
CHUNK_SIZES = {
    "script":     600,   # Keep scripts/code blocks intact, can be longer
    "command":    300,   # Commands with surrounding context
    "procedure":  500,   # Step-by-step instructions
    "technique":  400,   # Technique descriptions
    "tip":        250,   # Tips are usually short
    "finding":    450,   # Findings with context
    "tool_usage": 400,   # Tool documentation
    "output":     500,   # Scan output samples
    "report":     400,   # Report sections
    "default":    400,
}
CHUNK_OVERLAP = 80      # Word overlap between consecutive chunks (same type)
MIN_CHUNK_LEN = 60      # Minimum chars for a chunk to be stored

# ── Default paths ───────────────────────────────────────────────────────────────
# All RAG data lives in ``knowledge/data/`` (any subfolder structure the user
# wants).  The built vector store lives in ``knowledge/db/``.
_HERE        = os.path.dirname(__file__)
DEFAULT_DATA = os.path.join(_HERE, "data")
DEFAULT_DB   = os.path.join(_HERE, "db")

# Manifest for incremental ingestion — stored alongside the DB.
MANIFEST_FILE = os.path.join(DEFAULT_DB, "ingest_manifest.json")


def load_manifest() -> Dict[str, Any]:
    """Load the ingestion manifest (file path → {hash, timestamp, chunks})."""
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_manifest(manifest: Dict[str, Any]) -> None:
    """Persist the ingestion manifest atomically.

    Writes to a .tmp sibling first, fsyncs, then os.replace()'s it onto the
    real path.  This makes the call interrupt-safe: a Ctrl+C, OOM kill, or
    power loss mid-write can leave the .tmp file half-written but never
    corrupts the canonical manifest file itself.  Callers can now invoke
    this after every successful file ingest without risking a torn write.
    """
    os.makedirs(os.path.dirname(MANIFEST_FILE), exist_ok=True)
    tmp_path = MANIFEST_FILE + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
            f.flush()
            # fsync may not be supported on all FS (notably some Windows
            # NFS mounts); ignore the error rather than fail the write.
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(tmp_path, MANIFEST_FILE)
    except Exception:
        # Best-effort cleanup so we don't leave .tmp files behind on failure
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def file_hash(path: str) -> str:
    """SHA-256 of file content (first 4 MB is enough for change detection)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            h.update(f.read(4 * 1024 * 1024))
    except Exception:
        pass
    return h.hexdigest()


def needs_ingest(path: str, manifest: Dict[str, Any], force: bool = False) -> bool:
    """Return True if the file should be ingested (new, modified, or forced)."""
    if force:
        return True
    rec = manifest.get(path)
    if not rec:
        return True
    return rec.get("hash") != file_hash(path)


def build_content_hash_index(manifest: Dict[str, Any]) -> Dict[str, str]:
    """Build a {content_hash: first_path} reverse map from the manifest.

    Used by ingest_directory() to detect whole-file duplicates BEFORE
    chunking + embedding — the single biggest win against the MITRE
    ATT&CK versioning problem (9 historical releases all containing
    the same ~80k techniques).
    """
    seen: Dict[str, str] = {}
    for path, rec in (manifest or {}).items():
        h = (rec or {}).get("hash")
        if not h:
            continue
        # First-write-wins: the path already ingested becomes the canonical
        # source for that content hash.  Later identical files get skipped.
        seen.setdefault(h, path)
    return seen


def _is_playbook_yaml(path: str) -> bool:
    """Detect ARGUS-format playbook YAMLs without a full YAML parse.

    A playbook is a YAML file with all three top-level keys:
        id:        <string>
        trigger:   {...}
        steps:     [...]

    Used by ingest_directory() to skip these files — they are consumed
    by the deterministic Tier-0 retriever, not embedded.
    """
    if not path.lower().endswith((".yml", ".yaml")):
        return False
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(4096)
    except Exception:
        return False
    head = "\n" + head
    return "\nid:" in head and "\ntrigger:" in head and "\nsteps:" in head


# ── Metadata extraction patterns ────────────────────────────────────────────────

TOOL_PATTERNS = [
    # Network scanning/recon
    "nmap", "masscan", "rustscan", "unicornscan", "zmap", "hping3",
    "netdiscover", "arp-scan", "nbtscan",
    # Web scanning/fuzzing
    "gobuster", "ffuf", "feroxbuster", "wfuzz", "dirb", "dirbuster",
    "dirsearch", "nikto", "wapiti", "skipfish", "whatweb", "wafw00f",
    "nuclei", "jaeles", "dalfox",
    # Web exploitation
    "sqlmap", "nosqlmap", "xsstrike", "commix", "tplmap",
    "burpsuite", "burp", "zaproxy", "owasp-zap",
    # Password attacks
    "hydra", "medusa", "ncrack", "patator", "crowbar",
    "hashcat", "john", "johntheripper", "haiti", "hashes.org",
    "cewl", "crunch", "cupp",
    # SMB/AD/Windows
    "crackmapexec", "cme", "impacket", "psexec", "wmiexec", "smbexec",
    "smbmap", "smbclient", "rpcclient", "enum4linux", "enum4linux-ng",
    "ldapdomaindump", "ldapsearch", "bloodhound", "sharphound",
    "powerview", "rubeus", "mimikatz", "secretsdump", "lsassy",
    "evil-winrm", "winrm", "kerbrute", "GetNPUsers", "GetUserSPNs",
    "responder", "inveigh", "ntlmrelayx", "relay",
    # Exploitation frameworks
    "metasploit", "msfconsole", "msfvenom", "msfpc", "armitage",
    "searchsploit", "exploit-db",
    # Post-exploitation / privesc
    "linpeas", "winpeas", "pspy", "linenum", "lse", "beroot",
    "gtfobins", "lolbas", "peas",
    # Tunneling / pivoting
    "chisel", "socat", "netcat", "nc", "ncat", "sshuttle",
    "proxychains", "ligolo", "ligolo-ng", "rpivot", "frp",
    "stunnel", "reGeorg", "neo-reGeorg",
    # OSINT
    "theHarvester", "maltego", "recon-ng", "shodan", "censys",
    "amass", "subfinder", "assetfinder", "findomain",
    "dnsrecon", "dnsx", "massdns", "fierce", "dnsmap",
    # Web tools
    "curl", "wget", "httpx", "httprobe", "aquatone",
    "gowitness", "eyewitness",
    # Scripting
    "python", "python3", "ruby", "perl", "bash", "sh", "powershell",
    "pwsh", "php",
    # Misc
    "snmpwalk", "onesixtyone", "snmpcheck",
    "wpscan", "joomscan", "droopescan",
    "docker", "kubectl", "helm",
    "git", "svn",
    "openssl", "sslyze", "testssl",
    "tcpdump", "wireshark", "tshark", "pcap",
    "aircrack-ng", "airmon-ng", "bettercap",
    "volatility", "autopsy", "binwalk", "foremost",
    "gdb", "pwndbg", "peda", "pwntools",
    "radare2", "ghidra", "ida",
    "strace", "ltrace",
    "exiftool", "steghide", "stegsolve", "zsteg",
    "base64", "xxd", "hexdump", "strings",
]

# Remove duplicates while preserving order
_seen_tools: set = set()
TOOL_PATTERNS_DEDUP: List[str] = []
for _t in TOOL_PATTERNS:
    if _t not in _seen_tools:
        _seen_tools.add(_t)
        TOOL_PATTERNS_DEDUP.append(_t)
TOOL_PATTERNS = TOOL_PATTERNS_DEDUP

SERVICE_PATTERNS: Dict[str, str] = {
    r"apache[\s/]+([\d.]+)":           "apache",
    r"nginx[\s/]+([\d.]+)":            "nginx",
    r"iis[\s/]+([\d.]+)":              "iis",
    r"lighttpd[\s/]+([\d.]+)":         "lighttpd",
    r"tomcat[\s/]+([\d.]+)":           "tomcat",
    r"jetty[\s/]+([\d.]+)":            "jetty",
    r"openssh[\s/]+([\d.]+)":          "openssh",
    r"dropbear[\s/]+([\d.]+)":         "dropbear",
    r"vsftpd[\s/]+([\d.]+)":           "vsftpd",
    r"proftpd[\s/]+([\d.]+)":          "proftpd",
    r"pure-ftpd":                       "pure-ftpd",
    r"samba[\s/]+([\d.]+)":            "samba",
    r"mysql[\s/]+([\d.]+)":            "mysql",
    r"mariadb[\s/]+([\d.]+)":          "mariadb",
    r"postgresql[\s/]+([\d.]+)":       "postgresql",
    r"mssql|sql\s*server":             "mssql",
    r"oracle\s*db":                    "oracle",
    r"mongodb[\s/]*([\d.]+)?":         "mongodb",
    r"redis[\s/]*([\d.]+)?":           "redis",
    r"memcached":                      "memcached",
    r"elasticsearch[\s/]*([\d.]+)?":   "elasticsearch",
    r"wordpress[\s/]*([\d.]+)?":       "wordpress",
    r"drupal[\s/]*([\d.]+)?":          "drupal",
    r"joomla[\s/]*([\d.]+)?":          "joomla",
    r"jenkins[\s/]*([\d.]+)?":         "jenkins",
    r"jira[\s/]*([\d.]+)?":            "jira",
    r"confluence[\s/]*([\d.]+)?":      "confluence",
    r"gitlab[\s/]*([\d.]+)?":          "gitlab",
    r"gitea[\s/]*([\d.]+)?":           "gitea",
    r"grafana[\s/]*([\d.]+)?":         "grafana",
    r"kibana[\s/]*([\d.]+)?":          "kibana",
    r"splunk[\s/]*([\d.]+)?":          "splunk",
    r"nagios[\s/]*([\d.]+)?":          "nagios",
    r"zabbix[\s/]*([\d.]+)?":          "zabbix",
    r"docker[\s/]*([\d.]+)?":          "docker",
    r"kubernetes|k8s":                 "kubernetes",
    r"smtp|postfix|sendmail|exim":     "smtp",
    r"snmp":                           "snmp",
    r"\bftp[\s/:]":                    "ftp",
    r"smb|cifs|port[\s:]445":         "smb",
    r"rdp|3389":                       "rdp",
    r"ldap|port[\s:]389|port[\s:]636": "ldap",
    r"kerberos|port[\s:]88":           "kerberos",
    r"winrm|5985|5986":               "winrm",
    r"cassandra|9042":                 "cassandra",
    r"rpcbind|portmapper|111":         "rpc",
    r"nfs|2049":                       "nfs",
    r"pop3|110|995":                   "pop3",
    r"imap|143|993":                   "imap",
    r"dns|53/":                        "dns",
    r"telnet|23/":                     "telnet",
}

OS_PATTERNS: Dict[str, str] = {
    r"ubuntu[\s]*([\d.]+)?":           "linux ubuntu",
    r"debian[\s]*([\d.]+)?":           "linux debian",
    r"centos[\s]*([\d.]+)?":           "linux centos",
    r"rhel|red hat enterprise":        "linux rhel",
    r"fedora[\s]*([\d.]+)?":           "linux fedora",
    r"arch linux|archlinux":           "linux arch",
    r"alpine[\s linux]*([\d.]+)?":     "linux alpine",
    r"kali[\s linux]*":                "linux kali",
    r"parrot[\s os]*":                 "linux parrot",
    r"freebsd[\s]*([\d.]+)?":          "freebsd",
    r"openbsd[\s]*([\d.]+)?":          "openbsd",
    r"windows\s*xp":                   "windows xp",
    r"windows\s*vista":                "windows vista",
    r"windows\s*7":                    "windows 7",
    r"windows\s*8":                    "windows 8",
    r"windows\s*10":                   "windows 10",
    r"windows\s*11":                   "windows 11",
    r"windows\s*server\s*2003":        "windows server 2003",
    r"windows\s*server\s*2008":        "windows server 2008",
    r"windows\s*server\s*2012":        "windows server 2012",
    r"windows\s*server\s*2016":        "windows server 2016",
    r"windows\s*server\s*2019":        "windows server 2019",
    r"windows\s*server\s*2022":        "windows server 2022",
    r"macos|mac os|darwin":            "macos",
    r"android[\s]*([\d.]+)?":          "android",
    r"ios[\s]*([\d.]+)?":              "ios",
}

ATTACK_PATTERNS: Dict[str, str] = {
    r"sql.inject|sqli|\bsqli\b":                        "sqli",
    r"nosql.inject":                                    "nosqli",
    r"local file inclus|lfi\b":                        "lfi",
    r"remote file inclus|rfi\b":                       "rfi",
    r"lfi.*rce|rce.*lfi|log poison|proc/self":          "lfi_rce",
    r"command inject|os.inject|rce\b|remote code exec": "rce",
    r"file upload|upload bypass|webshell":              "file_upload",
    r"xxe|xml external entity":                        "xxe",
    r"ssrf|server.side request forgery":               "ssrf",
    r"ssti|server.side template inject":               "ssti",
    r"eternalblue|ms17.010|smb.*exploit":              "eternalblue",
    r"printspoofer|juicypotato|roguepotato|sweetpotato": "token_impersonation",
    r"pass.the.hash|\bpth\b":                          "pass_the_hash",
    r"pass.the.ticket|\bptt\b":                        "pass_the_ticket",
    r"kerberoast":                                     "kerberoasting",
    r"as.rep.roast|asrep":                             "asreproasting",
    r"golden ticket":                                  "golden_ticket",
    r"silver ticket":                                  "silver_ticket",
    r"dcsync|dc sync":                                 "dcsync",
    r"zerologon|cve-2020-1472":                        "zerologon",
    r"petitpotam":                                     "petitpotam",
    r"ntlm relay|responder.*relay":                    "ntlm_relay",
    r"sudo.*misconfig|sudo -l|sudo.*exploit":          "sudo_privesc",
    r"\bsuid\b|\bsetuid\b":                            "suid_privesc",
    r"cron.*job|writable cron|crontab.*write":         "cron_privesc",
    r"path hijack|path injection":                     "path_hijack",
    r"kernel exploit|dirty cow|dirtycow|dirty pipe":   "kernel_exploit",
    r"buffer overflow|bof\b|stack overflow":           "buffer_overflow",
    r"heap overflow|heap spray":                       "heap_exploit",
    r"format string":                                  "format_string",
    r"use after free|uaf\b":                           "use_after_free",
    r"deseri[a-z]*tion|pickle.*load|yaml.*load":       "deserialization",
    r"jwt.*tamper|jwt.*forge|alg.*none":               "jwt_attack",
    r"\bidor\b|insecure direct object":                "idor",
    r"broken access|access control bypass":            "access_control",
    r"brute.?forc|credential stuff":                   "brute_force",
    r"password spray":                                 "password_spray",
    r"default.cred|default password":                  "default_creds",
    r"open redirect":                                  "open_redirect",
    r"clickjack":                                      "clickjacking",
    r"csrf|cross.site request forgery":                "csrf",
    r"xss|cross.site script":                          "xss",
    r"dom.*xss|reflected xss|stored xss":              "xss",
    r"race condition|toctou":                          "race_condition",
    r"type confusion":                                 "type_confusion",
    r"prototype pollution":                            "prototype_pollution",
    r"log4j|log4shell|cve-2021-44228":                "log4shell",
    r"spring4shell|cve-2022-22965":                    "spring4shell",
    r"shellshock|cve-2014-6271":                       "shellshock",
    r"heartbleed|cve-2014-0160":                       "heartbleed",
    r"container escape|docker escape|cgroup":          "container_escape",
    r"cloud meta|imds|169\.254\.169\.254":             "cloud_metadata",
}

OUTCOME_PATTERNS: List[Tuple[str, str]] = [
    (r"got (?:a |root |user )?shell|shell (?:as|obtained|popped)|reverse shell.*connect|nc.*listen.*connect", "shell obtained"),
    (r"root(?:ed| flag| hash|\.txt)|privilege escal.*success|#\s*(?:whoami|id).*root|uid=0",                  "root"),
    (r"user\.txt|user flag|low.priv shell|www.data|limited shell|foothold|initial access",                    "user flag"),
    (r"no access|failed|not vulnerable|patched|could not|did not work|unsuccessful",                          "failed"),
    (r"lateral movement|moved.*domain|compromised.*host",                                                     "lateral"),
    (r"exfil|data.*stolen|credential.*dump",                                                                  "post_exploit"),
    # Scan-derived documents (auto_ingest) speak a different dialect to writeups:
    # they say "shell_obtained: true" and "**CRITICAL** ... RCE", never "got a
    # shell".  Without these every ingested engagement scored outcome=unknown —
    # so the ONE thing a TTP memory exists to record, whether the technique
    # actually worked, was absent from the whole scan corpus.
    (r"root_obtained:\s*true|root:\s*YES",                                                                    "root"),
    (r"shell_obtained:\s*true|shell obtained:\s*YES",                                                         "shell obtained"),
    (r"\*\*(?:CRITICAL|HIGH)\*\*.*(?:rce|remote code|deserial|injection|traversal|upload|auth bypass)",   "exploited"),
    (r"reached=(?:privesc|foothold)",                                                                     "shell obtained"),
]

DIFFICULTY_PATTERNS: Dict[str, str] = {
    r"\beasy\b":    "easy",
    r"\bmedium\b":  "medium",
    r"\bhard\b":    "hard",
    r"\binsane\b":  "insane",
    r"\bextreme\b": "insane",
}

PORT_RE    = re.compile(r'\b(\d{2,5})/(?:tcp|udp|open)\b|\bport[s]?\s+(\d{2,5})\b', re.I)
CVE_RE     = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
MITRE_RE   = re.compile(r'T\d{4}(?:\.\d{3})?', re.I)
BOX_NAME_RE = re.compile(r'(?:machine|box|target|room|challenge)[:\s]+([A-Za-z0-9_-]{3,20})', re.I)

# PRODUCT + VERSION.  "tomcat" retrieves noise; "tomcat 9.0.30" retrieves the CVE.
# Version is the strongest signal a pentest corpus can carry, and nothing was
# capturing it — services came back as bare product names, so a chunk about a
# patched release ranked identically to one about the vulnerable release.
# Matches "Apache Tomcat/9.0.30", "OpenSSH 8.2p1", "nginx/1.18.0", "PHP 7.4.3".
# The product class deliberately EXCLUDES '.' and '-': allowing them lets the
# product token swallow the version's leading digits.  Word boundaries keep
# "Started: 2026-07-25" and "Findings: 4" from being read as products.
PRODUCT_VERSION_RE = re.compile(
    r'\b([A-Za-z][A-Za-z0-9+]{2,24})[\s/_-]v?(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)\b'
)
#: Words that look like a product but are not one, so "Findings 4.2" is dropped.
_NOT_A_PRODUCT = frozenset({
    "cve", "cvss", "version", "port", "ports", "findings", "finding", "score",
    "severity", "duration", "started", "count", "total", "python", "utf",
    "http", "https", "tcp", "udp", "step", "phase", "line", "col", "id",
})

# Common command-line indicators
CMD_LINE_RE = re.compile(
    r'^\s*(?:'
    r'[$#┌]\s'                                # Shell prompts
    r'|(?:kali|root|user|htb|thm)[@\s].*[$#]\s'  # Kali/root prompts
    r'|(?:nmap|gobuster|ffuf|feroxbuster|wfuzz|sqlmap|hydra|medusa|'
    r'hashcat|john|crackmapexec|impacket|evil-winrm|msfvenom|msfconsole|'
    r'searchsploit|nikto|wpscan|dirsearch|curl|wget|python3?|perl|ruby|'
    r'nc|netcat|chisel|socat|ssh|scp|ftp|telnet|snmpwalk|ldapsearch|'
    r'secretsdump|bloodhound|responder|linpeas|winpeas|pspy|openssl|'
    r'base64|xxd|strings|file|find|cat|ls|id|whoami|uname|ps|netstat|ss)\s'
    r')',
    re.MULTILINE | re.IGNORECASE
)

# Code fence patterns
CODE_FENCE_RE = re.compile(r'```[\w]*\n([\s\S]*?)```', re.MULTILINE)
CODE_FENCE_OPEN = re.compile(r'^```[\w]*\s*$', re.MULTILINE)

# Markdown heading
MD_HEADING_RE = re.compile(r'^(#{1,4})\s+(.+)$', re.MULTILINE)

# Tip/note/warning patterns
TIP_RE = re.compile(r'^\s*(?:note|tip|warning|important|remember|gotcha|hint|trick|caution|info)[:\s]', re.I | re.M)

# Numbered step pattern
NUMBERED_STEP_RE = re.compile(r'^\s*(?:\d+[.)]\s|step\s*\d+[.):])', re.I | re.M)


# ── Chunk type classification ────────────────────────────────────────────────────

def _detect_chunk_type(text: str) -> str:
    """
    Classify a text chunk into a semantic type.
    Returns one of: command, script, procedure, technique, tip, finding, tool_usage, output, report
    """
    stripped = text.strip()
    if not stripped:
        return "technique"

    lines     = stripped.split('\n')
    lower     = stripped.lower()
    line_count = len(lines)

    # Code block (explicit fence)
    if stripped.startswith('```') or stripped.startswith('~~~'):
        return "script"

    # Mostly command lines (40%+ are command lines and at least 2)
    cmd_line_count = sum(1 for l in lines if CMD_LINE_RE.match(l))
    if cmd_line_count >= max(2, line_count * 0.35):
        return "command"

    # Numbered step procedure (3+ numbered lines)
    numbered_count = sum(1 for l in lines if NUMBERED_STEP_RE.match(l))
    if numbered_count >= 3:
        return "procedure"

    # Tip/note/warning
    if TIP_RE.search(stripped):
        return "tip"

    # Tool usage/help (has flag patterns and usage keyword)
    if re.search(r'(-{1,2}[a-zA-Z][\w-]+)', stripped) and re.search(r'\b(usage|synopsis|options|flags)\b', lower):
        return "tool_usage"

    # Vulnerability finding
    if re.search(r'\b(CVE-\d{4}-\d+|CVSS|severity|vulnerable|critical|high risk|vulnerability|exploit.*found)\b', stripped, re.I):
        return "finding"

    # Looks like terminal/tool output (lots of non-alphanumeric, ports, IPs)
    ip_count  = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', stripped))
    port_count = len(re.findall(r'\d{2,5}/(?:tcp|udp)', stripped))
    if ip_count >= 3 or port_count >= 5:
        return "output"

    # Report-style text (executive summary / risk ratings)
    if re.search(r'\b(executive summary|risk rating|remediation|finding|scope|methodology|assessment)\b', lower):
        return "report"

    return "technique"


# ── Text extraction per format ───────────────────────────────────────────────────

def extract_pdf(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Yield (text, section_hint) tuples, one per page or logical section.
    section_hint is an empty string for PDF (can't reliably detect sections).
    """
    try:
        import pypdf
        reader = pypdf.PdfReader(path)
        for page in reader.pages:
            text = page.extract_text() or ""
            if text.strip():
                yield (text, "")
    except Exception as e:
        logger.warning("PDF parse error %s: %s", path, e)


def extract_md(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Yield (section_text, section_title) for each markdown section.
    Splits on ## and ### headings to preserve section context.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()

        # Split on headings
        parts = re.split(r'^(#{1,4}\s+.+)$', raw, flags=re.MULTILINE)
        current_title = ""
        current_text  = ""

        for part in parts:
            if re.match(r'^#{1,4}\s+', part):
                if current_text.strip():
                    yield (current_text.strip(), current_title)
                current_title = re.sub(r'^#+\s+', '', part).strip()
                current_text  = part + "\n"
            else:
                current_text += part

        if current_text.strip():
            yield (current_text.strip(), current_title)

    except Exception as e:
        logger.warning("MD parse error %s: %s", path, e)


def extract_html(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Yield (text, section_title) from HTML.
    Splits on <h2>/<h3> boundaries for better sectioning.
    """
    try:
        from bs4 import BeautifulSoup
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        soup = BeautifulSoup(raw, "lxml")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside", "meta"]):
            tag.decompose()

        # Extract sections between headings
        current_title = ""
        current_parts: List[str] = []
        HEADING_TAGS = {"h1", "h2", "h3", "h4"}

        for element in soup.find_all(True):
            if element.name in HEADING_TAGS:
                if current_parts:
                    text = "\n".join(current_parts).strip()
                    text = re.sub(r'\n{3,}', '\n\n', text)
                    if text:
                        yield (text, current_title)
                current_title = element.get_text(strip=True)
                current_parts = []
            elif element.name in ("p", "pre", "code", "blockquote", "li", "td"):
                t = element.get_text(separator="\n").strip()
                if t:
                    current_parts.append(t)

        if current_parts:
            text = "\n".join(current_parts).strip()
            if text:
                yield (text, current_title)

    except Exception as e:
        logger.warning("HTML parse error %s: %s", path, e)


def extract_mhtml(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Extract text from MHTML (MIME HTML archive) files.
    Used for HackTheBox writeups saved from browsers.
    """
    try:
        from bs4 import BeautifulSoup
        with open(path, "rb") as f:
            raw = f.read()

        # Parse as MIME message
        msg = email.message_from_bytes(raw)
        html_content = None

        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/html", "text/plain"):
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        decoded = payload.decode(charset, errors="ignore")
                    except Exception:
                        decoded = payload.decode("utf-8", errors="ignore")
                    if ct == "text/html" and (html_content is None or len(decoded) > len(html_content)):
                        html_content = decoded

        if html_content:
            # Reuse HTML extractor on the extracted content
            soup = BeautifulSoup(html_content, "lxml")
            for tag in soup(["script", "style", "nav", "footer", "header", "aside", "meta"]):
                tag.decompose()

            current_title = ""
            current_parts: List[str] = []
            HEADING_TAGS = {"h1", "h2", "h3", "h4"}

            for element in soup.find_all(True):
                if element.name in HEADING_TAGS:
                    if current_parts:
                        text = "\n".join(current_parts).strip()
                        text = re.sub(r'\n{3,}', '\n\n', text)
                        if text:
                            yield (text, current_title)
                    current_title = element.get_text(strip=True)
                    current_parts = []
                elif element.name in ("p", "pre", "code", "blockquote", "li", "td"):
                    t = element.get_text(separator="\n").strip()
                    if t:
                        current_parts.append(t)

            if current_parts:
                text = "\n".join(current_parts).strip()
                if text:
                    yield (text, current_title)

    except Exception as e:
        logger.warning("MHTML parse error %s: %s", path, e)


def extract_txt(path: str) -> Generator[Tuple[str, str], None, None]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            yield (f.read(), "")
    except Exception as e:
        logger.warning("TXT parse error %s: %s", path, e)


def extract_json(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Extract knowledge from JSON files (e.g., MITRE ATT&CK JSON, custom tip collections).
    Supports arrays of {text, title, category} or nested technique objects.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        def _process(obj: Any, parent_title: str = "") -> Generator[Tuple[str, str], None, None]:
            if isinstance(obj, str) and len(obj) > MIN_CHUNK_LEN:
                yield (obj, parent_title)
            elif isinstance(obj, dict):
                title = obj.get("title") or obj.get("name") or obj.get("technique") or parent_title
                text  = obj.get("text") or obj.get("description") or obj.get("content") or ""
                if text and len(text) > MIN_CHUNK_LEN:
                    yield (str(text), str(title))
                for k, v in obj.items():
                    if k not in ("title", "name", "text", "description", "content"):
                        yield from _process(v, str(title))
            elif isinstance(obj, list):
                for item in obj:
                    yield from _process(item, parent_title)

        yield from _process(data)

    except Exception as e:
        logger.warning("JSON parse error %s: %s", path, e)


def extract_yaml(path: str) -> Generator[Tuple[str, str], None, None]:
    """
    Extract knowledge from YAML files (e.g., custom tip collections, tool configs).
    """
    try:
        import yaml
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)

        # Reuse JSON extraction logic
        yield from extract_json.__wrapped__ if hasattr(extract_json, '__wrapped__') else _yaml_fallback(data)

    except ImportError:
        logger.warning("PyYAML not installed — skipping YAML file")
    except Exception as e:
        logger.warning("YAML parse error %s: %s", path, e)


def _yaml_fallback(data: Any, title: str = "") -> Generator[Tuple[str, str], None, None]:
    """Recursively yield text from YAML data."""
    if isinstance(data, str) and len(data) > MIN_CHUNK_LEN:
        yield (data, title)
    elif isinstance(data, dict):
        new_title = data.get("title") or data.get("name") or title
        for k, v in data.items():
            yield from _yaml_fallback(v, str(new_title or k))
    elif isinstance(data, list):
        for item in data:
            yield from _yaml_fallback(item, title)


EXTRACTORS: Dict[str, Any] = {
    ".pdf":      extract_pdf,
    ".md":       extract_md,
    ".markdown": extract_md,
    ".html":     extract_html,
    ".htm":      extract_html,
    ".mhtml":    extract_mhtml,
    ".mht":      extract_mhtml,
    ".txt":      extract_txt,
    ".json":     extract_json,
    ".yaml":     lambda p: _yaml_fallback.__call__ if False else list(extract_yaml(p)) and iter([]),  # placeholder
    ".yml":      extract_yaml if "yaml" in sys.modules else extract_txt,
}

# Fix YAML extractor properly
try:
    import yaml as _yaml_module
    EXTRACTORS[".yaml"] = extract_yaml
    EXTRACTORS[".yml"]  = extract_yaml
except ImportError:
    pass


# ── Smart chunking ───────────────────────────────────────────────────────────────

def _extract_code_blocks(text: str) -> Tuple[str, List[Tuple[int, str]]]:
    """
    Remove code blocks from text and return them separately.
    Returns (text_with_placeholders, [(placeholder_idx, code_content), ...])
    """
    blocks = []
    idx    = [0]

    def replace_block(m):
        content = m.group(0)  # full block including fences
        placeholder = f"\x00CODE_BLOCK_{idx[0]}\x00"
        blocks.append((idx[0], content))
        idx[0] += 1
        return placeholder

    cleaned = CODE_FENCE_RE.sub(replace_block, text)

    # Also catch inline code that spans multiple lines (indented code blocks)
    def replace_indented(m):
        content = m.group(0)
        if len(content) > 80 and '\n' in content:
            placeholder = f"\x00CODE_BLOCK_{idx[0]}\x00"
            blocks.append((idx[0], content))
            idx[0] += 1
            return placeholder
        return content

    indented_re = re.compile(r'(?:^    .+\n){3,}', re.MULTILINE)
    cleaned = indented_re.sub(replace_indented, cleaned)

    return cleaned, blocks


def _word_chunks(text: str, chunk_size: int, overlap: int) -> List[str]:
    """Simple word-based sliding window chunking, split at paragraph boundaries."""
    # Try to split at paragraph boundaries first
    paragraphs = re.split(r'\n\s*\n', text.strip())
    if not paragraphs:
        return []

    chunks  = []
    current_words: List[str] = []

    for para in paragraphs:
        para_words = para.split()
        if not para_words:
            continue

        # If adding this paragraph exceeds chunk_size, emit current and start new
        if current_words and len(current_words) + len(para_words) > chunk_size:
            chunk = " ".join(current_words)
            if len(chunk.strip()) >= MIN_CHUNK_LEN:
                chunks.append(chunk)
            # Start new chunk with overlap from end of previous
            current_words = current_words[-overlap:] + para_words
        else:
            current_words.extend(para_words)

        # If current has grown beyond chunk_size, force-emit
        while len(current_words) > chunk_size:
            chunk = " ".join(current_words[:chunk_size])
            if len(chunk.strip()) >= MIN_CHUNK_LEN:
                chunks.append(chunk)
            current_words = current_words[chunk_size - overlap:]

    if current_words:
        chunk = " ".join(current_words)
        if len(chunk.strip()) >= MIN_CHUNK_LEN:
            chunks.append(chunk)

    return chunks


def smart_chunk(text: str, section_title: str = "") -> List[Dict[str, Any]]:
    """
    Structure-aware chunking that returns a list of:
      {"text": str, "chunk_type": str, "section_title": str}

    Strategy:
    1. Extract code blocks → script chunks (kept intact)
    2. Extract consecutive command-line sequences → command chunks
    3. Extract numbered step procedures → procedure chunks
    4. Remaining text → technique/tip/finding chunks (sliding window)
    """
    if not text or len(text.strip()) < MIN_CHUNK_LEN:
        return []

    result: List[Dict[str, Any]] = []

    # Step 1: Extract code blocks
    text_no_code, code_blocks = _extract_code_blocks(text)

    # Add code block chunks
    for _, code in code_blocks:
        if len(code.strip()) >= MIN_CHUNK_LEN:
            # For large scripts, still chunk them
            words = code.split()
            if len(words) <= CHUNK_SIZES["script"]:
                result.append({
                    "text":          code.strip(),
                    "chunk_type":    "script",
                    "section_title": section_title,
                })
            else:
                for sub in _word_chunks(code, CHUNK_SIZES["script"], CHUNK_OVERLAP):
                    if len(sub.strip()) >= MIN_CHUNK_LEN:
                        result.append({
                            "text":          sub,
                            "chunk_type":    "script",
                            "section_title": section_title,
                        })

    # Step 2: Work with text_no_code
    lines = text_no_code.split('\n')
    remaining_lines: List[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Skip code block placeholders
        if '\x00CODE_BLOCK_' in line:
            i += 1
            continue

        # Detect consecutive command lines
        cmd_group: List[str] = []
        j = i
        while j < len(lines) and CMD_LINE_RE.match(lines[j]):
            cmd_group.append(lines[j])
            j += 1

        if len(cmd_group) >= 2:
            # Include 1-2 lines of context before if available
            context_before = remaining_lines[-2:] if remaining_lines else []
            cmd_text = "\n".join(context_before + cmd_group).strip()

            # Sub-chunk if very long
            words = cmd_text.split()
            if len(words) <= CHUNK_SIZES["command"]:
                if len(cmd_text) >= MIN_CHUNK_LEN:
                    result.append({
                        "text":          cmd_text,
                        "chunk_type":    "command",
                        "section_title": section_title,
                    })
            else:
                for sub in _word_chunks(cmd_text, CHUNK_SIZES["command"], CHUNK_OVERLAP):
                    if len(sub.strip()) >= MIN_CHUNK_LEN:
                        result.append({
                            "text":          sub,
                            "chunk_type":    "command",
                            "section_title": section_title,
                        })
            i = j
            continue

        # Detect numbered procedure blocks (3+ consecutive numbered steps)
        proc_group: List[str] = []
        j = i
        while j < len(lines) and NUMBERED_STEP_RE.match(lines[j]):
            proc_group.append(lines[j])
            j += 1

        if len(proc_group) >= 3:
            proc_text = "\n".join(proc_group).strip()
            words     = proc_text.split()
            if len(words) <= CHUNK_SIZES["procedure"]:
                if len(proc_text) >= MIN_CHUNK_LEN:
                    result.append({
                        "text":          proc_text,
                        "chunk_type":    "procedure",
                        "section_title": section_title,
                    })
            else:
                for sub in _word_chunks(proc_text, CHUNK_SIZES["procedure"], CHUNK_OVERLAP):
                    if len(sub.strip()) >= MIN_CHUNK_LEN:
                        result.append({
                            "text":          sub,
                            "chunk_type":    "procedure",
                            "section_title": section_title,
                        })
            i = j
            continue

        remaining_lines.append(line)
        i += 1

    # Step 3: Chunk remaining prose text
    remaining_text = "\n".join(remaining_lines).strip()
    if remaining_text and len(remaining_text) >= MIN_CHUNK_LEN:
        prose_chunks = _word_chunks(remaining_text, CHUNK_SIZES["default"], CHUNK_OVERLAP)
        for chunk_text in prose_chunks:
            if len(chunk_text.strip()) >= MIN_CHUNK_LEN:
                ctype = _detect_chunk_type(chunk_text)
                result.append({
                    "text":          chunk_text.strip(),
                    "chunk_type":    ctype,
                    "section_title": section_title,
                })

    return result


# ── Metadata extraction ──────────────────────────────────────────────────────────

def extract_metadata(text: str) -> Dict[str, Any]:
    """Lightweight pattern-based metadata extraction — no LLM needed."""
    lower = text.lower()
    head  = lower[:3000]

    tools = [t for t in TOOL_PATTERNS if re.search(r'\b' + re.escape(t) + r'\b', lower)]

    services = []
    for pat, name in SERVICE_PATTERNS.items():
        if re.search(pat, lower):
            services.append(name)
    services = list(set(services))

    os_guess = "unknown"
    for pat, name in OS_PATTERNS.items():
        if re.search(pat, lower):
            os_guess = name
            break

    attack_types = []
    for pat, name in ATTACK_PATTERNS.items():
        if re.search(pat, lower):
            attack_types.append(name)
    attack_types = list(set(attack_types))

    outcome = "unknown"
    for pat, name in OUTCOME_PATTERNS:
        if re.search(pat, lower):
            outcome = name
            break

    difficulty = "unknown"
    for pat, name in DIFFICULTY_PATTERNS.items():
        if re.search(pat, head):
            difficulty = name
            break

    ports = list(set(
        int(m.group(1) or m.group(2))
        for m in PORT_RE.finditer(text)
        if (m.group(1) or m.group(2)) and int(m.group(1) or m.group(2)) < 65536
    ))[:20]

    cves       = list(set(m.upper() for m in CVE_RE.findall(text)))[:10]
    mitre_ttps = list(set(m.upper() for m in MITRE_RE.findall(text)))[:10]

    box_match = BOX_NAME_RE.search(head)
    box_name  = box_match.group(1).lower() if box_match else ""

    # product@version pairs, deduped, most specific first.
    # IPv4 is masked FIRST: "-p8080 192.168.50.44" otherwise yields the bogus
    # product "p8080" with "version" 192.168.50 — an address read as a version,
    # which would pollute the corpus with junk products and skew retrieval.
    _vtext = IP_RE.sub(" ", text) if "IP_RE" in globals() else re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    versions = []
    for m in PRODUCT_VERSION_RE.finditer(_vtext):
        prod, ver = m.group(1).lower().strip("._-"), m.group(2)
        if len(prod) < 3 or prod in _NOT_A_PRODUCT or prod.isdigit():
            continue
        # A single letter followed by digits is a CLI flag ("p8080", "x64"), a
        # product name is not.
        if re.fullmatch(r"[a-z]\d+", prod):
            continue
        pair = f"{prod} {ver}"
        if pair not in versions:
            versions.append(pair)
    versions = versions[:15]

    # Determine phase
    phase = "mixed"
    if any(a in attack_types for a in ["sqli", "lfi", "rfi", "rce", "file_upload", "xxe", "ssrf", "ssti", "xss"]):
        phase = "exploit"
    elif any(a in attack_types for a in ["sudo_privesc", "suid_privesc", "cron_privesc", "kernel_exploit", "path_hijack", "token_impersonation"]):
        phase = "privesc"
    elif any(a in attack_types for a in ["eternalblue", "pass_the_hash", "kerberoasting", "zerologon"]):
        phase = "exploit"
    elif any(a in attack_types for a in ["dcsync", "golden_ticket", "ntlm_relay"]):
        phase = "lateral"
    elif any(a in attack_types for a in ["post_exploit", "container_escape", "cloud_metadata"]):
        phase = "post"
    elif services or ports:
        phase = "recon"

    return {
        "tools":        tools,
        "services":     services,
        "os":           os_guess,
        "attack_types": attack_types,
        "outcome":      outcome,
        "difficulty":   difficulty,
        "ports":        ports,
        "cves":         cves,
        "mitre_ttps":   mitre_ttps,
        # box_name is retained for BACKWARD COMPATIBILITY with already-indexed
        # chunks only.  It was scraped from the ingest "target:" line, which no
        # longer exists (it named the client), so it is empty for every new
        # document and must not be reintroduced as a retrieval signal.
        "box_name":     box_name,
        "versions":     versions,
        "phase":        phase,
    }


# ── Main ingest pipeline ─────────────────────────────────────────────────────────

def ingest_file(path: str, kb) -> Dict[str, int]:
    """
    Ingest a single file into the knowledge base.
    Returns {"added": N, "skipped": N, "errors": N}
    """
    ext       = Path(path).suffix.lower()
    extractor = EXTRACTORS.get(ext)
    if not extractor:
        return {"skipped": 1}

    added = skipped = 0
    blocks: List[Tuple[str, str]] = []

    try:
        blocks = list(extractor(path))
    except Exception as e:
        logger.error("Extraction failed for %s: %s", path, e)
        return {"errors": 1}

    if not blocks:
        return {"skipped": 1}

    # Doc-level metadata from first 5 blocks
    doc_head = " ".join(b[0][:800] for b in blocks[:5])
    doc_meta = extract_metadata(doc_head)

    chunk_idx = 0
    for block_text, section_title in blocks:
        # Get chunks from this block
        chunks = smart_chunk(block_text, section_title=section_title)

        for chunk_info in chunks:
            chunk_text    = chunk_info["text"]
            chunk_type    = chunk_info["chunk_type"]
            sec_title     = chunk_info.get("section_title", section_title)

            # Per-chunk metadata refinement
            chunk_meta  = extract_metadata(chunk_text)
            merged_meta = dict(doc_meta)

            # Prefer chunk-level specifics over doc-level
            if chunk_meta["outcome"] != "unknown":
                merged_meta["outcome"]      = chunk_meta["outcome"]
            if chunk_meta["attack_types"]:
                merged_meta["attack_types"] = list(set(
                    doc_meta.get("attack_types", []) + chunk_meta["attack_types"]
                ))
            if chunk_meta["cves"]:
                merged_meta["cves"]         = list(set(
                    doc_meta.get("cves", []) + chunk_meta["cves"]
                ))
            if chunk_meta["mitre_ttps"]:
                merged_meta["mitre_ttps"]   = list(set(
                    doc_meta.get("mitre_ttps", []) + chunk_meta["mitre_ttps"]
                ))
            if chunk_meta["tools"]:
                merged_meta["tools"]        = list(set(
                    doc_meta.get("tools", []) + chunk_meta["tools"]
                ))
            if chunk_meta["services"] and not doc_meta.get("services"):
                merged_meta["services"]     = chunk_meta["services"]

            # Add chunk-type specific metadata
            merged_meta["chunk_type"]    = chunk_type
            merged_meta["section_title"] = sec_title[:100] if sec_title else ""

            # Flatten lists → JSON strings for ChromaDB
            flat_meta: Dict[str, Any] = {}
            for k, v in merged_meta.items():
                if isinstance(v, list):
                    flat_meta[k] = json.dumps(v)
                else:
                    flat_meta[k] = str(v)

            ok = kb.ingest(
                text        = chunk_text,
                source_file = path,
                chunk_index = chunk_idx,
                metadata    = flat_meta,
            )
            if ok:
                added += 1
            else:
                skipped += 1
            chunk_idx += 1

    return {"added": added, "skipped": skipped}


def ingest_directory(
    directory: str,
    kb,
    manifest: Optional[Dict[str, Any]] = None,
    force: bool = False,
) -> Tuple[Dict[str, int], Dict[str, Any]]:
    """
    Ingest all supported files in a directory (recursively).
    Uses manifest for incremental ingestion (skip unchanged files).
    Returns (totals_dict, updated_manifest).
    """
    from tqdm import tqdm

    if manifest is None:
        manifest = {}

    paths = []
    playbook_skipped = 0
    for root, _, files in os.walk(directory):
        for fname in files:
            if Path(fname).suffix.lower() not in EXTRACTORS:
                continue
            full = os.path.join(root, fname)
            # Playbook YAMLs are loaded deterministically by the Tier-0
            # retriever (knowledge/retriever/playbook_lookup.py) — do NOT
            # embed them, that would dilute results with their own keywords.
            if _is_playbook_yaml(full):
                playbook_skipped += 1
                continue
            paths.append(full)

    if playbook_skipped:
        logger.info("Skipped %s playbook YAML(s) — loaded directly by Tier-0 retriever, not embedded", playbook_skipped)

    # Filter to only files that need ingesting
    to_ingest = [p for p in paths if needs_ingest(p, manifest, force=force)]
    skip_count = len(paths) - len(to_ingest)

    # ── FILE-CONTENT-HASH DEDUP (the MITRE-versioning fix) ─────────────────
    # Two files with identical bytes (e.g. enterprise-attack-19.0.json and
    # enterprise-attack-15.1.json mostly differ only in metadata blocks but
    # not in the technique payloads we extract) should NOT both be embedded.
    # Build a reverse map from manifest, then check each candidate file's
    # content hash against it.  If a duplicate hash is found, skip the
    # whole file BEFORE chunking / embedding — saves hours of CPU on big
    # corpora.
    content_index    = build_content_hash_index(manifest)
    dup_file_skips:  int = 0
    deduped_to_ingest: List[str] = []
    for p in to_ingest:
        h = file_hash(p)
        canon = content_index.get(h)
        if canon and canon != p:
            logger.info("[dedup-file] %s == %s (identical content); skipping", p, canon)
            dup_file_skips += 1
            # Mark in manifest so future runs skip cleanly
            manifest[p] = {
                "hash":          h,
                "timestamp":     time.time(),
                "chunks":        0,
                "ext":           Path(p).suffix.lower(),
                "dedup_of":      canon,
            }
            continue
        deduped_to_ingest.append(p)
        # Reserve the hash so duplicates *within this batch* also dedup
        content_index.setdefault(h, p)

    if dup_file_skips:
        logger.info(
            "[dedup-file] Skipped %s file(s) whose content matched an "
            "already-ingested file (saves embedding cost)",
            dup_file_skips,
        )

    logger.info(
        "Found %s files | %s to ingest | %s unchanged | %s content-dup",
        len(paths), len(deduped_to_ingest), skip_count, dup_file_skips,
    )

    totals = {
        "added":          0,
        "skipped":        0,
        "errors":         0,
        "files":          0,
        "files_skipped":  skip_count,
        "files_deduped":  dup_file_skips,
    }

    # Persist the file-content-dedup decisions immediately so a kill BEFORE
    # any real ingest still leaves a useful manifest behind.
    if dup_file_skips:
        try:
            save_manifest(manifest)
        except Exception as exc:
            logger.warning("[manifest] early-save failed: %s", exc)

    # Throttle incremental saves: write at most every _MANIFEST_SAVE_EVERY
    # files OR every _MANIFEST_SAVE_SECS seconds, whichever comes first.
    # On a 1M-chunk / 1000-file corpus with 5 MB manifest, naïve per-file
    # writes would generate ~5 GB of redundant I/O.  Throttling drops that
    # to ~50 MB while still guaranteeing a kill loses at most a few files'
    # worth of tracking (not 9 hours of it like before).
    _MANIFEST_SAVE_EVERY = int(os.environ.get("KB_MANIFEST_SAVE_EVERY", "10"))
    _MANIFEST_SAVE_SECS  = float(os.environ.get("KB_MANIFEST_SAVE_SECS",  "30"))
    _last_save_files = 0
    _last_save_at    = time.time()

    for idx, path in enumerate(tqdm(deduped_to_ingest, desc="Ingesting", unit="file"), 1):
        try:
            result = ingest_file(path, kb)
            totals["files"] += 1
            for k in ("added", "skipped", "errors"):
                totals[k] = totals.get(k, 0) + result.get(k, 0)

            # Update manifest
            manifest[path] = {
                "hash":      file_hash(path),
                "timestamp": time.time(),
                "chunks":    result.get("added", 0),
                "ext":       Path(path).suffix.lower(),
            }

            # ── INCREMENTAL MANIFEST CHECKPOINT ──────────────────────────
            # Save after every N files OR every S seconds (whichever
            # fires first) so a kill mid-run never wastes more than a
            # short window of work.
            _files_since = idx - _last_save_files
            _secs_since  = time.time() - _last_save_at
            if _files_since >= _MANIFEST_SAVE_EVERY or _secs_since >= _MANIFEST_SAVE_SECS:
                try:
                    save_manifest(manifest)
                    _last_save_files = idx
                    _last_save_at    = time.time()
                except Exception as exc:
                    # Saving failed (disk full, perms, etc.) — log and keep
                    # going.  The in-memory manifest survives and we'll try
                    # again on the next checkpoint.
                    logger.warning("[manifest] checkpoint save failed: %s", exc)
        except Exception as e:
            logger.error("Error ingesting %s: %s", path, e)
            totals["errors"] += 1

    # Final save so the last <_MANIFEST_SAVE_EVERY files are persisted.
    try:
        save_manifest(manifest)
    except Exception as exc:
        logger.warning("[manifest] final save failed: %s", exc)

    return totals, manifest


# ── CLI ──────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Build / refresh the ARGUS RAG knowledge base.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Quick start:
  Drop any supported files (PDF / MD / TXT / YAML / HTML / JSON) into
  knowledge/data/ -- any subfolder structure is fine -- then run:

    python knowledge/build_kb.py            # incremental: only changed files
    python knowledge/build_kb.py --reset    # wipe & rebuild from scratch
    python knowledge/build_kb.py --stats    # print current KB stats
    python knowledge/build_kb.py --search "apache rce"

Playbook YAMLs (id + trigger + steps schema) live in knowledge/data/playbooks/
and are loaded directly by the retriever -- they are NOT embedded.
        """
    )
    parser.add_argument("path",     nargs="?", default=DEFAULT_DATA,
                        help=f"File or directory to ingest (default: {DEFAULT_DATA})")
    parser.add_argument("--stats",  action="store_true", help="Print knowledge base stats and exit")
    parser.add_argument("--reset",  action="store_true", help="Wipe KB and re-ingest from scratch")
    parser.add_argument("--force",  action="store_true", help="Re-ingest all files (ignore manifest)")
    parser.add_argument("--search", metavar="QUERY",     help="Test a search query and show results")
    parser.add_argument("--top-k",  type=int, default=3,  help="Number of search results (default: 3)")
    args = parser.parse_args()

    # Import the KB (same directory)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import knowledge_base as kb_module

    if args.stats:
        s = kb_module.stats()
        print(json.dumps(s, indent=2))
        return

    if args.search:
        print(f"Searching: '{args.search}'")
        result = kb_module.search(args.search, top_k=args.top_k)
        print(result or "(no results found)")
        return

    if args.reset:
        import shutil
        if os.path.exists(kb_module.CHROMA_PATH):
            shutil.rmtree(kb_module.CHROMA_PATH)
            logger.info("Knowledge base wiped — starting fresh")
        # Also clear manifest
        if os.path.exists(MANIFEST_FILE):
            os.remove(MANIFEST_FILE)
        args.force = True  # After reset, force re-ingest

    target = os.path.expanduser(args.path)
    if not os.path.exists(target):
        logger.error("Path does not exist: %s\nDrop your PDFs / markdown / YAMLs / text files into %s/ and re-run.", target, DEFAULT_DATA)
        sys.exit(1)

    logger.info("Loading embedding model (first run downloads ~80 MB)...")
    t0 = time.time()

    if os.path.isdir(target):
        manifest = load_manifest() if not args.force else {}
        result, updated_manifest = ingest_directory(
            target, kb_module, manifest=manifest, force=args.force
        )
        save_manifest(updated_manifest)
    else:
        result = ingest_file(target, kb_module)
        updated_manifest = load_manifest()
        updated_manifest[target] = {
            "hash":      file_hash(target),
            "timestamp": time.time(),
            "chunks":    result.get("added", 0),
        }
        save_manifest(updated_manifest)

    elapsed = time.time() - t0
    print(f"\n✓ Done in {elapsed:.1f}s")
    print(f"  Files processed    : {result.get('files', 1)}")
    print(f"  Files unchanged    : {result.get('files_skipped', 0)}")
    print(f"  Chunks added       : {result.get('added', 0)}")
    print(f"  Chunks skipped     : {result.get('skipped', 0)} (duplicates)")
    print(f"  Errors             : {result.get('errors', 0)}")

    s = kb_module.stats()
    print(f"  KB total chunks    : {s.get('total_chunks', '?')}")
    print(f"  KB source files    : {s.get('source_files', '?')}")
    if s.get("by_chunk_type"):
        print(f"  Chunk types        : {json.dumps(s['by_chunk_type'])}")

    if result.get("added", 0) > 0:
        print("\nSample search: 'apache exploit shell'")
        sample = kb_module.search("apache exploit shell", top_k=2)
        print(sample[:600] if sample else "(no results)")


# ════════════════════════════════════════════════════════════════════════════
#                         R E T R I E V A L   E N G I N E
# ════════════════════════════════════════════════════════════════════════════
#
# Everything below this line is the QUERY-time engine consumed by the agents
# (``agents/base_agent._kb_context_async`` calls ``retrieve()`` from here).
#
# It is intentionally co-located with the ingest code so users see ONE file
# in ``knowledge/`` instead of a maze of submodules.  The two halves are
# logically independent — ingest writes to ChromaDB, retrieval reads.
#
# Pipeline (all tiers in one place):
#
#   Tier 0  ── Curated playbook lookup (YAML, deterministic intel match)
#   Tier 1  ── Hybrid retrieval (dense vectors + BM25 / FTS5 + RRF fusion)
#   Tier 2  ── HyDE query rewrite (LLM-driven, optional)
#   Tier 3  ── Cross-encoder rerank (BGE-reranker-v2-m3) + MMR diversity
#   Tier 4  ── Outcome / recency scoring boost
#
# Agents call ``retrieve(query, intel=..., llm=agent.think)`` and get back a
# ``RetrievalResult`` with playbooks + chunks + a prompt-ready ``.text``.
# ════════════════════════════════════════════════════════════════════════════

import math
import sqlite3
import unicodedata
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Sequence

# ── Retrieval constants ─────────────────────────────────────────────────────

_RAG_DATA_DIR    = Path(DEFAULT_DATA)
_RAG_LEGACY_PB_DIR = Path(_HERE) / "playbooks"     # back-compat for old layouts
_RAG_DB_DIR      = Path(DEFAULT_DB)
_RAG_DB_FILE     = _RAG_DB_DIR / "chroma.sqlite3"

_RAG_COLLECTION  = "pentest_knowledge"
# Defaults aligned with knowledge_base.py — bge-small for low-RAM hosts.
# Override via KB_EMBED_MODEL / KB_RERANK_MODEL env vars.
_RAG_EMBED_MODEL = os.environ.get("KB_EMBED_MODEL",  "BAAI/bge-small-en-v1.5")
_RAG_RERANK_MODEL = os.environ.get(
    "KB_RERANK_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2",
)
_RAG_RERANK_FALLBACK = "cross-encoder/ms-marco-MiniLM-L-6-v2"
_RAG_RRF_K       = 60         # Cormack et al. recommend k=60
_RAG_MMR_LAMBDA  = float(os.environ.get("KB_MMR_LAMBDA", "0.65"))


# ── Public types ────────────────────────────────────────────────────────────


@dataclass
class Playbook:
    """A single curated YAML playbook (Tier 0)."""
    id:               str
    title:            str
    phase:            str
    mitre:            List[str]
    trigger:          Dict[str, Any]
    keywords:         List[str]
    preconditions:    List[str]
    steps:            List[Dict[str, Any]]
    expected_outcome: str
    fallbacks:        List[str]
    references:       List[str]
    raw:              Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlaybookHit:
    playbook:   Playbook
    relevance:  float
    matched_on: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":               self.playbook.id,
            "title":            self.playbook.title,
            "phase":            self.playbook.phase,
            "mitre":            self.playbook.mitre,
            "relevance":        round(self.relevance, 3),
            "matched_on":       self.matched_on,
            "trigger":          self.playbook.trigger,
            "steps":            self.playbook.steps,
            "expected_outcome": self.playbook.expected_outcome,
            "fallbacks":        self.playbook.fallbacks,
            "references":       self.playbook.references,
        }

    def to_prompt_block(self) -> str:
        pb = self.playbook
        lines = [
            f"[PLAYBOOK · {pb.id}]  {pb.title}  ({self.relevance:.2f})",
            f"  matched: {', '.join(self.matched_on) or '(generic)'}",
        ]
        if pb.preconditions:
            lines.append(f"  pre: {'; '.join(pb.preconditions)}")
        for i, st in enumerate(pb.steps[:8], 1):
            lines.append(f"  {i}. {st.get('tool', '?')} :: {st.get('cmd', '')}")
            if st.get("why"):
                lines.append(f"     why: {st['why']}")
        if pb.expected_outcome:
            lines.append(f"  expect: {pb.expected_outcome}")
        if pb.fallbacks:
            lines.append("  fallbacks:")
            for fb in pb.fallbacks[:3]:
                lines.append(f"    - {fb}")
        return "\n".join(lines)


@dataclass
class RetrievedChunk:
    """One chunk returned by hybrid retrieval (Tier 1)."""
    text:          str
    source_file:   str
    chunk_index:   Any        = 0
    chunk_type:    str        = ""
    phase:         str        = ""
    outcome:       str        = ""
    tools:         List[str]  = field(default_factory=list)
    cves:          List[str]  = field(default_factory=list)
    mitre_ttps:    List[str]  = field(default_factory=list)
    attack_types:  List[str]  = field(default_factory=list)
    services:      List[str]  = field(default_factory=list)
    box_name:      str        = ""
    os:            str        = ""
    section_title: str        = ""
    relevance:     float      = 0.0
    sources_hit:   List[str]  = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text":          self.text,
            "source_file":   self.source_file,
            "chunk_index":   self.chunk_index,
            "chunk_type":    self.chunk_type,
            "phase":         self.phase,
            "outcome":       self.outcome,
            "tools":         self.tools,
            "cves":          self.cves,
            "mitre_ttps":    self.mitre_ttps,
            "attack_types":  self.attack_types,
            "services":      self.services,
            "box_name":      self.box_name,
            "os":            self.os,
            "section_title": self.section_title,
            "relevance":     round(float(self.relevance), 3),
            "sources_hit":   self.sources_hit,
        }

    def to_prompt_block(self) -> str:
        tags: List[str] = []
        if self.tools:        tags.append("tools: " + ", ".join(self.tools[:6]))
        if self.cves:         tags.append("cves: "  + ", ".join(self.cves[:3]))
        if self.mitre_ttps:   tags.append("mitre: " + ", ".join(self.mitre_ttps[:4]))
        if self.attack_types: tags.append("tech: "  + ", ".join(self.attack_types[:4]))

        head = f"[CHUNK · {self.source_file}"
        if self.box_name:      head += f" · {self.box_name}"
        if self.section_title: head += f" § {self.section_title[:60]}"
        if self.phase:         head += f" · {self.phase}"
        head += f"]  ({self.relevance:.2f}, via {','.join(self.sources_hit) or 'dense'})"

        body = (self.text or "").strip()
        max_body = 800 if self.chunk_type in ("command", "script", "procedure") else 600
        if len(body) > max_body:
            body = body[: max_body - 1] + "…"

        out = [head]
        if tags:
            out.append("  " + " | ".join(tags))
        out.append("  " + body.replace("\n", "\n  "))
        return "\n".join(out)


@dataclass
class RetrievalResult:
    """Everything an agent needs from a single retrieval call."""
    query:            str
    playbooks:        List[PlaybookHit]    = field(default_factory=list)
    chunks:           List[RetrievedChunk] = field(default_factory=list)
    used_hyde:        bool                 = False
    inferred_filters: Dict[str, Any]       = field(default_factory=dict)
    text:             str                  = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query":            self.query,
            "playbooks":        [p.to_dict() for p in self.playbooks],
            "chunks":           [c.to_dict() for c in self.chunks],
            "used_hyde":        self.used_hyde,
            "inferred_filters": self.inferred_filters,
            "text":             self.text,
        }


# ── Tier 0: Playbook lookup ─────────────────────────────────────────────────


_RAG_PB_CACHE: Optional[List[Playbook]] = None
_RAG_TOKEN_RE = re.compile(r"[a-z0-9_.\-]+")


def _rag_norm(s: Any) -> str:
    return unicodedata.normalize("NFKC", str(s or "")).strip().lower()


def _rag_tokens(s: Any) -> List[str]:
    return _RAG_TOKEN_RE.findall(_rag_norm(s))


def _rag_playbook_paths() -> List[Path]:
    """Find every YAML in data/ that has the playbook schema."""
    out: List[Path] = []
    for root in (_RAG_DATA_DIR, _RAG_LEGACY_PB_DIR):
        if not root.exists():
            continue
        for path in root.rglob("*.y*ml"):
            if not path.is_file():
                continue
            try:
                head = path.read_text(encoding="utf-8", errors="ignore")[:4096]
            except Exception:
                continue
            if ("\nid:"      in "\n" + head
                    and "\ntrigger:" in "\n" + head
                    and "\nsteps:"   in "\n" + head):
                out.append(path)
    return sorted(set(out))


def _rag_load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        import yaml  # type: ignore
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else None
    except Exception as exc:
        logger.warning("yaml load failed for %s: %s", path.name, exc)
        return None


def _rag_coerce_playbook(data: Dict[str, Any], path: Path) -> Optional[Playbook]:
    if not isinstance(data, dict):
        return None
    return Playbook(
        id=str(data.get("id") or path.stem),
        title=str(data.get("title") or data.get("id") or path.stem),
        phase=str(data.get("phase") or "general"),
        mitre=list(data.get("mitre") or []),
        trigger=dict(data.get("trigger") or {}),
        keywords=[str(k).lower() for k in (data.get("keywords") or [])],
        preconditions=list(data.get("preconditions") or []),
        steps=[dict(s) for s in (data.get("steps") or [])],
        expected_outcome=str(data.get("expected_outcome") or ""),
        fallbacks=list(data.get("fallbacks") or []),
        references=list(data.get("references") or []),
        raw=data,
    )


def load_playbooks(force_reload: bool = False) -> List[Playbook]:
    """Load and cache every playbook YAML found under ``knowledge/data/``."""
    global _RAG_PB_CACHE
    if _RAG_PB_CACHE is not None and not force_reload:
        return _RAG_PB_CACHE
    out: List[Playbook] = []
    for path in _rag_playbook_paths():
        data = _rag_load_yaml(path)
        if not data:
            continue
        pb = _rag_coerce_playbook(data, path)
        if pb:
            out.append(pb)
    _RAG_PB_CACHE = out
    logger.info("Loaded %d playbooks from %s", len(out), _RAG_DATA_DIR)
    return out


def has_playbooks() -> bool:
    return bool(_rag_playbook_paths())


def _rag_intel_haystack(intel: Dict[str, Any]) -> Dict[str, List[str]]:
    h: Dict[str, List[str]] = {
        "services": [], "ports": [], "technologies": [], "cves": [],
        "os": [], "mitre": [], "phase": [], "keywords": [],
    }
    if not intel:
        return h
    for key, dest in (("services", "services"),
                      ("technologies", "technologies")):
        v = intel.get(key)
        if isinstance(v, dict):
            for k in v.keys():
                h[dest].append(_rag_norm(k))
        elif isinstance(v, list):
            for it in v:
                if isinstance(it, dict):
                    for kk in ("name", "service", "product"):
                        if it.get(kk):
                            h[dest].append(_rag_norm(it[kk]))
                else:
                    h[dest].append(_rag_norm(it))
    for p in (intel.get("open_ports") or intel.get("ports") or []):
        h["ports"].append(_rag_norm(p))
    for c in (intel.get("cves") or []):
        h["cves"].append(_rag_norm(c))
    if intel.get("os_guess"): h["os"].append(_rag_norm(intel["os_guess"]))
    if intel.get("os"):       h["os"].append(_rag_norm(intel["os"]))
    for t in (intel.get("mitre_ttps") or []):
        h["mitre"].append(_rag_norm(t))
    if intel.get("phase"):
        h["phase"].append(_rag_norm(intel["phase"]))
    blob: List[str] = []
    for k in ("target_url", "target_host", "target_kind", "target",
              "engagement_type", "summary"):
        if intel.get(k):
            blob.append(_rag_norm(intel[k]))
    h["keywords"] = blob
    return h


def _rag_overlap(needles: Iterable[str], haystack: List[str],
                 *, numeric: bool = False) -> List[str]:
    out: List[str] = []
    if numeric:
        hset = {_rag_norm(h) for h in haystack if h is not None}
        for n in needles:
            k = _rag_norm(n)
            if k and k in hset:
                out.append(k)
        return out
    hay_tokens = [set(_rag_tokens(h)) for h in haystack if h]
    seen = set()
    for n in needles:
        nn = _rag_norm(n)
        if not nn or nn in seen:
            continue
        ntok = set(_rag_tokens(nn))
        if not ntok:
            continue
        for ht in hay_tokens:
            if not ht: continue
            if ntok == ht:
                out.append(nn); seen.add(nn); break
            inter, union = ntok & ht, ntok | ht
            if inter and len(inter) / max(1, len(union)) >= 0.5:
                out.append(nn); seen.add(nn); break
            if ntok.issubset(ht) or ht.issubset(ntok):
                out.append(nn); seen.add(nn); break
    return out


def _rag_trigger_score(pb: Playbook, intel: Dict[str, List[str]],
                       qtokens: List[str]) -> Tuple[float, List[str]]:
    matched: List[str] = []
    score = 0.0
    trig = pb.trigger or {}

    cve_match = _rag_overlap(trig.get("cves") or [], intel["cves"])
    if cve_match:
        score += 1.00 * len(cve_match);  matched.append(f"cves:{','.join(cve_match)}")
    svc_match = _rag_overlap(trig.get("services") or [], intel["services"])
    if svc_match:
        score += 0.40 * len(svc_match);  matched.append(f"services:{','.join(svc_match)}")
    port_match = _rag_overlap([str(p) for p in (trig.get("ports") or [])],
                              intel["ports"], numeric=True)
    if port_match:
        score += 0.30 * len(port_match); matched.append(f"ports:{','.join(port_match)}")
    tech_match = _rag_overlap(trig.get("technologies") or [], intel["technologies"])
    if tech_match:
        score += 0.45 * len(tech_match); matched.append(f"tech:{','.join(tech_match)}")
    os_match = _rag_overlap(trig.get("os_any") or [], intel["os"])
    if os_match:
        score += 0.20 * len(os_match);   matched.append(f"os:{','.join(os_match)}")
    mitre_match = _rag_overlap(pb.mitre or [], intel["mitre"])
    if mitre_match:
        score += 0.15 * len(mitre_match); matched.append(f"mitre:{','.join(mitre_match)}")

    if qtokens and pb.keywords:
        kw_tokens: set = set()
        for kw in pb.keywords:
            kw_tokens.update(_rag_tokens(kw))
        overlap = set(qtokens) & kw_tokens
        if overlap:
            score += 0.20 * min(len(overlap), 5)
            matched.append(f"kw:{','.join(sorted(overlap))[:60]}")

    if pb.phase and intel["phase"] and pb.phase == intel["phase"][0]:
        score += 0.10
        matched.append(f"phase:{pb.phase}")

    # Specificity gate — generic-only matches get demoted 0.35× so they can't
    # crowd out playbooks that hit a CVE / tech / keyword signal.
    has_specific = bool(cve_match or tech_match or mitre_match)
    has_keyword  = any(m.startswith("kw:") for m in matched)
    if score > 0 and not has_specific and not has_keyword:
        score *= 0.35

    return score, matched


def lookup_playbooks(query: str, *,
                     intel: Optional[Dict[str, Any]] = None,
                     top_k: int = 6,
                     min_score: float = 0.20) -> List[PlaybookHit]:
    pbs = load_playbooks()
    if not pbs:
        return []
    qtokens = _rag_tokens(query)
    intel_h = _rag_intel_haystack(intel or {})
    hits: List[PlaybookHit] = []
    for pb in pbs:
        s, why = _rag_trigger_score(pb, intel_h, qtokens)
        if s < min_score:
            continue
        hits.append(PlaybookHit(playbook=pb, relevance=min(1.0, s / 2.0),
                                matched_on=why))
    hits.sort(key=lambda h: h.relevance, reverse=True)
    return hits[:top_k]


# ── Tier 1: Hybrid retrieval (dense vectors + BM25) ─────────────────────────


_RAG_EMBEDDER  = None
_RAG_COLL      = None
_RAG_RERANKER  = None
_RAG_RERANKER_LOADED = False
_RAG_FTS_TOKEN_RE = re.compile(r"[a-z0-9_.\-/]+")


def has_vector_store() -> bool:
    if not _RAG_DB_FILE.exists():
        return False
    try:
        con = sqlite3.connect(f"file:{_RAG_DB_FILE.as_posix()}?mode=ro", uri=True)
        try:
            (n,) = con.execute("SELECT COUNT(*) FROM embeddings").fetchone()
            return n > 0
        finally:
            con.close()
    except Exception:
        return False


def _rag_get_embedder():
    global _RAG_EMBEDDER
    if _RAG_EMBEDDER is None:
        from sentence_transformers import SentenceTransformer  # type: ignore
        logger.info("loading embedder: %s", _RAG_EMBED_MODEL)
        _RAG_EMBEDDER = SentenceTransformer(_RAG_EMBED_MODEL)
        if "bge-m3" in _RAG_EMBED_MODEL:
            _RAG_EMBEDDER.max_seq_length = 8192
    return _RAG_EMBEDDER


def _rag_get_collection():
    global _RAG_COLL
    if _RAG_COLL is None:
        import chromadb  # type: ignore
        from chromadb.config import Settings  # type: ignore
        client = chromadb.PersistentClient(
            path=str(_RAG_DB_DIR),
            settings=Settings(anonymized_telemetry=False),
        )
        _RAG_COLL = client.get_or_create_collection(
            name=_RAG_COLLECTION, metadata={"hnsw:space": "cosine"},
        )
    return _RAG_COLL


def _rag_build_where(metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conds: List[Dict[str, Any]] = []
    for k in ("phase", "outcome", "chunk_type", "box_name"):
        v = metadata.get(k)
        if v:
            conds.append({k: {"$eq": str(v)}})
    if not conds:           return None
    if len(conds) == 1:     return conds[0]
    return {"$and": conds}


def _rag_dense_search(queries: Sequence[str], top_k: int,
                      where: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    try:
        col = _rag_get_collection()
        embedder = _rag_get_embedder()
    except Exception as exc:
        logger.warning("dense backend unavailable: %s", exc)
        return []
    seen: Dict[str, Dict[str, Any]] = {}
    for q in queries:
        try:
            emb = embedder.encode(q, normalize_embeddings=True).tolist()
            kwargs: Dict[str, Any] = {
                "query_embeddings": [emb], "n_results": top_k,
                "include": ["documents", "metadatas", "distances"],
            }
            if where:
                kwargs["where"] = where
            res = col.query(**kwargs)
        except Exception as exc:
            logger.warning("dense query failed: %s", exc)
            continue
        ids   = (res.get("ids")        or [[]])[0]
        docs  = (res.get("documents")  or [[]])[0]
        metas = (res.get("metadatas")  or [[]])[0]
        dists = (res.get("distances")  or [[]])[0]
        for rank, (rid, doc, meta, dist) in enumerate(zip(ids, docs, metas, dists)):
            key = rid or f"{(meta or {}).get('source_file','?')}:{(meta or {}).get('chunk_index','?')}"
            entry = {"id": key, "doc": doc, "meta": meta or {},
                     "dense_score": 1.0 - float(dist), "dense_rank": rank + 1}
            if key not in seen or entry["dense_score"] > seen[key]["dense_score"]:
                seen[key] = entry
    return list(seen.values())


def _rag_fts_query(text: str) -> str:
    norm = unicodedata.normalize("NFKC", text or "").lower()
    tokens = [t for t in _RAG_FTS_TOKEN_RE.findall(norm) if len(t) > 1]
    return " OR ".join(t.replace('"', '') for t in tokens[:12])


def _rag_bm25_search(query: str, top_k: int) -> List[Dict[str, Any]]:
    if not _RAG_DB_FILE.exists():
        return []
    expr = _rag_fts_query(query)
    if not expr:
        return []
    try:
        con = sqlite3.connect(f"file:{_RAG_DB_FILE.as_posix()}?mode=ro", uri=True)
    except Exception as exc:
        logger.warning("FTS open failed: %s", exc)
        return []
    rows: List[Tuple] = []
    try:
        cur = con.execute(
            """
            SELECT efs.id, efs.string_value AS doc,
                   bm25(embedding_fulltext_search) AS score
            FROM   embedding_fulltext_search AS efs
            WHERE  efs.string_value MATCH ?
            ORDER  BY score
            LIMIT  ?
            """, (expr, top_k * 2),
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        try:
            cur = con.execute(
                """
                SELECT rowid AS id, string_value AS doc,
                       bm25(embedding_fulltext_search) AS score
                FROM   embedding_fulltext_search
                WHERE  string_value MATCH ?
                ORDER  BY score
                LIMIT  ?
                """, (expr, top_k * 2),
            )
            rows = cur.fetchall()
        except Exception as exc:
            logger.warning("FTS fallback failed: %s", exc)
    except Exception as exc:
        logger.warning("FTS query failed: %s", exc)
    finally:
        con.close()
    out: List[Dict[str, Any]] = []
    for rank, (rid, doc, score) in enumerate(rows[:top_k]):
        s = max(0.0, min(1.0, 1.0 - (-float(score) / 25.0)))
        out.append({
            "id": str(rid), "doc": doc, "meta": {},
            "bm25_score": s, "bm25_rank": rank + 1,
        })
    return out


def _rag_hydrate_meta(con: sqlite3.Connection, doc_id: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        cur = con.execute(
            "SELECT key, string_value, int_value, float_value, bool_value "
            "FROM embedding_metadata WHERE id = ?", (doc_id,)
        )
        for key, sv, iv, fv, bv in cur.fetchall():
            if   sv is not None: out[key] = sv
            elif iv is not None: out[key] = iv
            elif fv is not None: out[key] = fv
            elif bv is not None: out[key] = bool(bv)
    except Exception:
        pass
    return out


def _rag_rrf_merge(dense: List[Dict[str, Any]], bm25: List[Dict[str, Any]],
                   k: int = _RAG_RRF_K) -> List[Dict[str, Any]]:
    pool: Dict[str, Dict[str, Any]] = {}
    for entry in dense:
        rid = entry["id"]
        rrf = 1.0 / (k + entry.get("dense_rank", 999))
        pool[rid] = {**entry, "rrf": rrf, "sources_hit": ["dense"]}
    for entry in bm25:
        rid = entry["id"]
        rrf = 1.0 / (k + entry.get("bm25_rank", 999))
        if rid in pool:
            pool[rid]["rrf"] += rrf
            pool[rid]["sources_hit"].append("bm25")
            pool[rid].setdefault("bm25_score", entry.get("bm25_score", 0.0))
        else:
            pool[rid] = {**entry, "rrf": rrf, "sources_hit": ["bm25"]}
    return sorted(pool.values(), key=lambda r: r["rrf"], reverse=True)


def _rag_to_chunk(entry: Dict[str, Any]) -> RetrievedChunk:
    meta = entry.get("meta") or {}
    def _list(key: str) -> List[str]:
        v = meta.get(key)
        if not v:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        try:
            parsed = json.loads(v)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except Exception:
            pass
        return [str(v)]
    dense = entry.get("dense_score", 0.0) or 0.0
    bm25  = entry.get("bm25_score", 0.0)  or 0.0
    rrf   = entry.get("rrf",        0.0)  or 0.0
    rel   = max(dense, bm25, rrf * 4.0)
    return RetrievedChunk(
        text         = entry.get("doc") or "",
        source_file  = str(meta.get("source_file") or "unknown"),
        chunk_index  = meta.get("chunk_index") or 0,
        chunk_type   = str(meta.get("chunk_type")    or ""),
        phase        = str(meta.get("phase")         or ""),
        outcome      = str(meta.get("outcome")       or ""),
        tools        = _list("tools"),
        cves         = _list("cves"),
        mitre_ttps   = _list("mitre_ttps"),
        attack_types = _list("attack_types"),
        services     = _list("services"),
        box_name     = str(meta.get("box_name")      or ""),
        os           = str(meta.get("os")            or ""),
        section_title= str(meta.get("section_title") or ""),
        relevance    = float(rel),
        sources_hit  = list(entry.get("sources_hit") or []),
    )


def hybrid_search(queries: Sequence[str], *, top_k: int = 25,
                  phase: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> List[RetrievedChunk]:
    if not queries:
        return []
    md = dict(metadata or {})
    if phase:
        md.setdefault("phase", phase)
    where = _rag_build_where(md)
    dense_hits = _rag_dense_search(queries, top_k=top_k, where=where)
    bm25_hits  = _rag_bm25_search(queries[0], top_k=top_k) if queries else []
    fused = _rag_rrf_merge(dense_hits, bm25_hits)
    if bm25_hits and _RAG_DB_FILE.exists():
        try:
            con = sqlite3.connect(f"file:{_RAG_DB_FILE.as_posix()}?mode=ro", uri=True)
            try:
                for entry in fused:
                    if not entry.get("meta"):
                        entry["meta"] = _rag_hydrate_meta(con, entry["id"])
            finally:
                con.close()
        except Exception:
            pass
    return [_rag_to_chunk(e) for e in fused[:top_k]]


# ── Tier 2: HyDE query rewrite ──────────────────────────────────────────────


_HYDE_SYSTEM = (
    "You are a senior penetration testing engineer. "
    "Given a question, write a concise, technical 3-5 sentence answer in "
    "the style of an HTB/THM writeup or pentest report — concrete tools, "
    "exact commands, and outcomes. Do NOT add disclaimers, headers, or "
    "markdown. Output the paragraph only."
)


def _rag_intel_brief(intel: Dict[str, Any]) -> str:
    if not intel:
        return ""
    bits: List[str] = []
    for k in ("target_kind", "os_guess", "engagement_type"):
        if intel.get(k):
            bits.append(f"{k}={intel[k]}")
    services = intel.get("services") or []
    if isinstance(services, dict):
        services = list(services.keys())
    if services:
        bits.append(f"services={','.join(map(str, services[:6]))}")
    ports = intel.get("open_ports") or intel.get("ports") or []
    if ports:
        bits.append(f"ports={','.join(map(str, ports[:8]))}")
    techs = intel.get("technologies") or []
    if techs:
        bits.append(f"tech={','.join(map(str, techs[:6]))}")
    return " | ".join(bits)


async def maybe_hyde_rewrite(query: str, *,
                             intel: Optional[Dict[str, Any]] = None,
                             llm:   Optional[Callable[..., Awaitable[str]]] = None,
                             max_tokens_hint: int = 250) -> Optional[str]:
    if not llm or not query or len(query.strip()) < 8:
        return None
    brief = _rag_intel_brief(intel or {})
    user_prompt = (
        f"Question: {query.strip()}\n"
        + (f"Context: {brief}\n" if brief else "")
        + "Write the hypothetical answer paragraph now."
    )
    try:
        out = await llm(user_prompt, _HYDE_SYSTEM)
    except TypeError:
        try:
            out = await llm(user_prompt)
        except Exception:
            return None
    except Exception:
        return None
    if not out:
        return None
    out = out.strip()
    if any(out.lower().startswith(b) for b in ("i cannot", "i'm sorry", "as an ai", "{}", "null")):
        return None
    return out[: max_tokens_hint * 6]


# ── Tier 3: Cross-encoder rerank + MMR diversity ────────────────────────────


def _rag_get_reranker():
    global _RAG_RERANKER, _RAG_RERANKER_LOADED
    if _RAG_RERANKER_LOADED:
        return _RAG_RERANKER
    _RAG_RERANKER_LOADED = True
    try:
        from sentence_transformers import CrossEncoder  # type: ignore
        try:
            logger.info("loading reranker: %s", _RAG_RERANK_MODEL)
            _RAG_RERANKER = CrossEncoder(_RAG_RERANK_MODEL, max_length=512)
        except Exception as exc:
            logger.warning("reranker %s unavailable (%s) — fallback %s",
                           _RAG_RERANK_MODEL, exc, _RAG_RERANK_FALLBACK)
            _RAG_RERANKER = CrossEncoder(_RAG_RERANK_FALLBACK, max_length=512)
    except Exception as exc:
        logger.warning("no reranker available (%s) — skipping", exc)
        _RAG_RERANKER = None
    return _RAG_RERANKER


def _rag_jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / len(a | b) if inter else 0.0


def _rag_mmr_select(query: str, ranked: List[RetrievedChunk],
                    top_k: int, lam: float = _RAG_MMR_LAMBDA) -> List[RetrievedChunk]:
    if len(ranked) <= top_k:
        return ranked
    chosen: List[RetrievedChunk] = []
    chosen_tokens: List[set] = []
    pool = list(ranked)
    qtok = set(_rag_tokens(query))
    while pool and len(chosen) < top_k:
        best_idx, best_score = 0, float("-inf")
        for i, c in enumerate(pool):
            ctok = set(_rag_tokens(c.text))
            penalty = max((_rag_jaccard(ctok, ct) for ct in chosen_tokens), default=0.0)
            qoverlap = _rag_jaccard(ctok, qtok) if qtok else 0.0
            mmr = lam * (c.relevance + 0.05 * qoverlap) - (1.0 - lam) * penalty
            if mmr > best_score:
                best_score, best_idx = mmr, i
        chosen.append(pool.pop(best_idx))
        chosen_tokens.append(set(_rag_tokens(chosen[-1].text)))
    return chosen


def rerank_with_diversity(query: str, candidates: Sequence[RetrievedChunk],
                          *, top_k: int = 6) -> List[RetrievedChunk]:
    if not candidates:
        return []
    cands = list(candidates)
    rer = _rag_get_reranker()
    if rer is not None and len(cands) > 1:
        try:
            scores = rer.predict([(query, c.text) for c in cands])
            for c, s in zip(cands, scores):
                c.relevance = float(s)
        except Exception as exc:
            logger.warning("rerank predict failed: %s", exc)
    cands.sort(key=lambda c: c.relevance, reverse=True)
    return _rag_mmr_select(query, cands[: max(top_k * 4, 20)], top_k=top_k)


# ── Tier 4: Outcome × recency boost ─────────────────────────────────────────


_OUTCOME_TABLE = {
    "root":             1.50,  "shell":          1.40,  "shell obtained":   1.40,
    "user flag":        1.30,  "domain admin":   1.50,  "credential":       1.20,
    "credential found": 1.20,  "rce":            1.40,  "success":          1.20,
    "":                 1.00,  "unknown":        1.00,  "info":             0.95,
    "failed":           0.70,  "blocked":        0.65,  "denied":           0.65,
}


def _rag_outcome_weight(outcome: str) -> float:
    if not outcome:
        return 1.0
    key = outcome.lower().strip()
    if key in _OUTCOME_TABLE:
        return _OUTCOME_TABLE[key]
    for k, w in _OUTCOME_TABLE.items():
        if k and k in key:
            return w
    return 1.0


def apply_outcome_recency_boost(chunks: List[RetrievedChunk]) -> List[RetrievedChunk]:
    for c in chunks:
        c.relevance = float(c.relevance) * _rag_outcome_weight(c.outcome)
    return chunks


# ── Self-query (heuristic + optional LLM) ───────────────────────────────────


_RAG_CVE_RE   = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)
_RAG_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RAG_PORT_RE  = re.compile(r"\b(?:port\s*)?(\d{2,5})/(?:tcp|udp)\b", re.IGNORECASE)

_RAG_PHASE_HINTS = {
    "recon":   ("recon","enum","scan","discover","fingerprint","nmap","subdomain","dns"),
    "exploit": ("exploit","rce","shell","payload","reverse","foothold","cve-","msf"),
    "privesc": ("privesc","escalat","root","sudo","suid","linpeas","winpeas","kernel"),
    "web":     ("web","http","sqli","xss","lfi","rfi","ssrf","ssti","burp","jwt"),
    "post":    ("loot","exfil","creds","hash","lsass","dpapi","persistence"),
    "lateral": ("lateral","pivot","smb","winrm","psexec","kerberos","bloodhound","mimikatz"),
}
_RAG_OS_HINTS = {
    "linux":   ("linux","ubuntu","debian","kernel","/etc/passwd","bash","www-data"),
    "windows": ("windows","active directory","kerberos","ntlm","domain admin","powershell"),
    "macos":   ("macos","darwin","osx"),
}
_RAG_SVC_HINTS = {
    "smb":      ("smb","samba","445","139","netbios"),
    "http":     ("http","https","apache","nginx","iis"),
    "ssh":      ("ssh","openssh","22"),
    "ftp":      ("ftp","vsftpd","21"),
    "mysql":    ("mysql","mariadb","3306"),
    "mssql":    ("mssql","sqlserver","1433"),
    "ldap":     ("ldap","389","636"),
    "kerberos": ("kerberos","88"),
    "redis":    ("redis","6379"),
    "mongodb":  ("mongodb","27017"),
}


def _rag_heuristic_extract(query: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    q = query.lower()
    cves = _RAG_CVE_RE.findall(query)
    if cves:  out["cves"] = [c.upper() for c in cves]
    mitre = _RAG_MITRE_RE.findall(query)
    if mitre: out["mitre"] = list(dict.fromkeys(mitre))
    ports = [int(m.group(1)) for m in _RAG_PORT_RE.finditer(query)]
    if ports: out["ports"] = ports
    for phase, hints in _RAG_PHASE_HINTS.items():
        if any(h in q for h in hints):
            out["phase"] = phase
            break
    for os_name, hints in _RAG_OS_HINTS.items():
        if any(h in q for h in hints):
            out["os"] = os_name
            break
    services: List[str] = []
    for svc, hints in _RAG_SVC_HINTS.items():
        if any(h in q for h in hints):
            services.append(svc)
    if services:
        out["services"] = services
    return out


async def infer_metadata_filters(query: str, *,
                                 intel: Optional[Dict[str, Any]] = None,
                                 llm:   Optional[Callable[..., Awaitable[str]]] = None
                                 ) -> Dict[str, Any]:
    base = _rag_heuristic_extract(query)
    if llm is None:
        return base
    sys_prompt = (
        "You extract structured search filters from pentest queries. "
        "Output valid JSON only — no commentary. Keys you may use: "
        "phase, services, ports, os, technologies, cves, mitre. "
        "Empty/null any key you can't determine."
    )
    try:
        raw = await llm(f"Query: {query}\nReturn only the JSON object.", sys_prompt)
    except TypeError:
        try:
            raw = await llm(f"Query: {query}\nReturn only the JSON object.")
        except Exception:
            return base
    except Exception:
        return base
    if not raw:
        return base
    try:
        ext = {k: v for k, v in (json.loads(raw) or {}).items() if v}
    except Exception:
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return base
        try:
            ext = {k: v for k, v in (json.loads(m.group(0)) or {}).items() if v}
        except Exception:
            return base
    merged = dict(ext or {})
    merged.update(base)   # heuristic CVE/MITRE/port wins over LLM
    return merged


# ── Public retrieval API ────────────────────────────────────────────────────


def available() -> bool:
    """True if either curated playbooks or the vector store are usable."""
    try:
        if has_playbooks():
            return True
    except Exception:
        pass
    try:
        return has_vector_store()
    except Exception:
        return False


def _rag_format_for_prompt(r: RetrievalResult) -> str:
    out: List[str] = []
    if r.playbooks:
        out.append("=== ARGUS PLAYBOOKS ===")
        for pb in r.playbooks:
            out.append(pb.to_prompt_block())
        out.append("=== END PLAYBOOKS ===")
    if r.chunks:
        out.append("\n=== ARGUS KNOWLEDGE BASE ===")
        for c in r.chunks:
            out.append(c.to_prompt_block())
        out.append("=== END KNOWLEDGE BASE ===")
    if not out:
        return ""
    out.append(
        "\nApply the playbooks first (they are field-validated). "
        "Use the knowledge-base chunks to refine commands and adapt to the "
        "current target's intel."
    )
    return "\n".join(out)


async def retrieve(query: str, *,
                   intel:           Optional[Dict[str, Any]] = None,
                   top_k:           int = 6,
                   phase:           Optional[str] = None,
                   use_hyde:        bool = True,
                   use_rerank:      bool = True,
                   use_self_query:  bool = True,
                   llm:             Optional[Callable[..., Awaitable[str]]] = None
                   ) -> RetrievalResult:
    """Run the full 4-tier retrieval pipeline.

    Pass the agent's ``think`` coroutine as ``llm`` to enable HyDE +
    LLM-driven self-query metadata extraction.  When ``llm=None`` those
    tiers are silently skipped and we fall back to dense + BM25 only.
    """
    intel = dict(intel or {})
    result = RetrievalResult(query=query)
    if not query or len(query.strip()) < 3:
        return result

    # Tier 0
    try:
        result.playbooks = lookup_playbooks(query, intel=intel, top_k=top_k)
    except Exception as exc:
        logger.warning("Tier 0 (playbooks) failed: %s", exc)

    # Self-query
    inferred: Dict[str, Any] = {}
    if use_self_query:
        try:
            inferred = await infer_metadata_filters(query, intel=intel, llm=llm)
            result.inferred_filters = inferred
        except Exception as exc:
            logger.warning("self-query failed: %s", exc)

    # Tier 2 — HyDE (only when llm is callable)
    queries: List[str] = [query]
    if use_hyde and llm is not None:
        try:
            hyde_doc = await maybe_hyde_rewrite(query, intel=intel, llm=llm)
            if hyde_doc:
                queries.append(hyde_doc)
                result.used_hyde = True
        except Exception as exc:
            logger.warning("HyDE rewrite failed: %s", exc)

    # Tier 1 — hybrid retrieval
    candidates: List[RetrievedChunk] = []
    try:
        candidates = hybrid_search(queries=queries,
                                   top_k=max(top_k * 4, 25),
                                   phase=phase, metadata=inferred)
    except Exception as exc:
        logger.warning("Tier 1 (hybrid) failed: %s", exc)
        candidates = []

    # Tier 4 — outcome boost (before rerank)
    candidates = apply_outcome_recency_boost(candidates)

    # Tier 3 — rerank + MMR
    if use_rerank and candidates:
        try:
            candidates = rerank_with_diversity(query=query,
                                               candidates=candidates, top_k=top_k)
        except Exception as exc:
            logger.warning("Tier 3 (rerank) failed: %s", exc)
            candidates = candidates[:top_k]
    else:
        candidates = candidates[:top_k]

    result.chunks = candidates
    result.text   = _rag_format_for_prompt(result)
    return result


async def retrieve_text(query: str, *,
                        intel: Optional[Dict[str, Any]] = None,
                        top_k: int = 6,
                        phase: Optional[str] = None,
                        llm:   Optional[Callable[..., Awaitable[str]]] = None) -> str:
    """Convenience wrapper — return the prompt-ready text only."""
    res = await retrieve(query, intel=intel, top_k=top_k, phase=phase, llm=llm)
    return res.text


# ── End of retrieval engine ─────────────────────────────────────────────────


if __name__ == "__main__":
    main()
