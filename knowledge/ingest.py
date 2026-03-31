#!/usr/bin/env python3
"""
ingest.py — Enhanced ingestion pipeline for the Kali Pentest Platform RAG v2

Improvements over v1:
  - Structure-aware chunking (respects headers, code blocks, procedures, commands)
  - Chunk type classification (command/script/procedure/technique/tip/finding/tool_usage)
  - MHTML support (.mhtml — HackTheBox writeup format from 0xdf)
  - Incremental manifest: only re-ingest new or modified files
  - MITRE ATT&CK TTP extraction (T#### patterns)
  - Expanded tool list (130+ tools), attack patterns (50+), service patterns (50+)
  - Section title preserved in chunk metadata for better context
  - Configurable chunk sizes per content type

Usage:
  python3 ingest.py /path/to/writeups/          # ingest (incremental by default)
  python3 ingest.py /path/to/single.pdf         # ingest one file
  python3 ingest.py /path/to/dir --force        # re-ingest all files ignoring manifest
  python3 ingest.py /path/to/dir --stats        # just print current stats
  python3 ingest.py /path/to/dir --reset        # wipe KB and re-ingest everything
  python3 ingest.py /path/to/dir --search QUERY # test a search query

Supports: .pdf, .md, .markdown, .html, .htm, .mhtml, .txt, .json, .yaml, .yml

Install once:
  pip install chromadb sentence-transformers pypdf beautifulsoup4 tqdm lxml
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
logger = logging.getLogger("ingest")

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

# ── Manifest for incremental ingestion ──────────────────────────────────────────
MANIFEST_FILE = os.path.join(os.path.dirname(__file__), "chroma_db", "ingest_manifest.json")


def load_manifest() -> Dict[str, Any]:
    """Load the ingestion manifest (file path → {hash, timestamp, chunks})."""
    if os.path.exists(MANIFEST_FILE):
        try:
            with open(MANIFEST_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_manifest(manifest: Dict[str, Any]) -> None:
    """Persist the ingestion manifest."""
    os.makedirs(os.path.dirname(MANIFEST_FILE), exist_ok=True)
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)


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
        logger.warning(f"PDF parse error {path}: {e}")


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
        logger.warning(f"MD parse error {path}: {e}")


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
        logger.warning(f"HTML parse error {path}: {e}")


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
        logger.warning(f"MHTML parse error {path}: {e}")


def extract_txt(path: str) -> Generator[Tuple[str, str], None, None]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            yield (f.read(), "")
    except Exception as e:
        logger.warning(f"TXT parse error {path}: {e}")


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
        logger.warning(f"JSON parse error {path}: {e}")


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
        logger.warning(f"YAML parse error {path}: {e}")


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
        "box_name":     box_name,
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
        logger.error(f"Extraction failed for {path}: {e}")
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
    for root, _, files in os.walk(directory):
        for fname in files:
            if Path(fname).suffix.lower() in EXTRACTORS:
                paths.append(os.path.join(root, fname))

    # Filter to only files that need ingesting
    to_ingest = [p for p in paths if needs_ingest(p, manifest, force=force)]
    skip_count = len(paths) - len(to_ingest)

    logger.info(f"Found {len(paths)} files | {len(to_ingest)} to ingest | {skip_count} unchanged (skipped)")

    totals = {"added": 0, "skipped": 0, "errors": 0, "files": 0, "files_skipped": skip_count}

    for path in tqdm(to_ingest, desc="Ingesting", unit="file"):
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
        except Exception as e:
            logger.error(f"Error ingesting {path}: {e}")
            totals["errors"] += 1

    return totals, manifest


# ── CLI ──────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ingest CTF writeups and pentest content into the RAG knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ingest.py ./data/                   # incremental ingest of data folder
  python3 ingest.py ./data/ --force           # re-ingest all files
  python3 ingest.py report.pdf                # ingest single file
  python3 ingest.py ./data/ --stats           # show KB statistics
  python3 ingest.py ./data/ --search "apache exploit"  # test search
  python3 ingest.py ./data/ --reset           # wipe and re-ingest
        """
    )
    parser.add_argument("path",     nargs="?",         help="File or directory to ingest")
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

    if not args.path:
        parser.print_help()
        return

    target = os.path.expanduser(args.path)
    if not os.path.exists(target):
        logger.error(f"Path does not exist: {target}")
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


if __name__ == "__main__":
    main()
