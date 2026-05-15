"""agents/reasoning/exfil_pipeline.py — Recommendation #7

Loot collection and data-exfiltration pipeline.

The post-foothold primer (#4) and lateral primer (#6) shovel raw shell
output into this module.  Its job is to:

  1. **Classify** that output against a Data-of-Interest (DoI) catalog —
     credentials, NTLM/Kerberos hashes, SSH keys, browser stores, source
     code with secrets, configuration files, customer PII patterns, etc.
  2. **Stage** matched loot in a per-engagement loot directory with a
     stable filename scheme so the operator (and the report generator)
     can find it later.
  3. **Manifest** every byte that left the target into a JSONL audit log
     — chain-of-custody for the final report.
  4. **Surface** structured findings back to MasterAgent so the issue
     validator and report generator can reference them.

This module is intentionally **passive about transport** — it does not
spawn its own egress channel.  The shell session that already exists
(reverse shell, SSH, evil-winrm) is the channel.  The output of every
shell_exec call is routed through here for classification + staging.

Wiring:
  ShellExecutor → output → ExfilPipeline.ingest(output, source) →
      classify → stage_to_disk → manifest_append → emit_finding →
      MasterAgent.intel['loot'] aggregated for the lateral primer.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


logger = logging.getLogger(__name__)


__all__ = [
    "DataOfInterest", "LootEntry", "ExfilPipeline",
    "DEFAULT_DOI_PATTERNS",
]


# ════════════════════════════════════════════════════════════════════
# Data-of-Interest catalog
# ════════════════════════════════════════════════════════════════════

@dataclass
class DataOfInterest:
    id:             str
    label:          str
    severity:       str               # info / low / medium / high / critical
    pattern:        re.Pattern
    capture:        str = "0"         # group name or "0" for entire match
    redact_in_log:  bool = False
    multiline:      bool = False


_F = re.MULTILINE


DEFAULT_DOI_PATTERNS: List[DataOfInterest] = [
    # ── Authentication artefacts ─────────────────────────────────────
    DataOfInterest(
        id="ntlm_hash",
        label="NTLM Hash (NTDS / SAM dump line)",
        severity="critical",
        pattern=re.compile(r"\b([A-Za-z0-9_.\\-]+):(\d{3,7}):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="kerberos_asrep",
        label="Kerberos AS-REP Hash (hashcat 18200 format)",
        severity="critical",
        pattern=re.compile(r"\$krb5asrep\$23\$[^\s'\"]{40,}"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="kerberos_tgs",
        label="Kerberos TGS Hash (hashcat 13100 format)",
        severity="critical",
        pattern=re.compile(r"\$krb5tgs\$23\$\*[^\s'\"]+\*\$[a-fA-F0-9]{32}\$[^\s'\"]+"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="bcrypt_hash",
        label="bcrypt password hash",
        severity="high",
        pattern=re.compile(r"\$2[abxy]\$\d{1,2}\$[A-Za-z0-9./]{53}"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="md5_passwd_line",
        label="/etc/shadow style hash line",
        severity="critical",
        pattern=re.compile(r"^[A-Za-z0-9_-]+:\$[156y]\$[^\s:]+:", _F),
        redact_in_log=True,
    ),

    # ── SSH artefacts ────────────────────────────────────────────────
    DataOfInterest(
        id="ssh_private_key",
        label="SSH private key block",
        severity="critical",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ED25519 )?PRIVATE KEY-----"
            r"[\s\S]+?"
            r"-----END (?:RSA |OPENSSH |EC |DSA |ED25519 )?PRIVATE KEY-----"
        ),
        multiline=True,
        redact_in_log=True,
    ),

    # ── API tokens / cloud creds ────────────────────────────────────
    DataOfInterest(
        id="aws_access_key",
        label="AWS Access Key ID",
        severity="critical",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="aws_secret_key",
        label="AWS Secret Access Key",
        severity="critical",
        pattern=re.compile(r"\baws_secret_access_key\s*=\s*['\"]?(?P<val>[A-Za-z0-9/+=]{40})['\"]?", re.I),
        capture="val",
        redact_in_log=True,
    ),
    DataOfInterest(
        id="github_token",
        label="GitHub personal access token",
        severity="high",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="slack_token",
        label="Slack token",
        severity="high",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="gcp_service_key",
        label="GCP service account JSON",
        severity="critical",
        pattern=re.compile(r'"type":\s*"service_account"[\s\S]{0,500}?"private_key":\s*"-----BEGIN'),
        multiline=True,
        redact_in_log=True,
    ),
    DataOfInterest(
        id="azure_app_secret",
        label="Azure AD app client secret",
        severity="critical",
        pattern=re.compile(r"AZURE_CLIENT_SECRET\s*=\s*['\"]?(?P<val>[A-Za-z0-9~._\-]{30,})['\"]?", re.I),
        capture="val",
        redact_in_log=True,
    ),
    DataOfInterest(
        id="jwt_token",
        label="JSON Web Token",
        severity="medium",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_=-]{10,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=.+/-]{10,}\b"),
        redact_in_log=True,
    ),

    # ── Database connection strings ──────────────────────────────────
    DataOfInterest(
        id="db_conn_string",
        label="Database URL with embedded password",
        severity="high",
        pattern=re.compile(
            r"\b(?:postgres|postgresql|mysql|mariadb|mongodb|redis|amqp|sqlserver|mssql|jdbc:[a-z]+)://"
            r"[^:\s'\"]+:[^@\s'\"]{4,}@[^/\s'\"]+",
            re.I,
        ),
        redact_in_log=True,
    ),

    # ── .env / config secrets ────────────────────────────────────────
    DataOfInterest(
        id="env_dotenv_secret",
        label=".env variable with secret-shaped value",
        severity="medium",
        pattern=re.compile(
            r"^(?P<key>[A-Z][A-Z0-9_]+(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD|API))"
            r"\s*=\s*['\"]?(?P<val>[^\s'\"]{8,})['\"]?\s*$",
            _F,
        ),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="basic_auth_header",
        label="HTTP Basic auth header (base64 creds)",
        severity="high",
        pattern=re.compile(r"Authorization:\s*Basic\s+(?P<val>[A-Za-z0-9+/=]{8,})", re.I),
        capture="val",
        redact_in_log=True,
    ),

    # ── PII-shaped data ──────────────────────────────────────────────
    DataOfInterest(
        id="ssn_us",
        label="US SSN (XXX-XX-XXXX format)",
        severity="critical",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        redact_in_log=True,
    ),
    DataOfInterest(
        id="email_address",
        label="Email address (info-only)",
        severity="info",
        pattern=re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    ),

    # ── Source-code secrets ─────────────────────────────────────────
    DataOfInterest(
        id="hardcoded_password",
        label="Hardcoded password in source",
        severity="medium",
        pattern=re.compile(
            r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"](?P<val>[^'\"]{6,})['\"]",
            re.I,
        ),
        capture="val",
        redact_in_log=True,
    ),

    # ── File paths to interesting files ──────────────────────────────
    DataOfInterest(
        id="file_kdbx",
        label="KeePass database file path",
        severity="high",
        pattern=re.compile(r"\b[\w\-./\\:]*\.kdbx\b", re.I),
    ),
    DataOfInterest(
        id="file_pfx_pem",
        label="Certificate / private-key file path",
        severity="high",
        pattern=re.compile(r"\b[\w\-./\\:]+\.(?:pfx|p12|pem|key|cer|crt)\b", re.I),
    ),
]


# ════════════════════════════════════════════════════════════════════
# Loot entries + manifest
# ════════════════════════════════════════════════════════════════════

@dataclass
class LootEntry:
    """A single piece of loot extracted from shell output."""
    id:           str
    doi_id:       str
    doi_label:    str
    severity:     str
    source:       str
    target:       str
    captured_at:  str
    sha256:       str
    size_bytes:   int
    cleartext:    Optional[str]
    file_path:    Optional[str] = None
    extra:        Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "id":          self.id,
            "doi_id":      self.doi_id,
            "doi_label":   self.doi_label,
            "severity":    self.severity,
            "source":      self.source,
            "target":      self.target,
            "captured_at": self.captured_at,
            "sha256":      self.sha256,
            "size_bytes":  self.size_bytes,
            "file_path":   self.file_path,
        }
        if self.cleartext is not None:
            d["cleartext_preview"] = self.cleartext[:120]
        if self.extra:
            d["extra"] = self.extra
        return d


# ════════════════════════════════════════════════════════════════════
# Pipeline
# ════════════════════════════════════════════════════════════════════

class ExfilPipeline:
    """Per-session loot collector + manifester.

    Owned by MasterAgent.  Every tool/shell output that's worth
    examining is fed into ``ingest()``.  The pipeline classifies,
    stages, and manifests.
    """

    DEFAULT_LOOT_ROOT = "/tmp/argus_loot"

    # Stable file-extension hints per DoI id, so a glance at the loot
    # directory tells the operator what each file contains.
    _EXT_BY_DOI = {
        "ssh_private_key":   ".id_rsa",
        "gcp_service_key":   ".json",
        "ntlm_hash":         ".ntlm",
        "kerberos_asrep":    ".asrep",
        "kerberos_tgs":      ".tgs",
        "bcrypt_hash":       ".bcrypt",
        "md5_passwd_line":   ".shadow",
        "aws_access_key":    ".aws",
        "aws_secret_key":    ".aws",
        "github_token":      ".token",
        "slack_token":       ".token",
        "azure_app_secret":  ".azure",
        "jwt_token":         ".jwt",
        "db_conn_string":    ".dburl",
        "env_dotenv_secret": ".env",
        "basic_auth_header": ".basicauth",
        "credit_card_pan":   ".pii",
        "ssn_us":            ".pii",
        "email_address":     ".email",
        "hardcoded_password": ".secret",
        "file_kdbx":         ".kdbx-ref",
        "file_pfx_pem":      ".cert-ref",
    }

    def __init__(
        self,
        *, session_id: str,
        target:        str,
        loot_root:     Optional[str] = None,
        emit_finding:  Optional[Callable[..., Any]] = None,
        custom_doi:    Optional[List[DataOfInterest]] = None,
    ) -> None:
        self.session_id    = session_id
        self.target        = target
        self.emit_finding  = emit_finding
        self._patterns     = list(DEFAULT_DOI_PATTERNS)
        if custom_doi:
            # Custom patterns take priority by being checked first.
            self._patterns = list(custom_doi) + self._patterns

        root = loot_root or self.DEFAULT_LOOT_ROOT
        self._loot_dir = os.path.join(root, session_id)
        try:
            os.makedirs(self._loot_dir, exist_ok=True)
        except Exception as exc:
            logger.warning("[ExfilPipeline] cannot create loot dir %s: %s",
                           self._loot_dir, exc)
        self._manifest_path = os.path.join(self._loot_dir, "manifest.jsonl")

        # In-memory mirror so the report generator can read from RAM.
        self.entries:       List[LootEntry] = []
        self._seen_hashes:  set             = set()

    # ── Public API ────────────────────────────────────────────────────
    def ingest(
        self,
        output: str,
        *, source: str = "unknown",
        tool:   str = "",
        host:   Optional[str] = None,
    ) -> List[LootEntry]:
        """Classify ``output`` against the DoI catalog and stage matches.

        Returns the list of LootEntry rows produced (possibly empty).
        Idempotent — duplicate content is detected by SHA256 and
        skipped.
        """
        if not output or not isinstance(output, str):
            return []
        target = host or self.target
        produced: List[LootEntry] = []

        for doi in self._patterns:
            try:
                matches = list(doi.pattern.finditer(output))
            except Exception as exc:
                logger.debug("[ExfilPipeline] regex error for %s: %s", doi.id, exc)
                continue
            for m in matches:
                raw = self._extract_match(m, doi.capture)
                if not raw:
                    continue
                raw_bytes = raw.encode("utf-8", errors="replace")
                digest = hashlib.sha256(raw_bytes).hexdigest()
                if digest in self._seen_hashes:
                    continue
                self._seen_hashes.add(digest)

                entry_id  = f"{doi.id}-{digest[:12]}"
                file_path = self._stage_to_disk(entry_id, doi, raw_bytes)

                entry = LootEntry(
                    id          = entry_id,
                    doi_id      = doi.id,
                    doi_label   = doi.label,
                    severity    = doi.severity,
                    source      = source if source else (tool or "unknown"),
                    target      = target,
                    captured_at = datetime.now(timezone.utc).isoformat(),
                    sha256      = digest,
                    size_bytes  = len(raw_bytes),
                    cleartext   = None if doi.redact_in_log else raw,
                    file_path   = file_path,
                    extra       = {"tool": tool} if tool else {},
                )
                self.entries.append(entry)
                produced.append(entry)
                self._append_manifest(entry)

                if callable(self.emit_finding):
                    try:
                        result = self.emit_finding(
                            title       = f"DoI captured: {doi.label}",
                            description = (
                                f"Pattern '{doi.id}' matched in output from "
                                f"{source or tool or 'unknown source'} on {target}. "
                                f"Size={len(raw_bytes)}B, SHA256={digest[:16]}…. "
                                f"{'Cleartext redacted from manifest.' if doi.redact_in_log else ''}"
                            ),
                            severity = doi.severity,
                            host     = target,
                            extra    = {"loot_entry": entry.to_dict()},
                        )
                        if asyncio.iscoroutine(result):
                            asyncio.create_task(result)
                    except Exception as exc:
                        logger.debug("[ExfilPipeline] emit_finding failed: %s", exc)

        if produced:
            logger.info(
                "[ExfilPipeline] ingested %d loot items from source=%s tool=%s host=%s",
                len(produced), source, tool, target,
            )
        return produced

    def manifest_summary(self) -> Dict[str, Any]:
        """Return aggregate stats — used by the report generator."""
        by_severity: Dict[str, int] = {}
        by_doi:      Dict[str, int] = {}
        for e in self.entries:
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            by_doi[e.doi_id]        = by_doi.get(e.doi_id, 0) + 1
        return {
            "loot_dir":      self._loot_dir,
            "manifest":      self._manifest_path,
            "total_entries": len(self.entries),
            "by_severity":   by_severity,
            "by_doi":        by_doi,
            "size_bytes":    sum(e.size_bytes for e in self.entries),
        }

    def list_entries(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

    def export_aggregate_loot(self) -> Dict[str, Any]:
        """Return loot organised in the shape lateral primer (#6) reads.

        The lateral primer's gate-checks look for these keys:
          * ssh_keys      — list of {path, key_blob, target}
          * nt_hashes     — list of {user, hash, target}
          * kerberos_tgts — list of {user, ticket}
        """
        out: Dict[str, List[Dict[str, Any]]] = {
            "ssh_keys":      [],
            "nt_hashes":     [],
            "kerberos_tgts": [],
            "kerberos_tgss": [],
            "secrets":       [],
        }
        for e in self.entries:
            if e.doi_id == "ssh_private_key":
                out["ssh_keys"].append({
                    "path":   e.file_path,
                    "sha256": e.sha256,
                    "target": e.target,
                })
            elif e.doi_id == "ntlm_hash" and e.cleartext is None:
                # cleartext was redacted in-log, but the file on disk has it
                try:
                    if e.file_path and os.path.exists(e.file_path):
                        with open(e.file_path, encoding="utf-8") as f:
                            line = f.read().strip()
                        # NT line format: user:rid:lm:nt:::
                        parts = line.split(":")
                        if len(parts) >= 4:
                            out["nt_hashes"].append({
                                "user":   parts[0],
                                "rid":    parts[1],
                                "hash":   parts[3],
                                "target": e.target,
                            })
                except Exception:
                    pass
            elif e.doi_id == "kerberos_asrep":
                out["kerberos_tgts"].append({
                    "hash_path": e.file_path, "target": e.target,
                })
            elif e.doi_id == "kerberos_tgs":
                out["kerberos_tgss"].append({
                    "hash_path": e.file_path, "target": e.target,
                })
            elif e.severity in ("high", "critical"):
                out["secrets"].append(e.to_dict())
        return out

    # ── Internal ──────────────────────────────────────────────────────
    @staticmethod
    def _extract_match(m: "re.Match", capture: str) -> str:
        """Pull the configured group from a regex match safely."""
        if not capture or capture == "0":
            return m.group(0) or ""
        try:
            v = m.group(capture)
            return v or ""
        except Exception:
            return m.group(0) or ""

    def _stage_to_disk(self, entry_id: str, doi: DataOfInterest, raw_bytes: bytes) -> Optional[str]:
        """Write the loot blob to the loot directory.  Returns the path
        on success, None on failure (logged but non-fatal)."""
        try:
            ext = self._EXT_BY_DOI.get(doi.id, ".loot")
            path = os.path.join(self._loot_dir, f"{entry_id}{ext}")
            with open(path, "wb") as f:
                f.write(raw_bytes)
            try:
                os.chmod(path, 0o600)   # operator-readable only
            except Exception:
                pass
            return path
        except Exception as exc:
            logger.warning("[ExfilPipeline] failed to stage %s: %s", entry_id, exc)
            return None

    def _append_manifest(self, entry: LootEntry) -> None:
        """Append a single JSONL line to the manifest."""
        try:
            with open(self._manifest_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")
        except Exception as exc:
            logger.warning("[ExfilPipeline] manifest append failed: %s", exc)
