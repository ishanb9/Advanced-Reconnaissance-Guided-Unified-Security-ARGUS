"""
ssl_audit_subagent.py — SSL/TLS configuration audit for HTTPS services.

Methodology:
  1. For each HTTPS/SSL service in services_list kwarg:
     a. Run sslscan --no-colour target:port
     b. Run testssl.sh --fast target:port
     c. Run nmap SSL scripts (heartbleed, poodle, ccs-injection, dh-params, enum-ciphers)
  2. Parse: supported protocols, cipher suites, certificate info, vulnerabilities
  3. Findings: CRITICAL for Heartbleed/POODLE/BEAST; HIGH for weak ciphers/expired cert;
               MEDIUM for self-signed/old TLS; LOW for missing HSTS
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_HEARTBLEED_RE = re.compile(
    r"(heartbleed|VULNERABLE|CVE-2014-0160)", re.IGNORECASE
)

# [50] A TLS vuln is CONFIRMED only when the scanner emits an explicit VULNERABLE VERDICT
# for it — nmap NSE "State: VULNERABLE" / a "VULNERABLE:" result block, testssl
# "VULNERABLE (NOT ok)", or "vulnerable to <x>" — NOT the bare test NAME (nmap echoes every
# --script name it runs, and prints "ssl-heartbleed:" headers) nor a lone "VULNERABLE"
# keyword.  Stops a CRITICAL CVE being minted from a tool test-name.
_SSL_VERDICT_POS_RE = re.compile(
    r"state:\s*vulnerable|vulnerable \(not ok\)|^\s*\|?\s*vulnerable:\s*$|\bis vulnerable\b|"
    r"vulnerable to\b", re.I | re.M)
_SSL_VERDICT_NEG_RE = re.compile(
    r"not vulnerable|likely safe|state:\s*(?:not|likely)\b|no ssl|not offered|offers no", re.I)


def _confirmed_ssl_vuln(text: str, *terms: str) -> bool:
    """True only when the scanner explicitly flagged one of ``terms`` as VULNERABLE — a
    positive verdict within a short window of the term, with no negation nearby — never
    from the test name or a bare keyword alone.  Pure + unit-testable."""
    t = text or ""
    for term in terms:
        for m in re.finditer(re.escape(term), t, re.I):
            win = t[max(0, m.start() - 60): m.end() + 320]
            if _SSL_VERDICT_POS_RE.search(win) and not _SSL_VERDICT_NEG_RE.search(win):
                return True
    return False
_POODLE_RE = re.compile(
    r"(poodle|VULNERABLE to POODLE|CVE-2014-3566)", re.IGNORECASE
)
_BEAST_RE = re.compile(
    r"(BEAST|CVE-2011-3389)", re.IGNORECASE
)
_CCS_RE = re.compile(
    r"(CCS injection|CVE-2014-0224|openssl ccs)", re.IGNORECASE
)
_CRIME_RE = re.compile(
    r"(CRIME|CVE-2012-4929)", re.IGNORECASE
)
_DROWN_RE = re.compile(
    r"(DROWN|CVE-2016-0800)", re.IGNORECASE
)
_LOGJAM_RE = re.compile(
    r"(LOGJAM|CVE-2015-4000|weak dh)", re.IGNORECASE
)
_WEAK_CIPHER_RE = re.compile(
    r"\b(RC4|DES\b|3DES|EXPORT|NULL|anon|ADH|AECDH|IDEA)\b", re.IGNORECASE
)
_EXPIRED_RE = re.compile(
    r"(expired|NOT after.*\d{4}.*before|certificate.*expired)", re.IGNORECASE
)
_SELF_SIGNED_RE = re.compile(
    r"(self.?signed|Self Signed|unable to get local issuer)", re.IGNORECASE
)
_SSLV2_RE = re.compile(r"SSLv2\s+(enabled|accepted|supported)", re.IGNORECASE)
_SSLV3_RE = re.compile(r"SSLv3\s+(enabled|accepted|supported)", re.IGNORECASE)
_TLSV10_RE = re.compile(r"TLSv1\.0\s+(enabled|accepted|supported)", re.IGNORECASE)
_HSTS_RE = re.compile(r"(Strict-Transport-Security|HSTS)", re.IGNORECASE)
_CERT_CN_RE = re.compile(r"(?:Subject|CN)\s*[:=]\s*([^\n,/]+)", re.IGNORECASE)
_CERT_EXPIRY_RE = re.compile(
    r"Not After\s*:\s*(.+)", re.IGNORECASE
)
_DH_BITS_RE = re.compile(r"DH\s+(?:param(?:eter)?s?)?\s+(\d+)\s*bits?", re.IGNORECASE)


def _detect_weak_ciphers(output: str) -> list[str]:
    """Return a list of weak cipher names found in output."""
    return list({
        m.group(0).upper()
        for m in _WEAK_CIPHER_RE.finditer(output)
    })


class SslAuditSubagent(BaseSubagent):
    """
    SSL/TLS configuration audit for HTTPS and other SSL-wrapped services.

    Combines sslscan, testssl.sh, and nmap SSL scripts to detect protocol
    weaknesses, insecure cipher suites, certificate issues, and known
    SSL vulnerabilities such as Heartbleed, POODLE, and BEAST.
    """

    AGENT_NAME    = "vuln"
    SUBAGENT_NAME = "ssl_audit"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:  # noqa: C901
        """
        Audit SSL/TLS for all HTTPS services in services_list.

        Parameters
        ----------
        target:
            IP address or hostname.
        services_list:
            List of dicts with keys: port (int), service (str), version (str).
            Only services whose service name contains 'https', 'ssl', 'tls',
            or which run on ports 443/8443/4443 are audited.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )
        wall_start = time.monotonic()

        services_list: list[dict] = kwargs.get("services_list", [])

        _SSL_PORTS    = {443, 8443, 4443, 8080, 9443, 9200}
        _SSL_KEYWORDS = {"https", "ssl", "tls", "smtps", "imaps", "pop3s",
                         "ftps", "ldaps"}

        ssl_services = [
            s for s in services_list
            if int(s.get("port", 0)) in _SSL_PORTS
            or any(kw in str(s.get("service", "")).lower() for kw in _SSL_KEYWORDS)
        ]

        if not ssl_services:
            # Attempt default port 443
            ssl_services = [{"port": 443, "service": "https", "version": ""}]

        for svc in ssl_services:
            port = svc.get("port", 443)
            host_port = f"{target}:{port}"

            # ── sslscan ──────────────────────────────────────────────────
            logger.info("[ssl_audit] sslscan %s", host_port)
            sslscan_out = ""
            try:
                sslscan_out = await self.collect_tool(
                    "sslscan",
                    target,
                    {"options": f"--no-colour {host_port}"},
                )
            except Exception as exc:
                logger.warning("[ssl_audit] sslscan error on %s: %s", host_port, exc)

            # ── testssl.sh ───────────────────────────────────────────────
            logger.info("[ssl_audit] testssl.sh %s", host_port)
            testssl_out = ""
            try:
                testssl_out = await self.collect_tool(
                    "testssl",
                    target,
                    {"options": f"--fast --color 0 {host_port}"},
                )
            except Exception as exc:
                logger.warning("[ssl_audit] testssl error on %s: %s", host_port, exc)

            # ── nmap SSL scripts ─────────────────────────────────────────
            logger.info("[ssl_audit] nmap ssl scripts on port %s", port)
            nmap_ssl_out = ""
            try:
                nmap_ssl_out = await self.collect_tool(
                    "nmap",
                    target,
                    {
                        "options": (
                            f"--script=ssl-heartbleed,ssl-poodle,ssl-ccs-injection,"
                            f"ssl-dh-params,ssl-enum-ciphers "
                            f"-p {port} {target}"
                        )
                    },
                )
            except Exception as exc:
                logger.warning("[ssl_audit] nmap ssl scripts error: %s", exc)

            combined = "\n".join([sslscan_out, testssl_out, nmap_ssl_out])

            # ── Parse and emit findings ───────────────────────────────────

            # Heartbleed (CRITICAL) — gated on an explicit VULNERABLE verdict [50]
            if _confirmed_ssl_vuln(combined, "heartbleed", "CVE-2014-0160"):
                await self.store_finding(Finding(
                    title=f"Heartbleed (CVE-2014-0160) on {host_port}",
                    description=(
                        f"The SSL service on {host_port} is vulnerable to Heartbleed "
                        f"(CVE-2014-0160). An attacker can read up to 64 KB of server "
                        f"memory per request, potentially exposing private keys, session "
                        f"tokens, and credentials."
                    ),
                    severity="CRITICAL",
                    evidence=combined[:3000],
                    tool="sslscan+nmap",
                    host=target,
                    port=int(port),
                    cve="CVE-2014-0160",
                    mitre_technique="T1040",
                    exploit_suggestion="MSF: auxiliary/scanner/ssl/openssl_heartbleed",
                ))

            # POODLE (CRITICAL) — gated on an explicit VULNERABLE verdict [50]
            if _confirmed_ssl_vuln(combined, "poodle", "CVE-2014-3566"):
                await self.store_finding(Finding(
                    title=f"POODLE (CVE-2014-3566) on {host_port}",
                    description=(
                        f"The SSL service on {host_port} is vulnerable to POODLE "
                        f"(CVE-2014-3566). SSLv3 is enabled, allowing a man-in-the-middle "
                        f"to downgrade connections and decrypt HTTPS cookies."
                    ),
                    severity="CRITICAL",
                    evidence=combined[:2000],
                    tool="sslscan+testssl",
                    host=target,
                    port=int(port),
                    cve="CVE-2014-3566",
                    mitre_technique="T1040",
                    exploit_suggestion="Disable SSLv3 server-side. No direct MSF module.",
                ))

            # BEAST (CRITICAL) — gated on an explicit VULNERABLE verdict [50]
            if _confirmed_ssl_vuln(combined, "BEAST", "CVE-2011-3389"):
                await self.store_finding(Finding(
                    title=f"BEAST (CVE-2011-3389) on {host_port}",
                    description=(
                        f"The service on {host_port} supports TLS 1.0 with CBC cipher "
                        f"suites, making it vulnerable to the BEAST attack (CVE-2011-3389)."
                    ),
                    severity="CRITICAL",
                    evidence=combined[:2000],
                    tool="testssl",
                    host=target,
                    port=int(port),
                    cve="CVE-2011-3389",
                    mitre_technique="T1040",
                    exploit_suggestion="Disable TLS 1.0 and prefer TLS 1.2+ with GCM ciphers.",
                ))

            # CCS Injection (CRITICAL) — gated on an explicit VULNERABLE verdict [50]
            if _confirmed_ssl_vuln(combined, "ccs injection", "openssl ccs", "CVE-2014-0224"):
                await self.store_finding(Finding(
                    title=f"OpenSSL CCS Injection (CVE-2014-0224) on {host_port}",
                    description=(
                        f"The service on {host_port} is vulnerable to OpenSSL CCS Injection "
                        f"(CVE-2014-0224), allowing MITM decryption of SSL/TLS traffic."
                    ),
                    severity="CRITICAL",
                    evidence=combined[:2000],
                    tool="nmap_ssl-ccs-injection",
                    host=target,
                    port=int(port),
                    cve="CVE-2014-0224",
                    mitre_technique="T1040",
                    exploit_suggestion="Patch OpenSSL. MSF: auxiliary/scanner/ssl/openssl_ccs.",
                ))

            # Weak ciphers (HIGH)
            weak_ciphers = _detect_weak_ciphers(combined)
            if weak_ciphers:
                await self.store_finding(Finding(
                    title=f"Weak Cipher Suites on {host_port}: {', '.join(weak_ciphers[:5])}",
                    description=(
                        f"The SSL service on {host_port} supports cryptographically weak "
                        f"cipher suites: {', '.join(weak_ciphers)}. These ciphers can be "
                        f"exploited by sufficiently resourced attackers to decrypt traffic."
                    ),
                    severity="HIGH",
                    evidence=combined[:2000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion=(
                        "Configure server to reject weak ciphers. "
                        "Use openssl-ciphers to enumerate preferred suites."
                    ),
                ))

            # Expired certificate (HIGH)
            if _EXPIRED_RE.search(combined):
                expiry_m = _CERT_EXPIRY_RE.search(combined)
                expiry_str = expiry_m.group(1).strip() if expiry_m else "unknown date"
                await self.store_finding(Finding(
                    title=f"Expired SSL Certificate on {host_port}",
                    description=(
                        f"The SSL certificate on {host_port} has expired (Not After: "
                        f"{expiry_str}). Expired certificates can facilitate MITM attacks "
                        f"as clients may accept invalid certificates."
                    ),
                    severity="HIGH",
                    evidence=combined[:1000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion="Replace the certificate with a valid, unexpired one.",
                ))

            # Self-signed certificate (MEDIUM)
            if _SELF_SIGNED_RE.search(combined):
                cn_m = _CERT_CN_RE.search(combined)
                cn = cn_m.group(1).strip() if cn_m else "unknown"
                await self.store_finding(Finding(
                    title=f"Self-Signed Certificate on {host_port} (CN={cn})",
                    description=(
                        f"The SSL certificate on {host_port} is self-signed and not trusted "
                        f"by a public CA. Users may ignore certificate warnings, enabling MITM."
                    ),
                    severity="MEDIUM",
                    evidence=combined[:1000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion="Replace with a CA-signed certificate (e.g., Let's Encrypt).",
                ))

            # Old TLS (1.0/1.1) or SSLv2/v3 (MEDIUM)
            if _SSLV2_RE.search(combined):
                await self.store_finding(Finding(
                    title=f"SSLv2 Enabled on {host_port}",
                    description=(
                        f"SSLv2 is enabled on {host_port}. SSLv2 is cryptographically broken "
                        f"and its use exposes the service to DROWN and similar attacks."
                    ),
                    severity="CRITICAL",
                    evidence=combined[:1000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    cve="CVE-2016-0800",
                    mitre_technique="T1040",
                    exploit_suggestion="Disable SSLv2 immediately. MSF: auxiliary/scanner/ssl/drown.",
                ))

            if _SSLV3_RE.search(combined):
                await self.store_finding(Finding(
                    title=f"SSLv3 Enabled on {host_port}",
                    description=(
                        f"SSLv3 is enabled on {host_port}. SSLv3 is vulnerable to POODLE "
                        f"and other attacks."
                    ),
                    severity="MEDIUM",
                    evidence=combined[:1000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion="Disable SSLv3 and prefer TLS 1.2+.",
                ))

            if _TLSV10_RE.search(combined) and not _BEAST_RE.search(combined):
                await self.store_finding(Finding(
                    title=f"TLS 1.0 Supported on {host_port}",
                    description=(
                        f"TLS 1.0 is supported on {host_port}. TLS 1.0 is deprecated "
                        f"(RFC 8996) and vulnerable to BEAST and related attacks."
                    ),
                    severity="MEDIUM",
                    evidence=combined[:1000],
                    tool="sslscan",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion="Disable TLS 1.0; require TLS 1.2 or TLS 1.3.",
                ))

            # Weak DH (MEDIUM/HIGH)
            dh_m = _DH_BITS_RE.search(combined)
            if dh_m:
                dh_bits = int(dh_m.group(1))
                if dh_bits < 2048:
                    await self.store_finding(Finding(
                        title=f"Weak DH Parameters ({dh_bits} bits) on {host_port}",
                        description=(
                            f"The service on {host_port} uses Diffie-Hellman parameters "
                            f"of only {dh_bits} bits. Parameters below 2048 bits are "
                            f"vulnerable to the Logjam attack (CVE-2015-4000)."
                        ),
                        severity="HIGH" if dh_bits < 1024 else "MEDIUM",
                        evidence=combined[:1000],
                        tool="nmap_ssl-dh-params",
                        host=target,
                        port=int(port),
                        cve="CVE-2015-4000",
                        mitre_technique="T1040",
                        exploit_suggestion="Generate fresh 2048-bit (or larger) DH parameters.",
                    ))

            # Missing HSTS (LOW)
            if not _HSTS_RE.search(combined):
                await self.store_finding(Finding(
                    title=f"Missing HSTS Header on {host_port}",
                    description=(
                        f"The HTTPS service on {host_port} does not return a "
                        f"Strict-Transport-Security (HSTS) header. Without HSTS, "
                        f"browsers may connect over plain HTTP if tricked."
                    ),
                    severity="LOW",
                    evidence="No 'Strict-Transport-Security' header found in testssl output.",
                    tool="testssl",
                    host=target,
                    port=int(port),
                    mitre_technique="T1040",
                    exploit_suggestion="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                ))

        # ── Finalise result ───────────────────────────────────────────────
        result.findings         = self._findings
        result.tool_outputs     = self._tool_outputs
        result.duration_seconds = time.monotonic() - wall_start

        await self._emit(
            "ssl_audit_complete",
            {
                "target": target,
                "services_checked": len(ssl_services),
                "findings": len(self._findings),
                "duration_seconds": round(result.duration_seconds, 2),
            },
        )
        logger.info(
            "[ssl_audit] complete — %d services, %d findings, %.1fs",
            len(ssl_services), len(self._findings), result.duration_seconds,
        )
        return result
