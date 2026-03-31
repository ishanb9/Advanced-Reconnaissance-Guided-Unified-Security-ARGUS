"""
gcp_enum_subagent.py — GCP project enumeration and IAM assessment.

AGENT_NAME  : "cloud"
SUBAGENT_NAME: "gcp_enum"

Methodology:
  1. gcloud config / auth list — confirm identity
  2. gcloud projects list — enumerate accessible projects
  3. gcloud iam roles / bindings — enumerate IAM permissions
  4. gsutil ls — enumerate GCS buckets, check for public access
  5. gcloud compute instances list — enumerate VMs
  6. gcloud secrets list — Secret Manager enumeration
  7. gcloud functions list — Cloud Functions
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_OWNER_RE   = re.compile(r'(roles/owner|roles/editor|roles/iam\.admin)', re.I)
_PUBLIC_RE  = re.compile(r'(allUsers|allAuthenticatedUsers)', re.I)
_IP_RE      = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
_SECRET_RE  = re.compile(r'NAME:\s*(\S+)', re.I)


class GcpEnumSubagent(BaseSubagent):
    """Enumerate GCP project resources and IAM configuration."""

    AGENT_NAME    = "cloud"
    SUBAGENT_NAME = "gcp_enum"

    async def run(self, target: str, project: str = "", **kwargs: Any) -> SubagentResult:
        result   = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        proj_flag = f"--project {project}" if project else ""

        # ── 1. Auth identity ──────────────────────────────────────────────
        auth_out = await self.collect_tool("gcloud", target, {"options": f"auth list --format=json 2>&1"})
        cfg_out  = await self.collect_tool("gcloud", target, {"options": f"config list --format=json 2>&1"})
        await self.store_finding(Finding(
            title="GCP: Authenticated Identity Confirmed",
            description=f"gcloud credentials valid. Config: {cfg_out[:200]}",
            severity="INFO", evidence=auth_out[:300], tool="gcloud", host=target,
            mitre_technique="T1526",
        ))

        # ── 2. Projects ───────────────────────────────────────────────────
        proj_out = await self.collect_tool("gcloud", target, {"options": "projects list --format=json 2>&1"})
        projects = re.findall(r'"projectId"\s*:\s*"([^"]+)"', proj_out)
        if not project and projects:
            project   = projects[0]
            proj_flag = f"--project {project}"

        # ── 3. IAM policy ─────────────────────────────────────────────────
        iam_out = await self.collect_tool("gcloud", target,
            {"options": f"projects get-iam-policy {project} --format=json 2>&1"})
        high_roles = _OWNER_RE.findall(iam_out)
        public_iam = bool(_PUBLIC_RE.search(iam_out))

        if high_roles:
            await self.store_finding(Finding(
                title=f"GCP IAM: Owner/Editor Role Binding Found",
                description=f"High-privilege IAM roles: {set(high_roles)}.",
                severity="CRITICAL", evidence=iam_out[:600], tool="gcloud", host=target,
                mitre_technique="T1078.004",
                exploit_suggestion="Add self: gcloud projects add-iam-policy-binding PROJECT --member=user:YOU --role=roles/owner",
            ))

        # ── 4. GCS buckets ────────────────────────────────────────────────
        buckets_out = await self.collect_tool("gsutil", target, {"options": "ls 2>&1"})
        buckets = re.findall(r'gs://([^\s/]+)', buckets_out)
        for bucket in buckets[:10]:
            acl_out = await self.collect_tool("gsutil", target, {"options": f"acl get gs://{bucket} 2>&1"})
            public  = bool(_PUBLIC_RE.search(acl_out))
            if public:
                await self.store_finding(Finding(
                    title=f"GCP GCS: Public Bucket — gs://{bucket}",
                    description=f"GCS bucket gs://{bucket} has allUsers or allAuthenticatedUsers access.",
                    severity="HIGH", evidence=acl_out[:400], tool="gsutil", host=target,
                    mitre_technique="T1530",
                    exploit_suggestion=f"Download: gsutil -m cp -r gs://{bucket} /tmp/{bucket}",
                ))

        # ── 5. Compute instances ──────────────────────────────────────────
        vm_out = await self.collect_tool("gcloud", target,
            {"options": f"compute instances list {proj_flag} --format=json 2>&1"})
        pub_ips = _IP_RE.findall(vm_out)
        nat_ips = [ip for ip in pub_ips if not ip.startswith(("10.", "172.", "192.168."))]
        if nat_ips:
            await self.store_finding(Finding(
                title=f"GCP Compute: {len(nat_ips)} Instance(s) with External IPs",
                description=f"GCP VMs with external IPs: {', '.join(nat_ips[:5])}.",
                severity="MEDIUM", evidence=vm_out[:400], tool="gcloud", host=target,
                mitre_technique="T1526",
            ))

        # ── 6. Secret Manager ─────────────────────────────────────────────
        secrets_out = await self.collect_tool("gcloud", target,
            {"options": f"secrets list {proj_flag} --format=json 2>&1"})
        secret_names = re.findall(r'"name"\s*:\s*"[^"]*/secrets/([^"]+)"', secrets_out)
        if secret_names:
            await self.store_finding(Finding(
                title=f"GCP Secret Manager: {len(secret_names)} Secret(s) Accessible",
                description=f"Secrets: {', '.join(secret_names[:5])}.",
                severity="CRITICAL", evidence=secrets_out[:400], tool="gcloud", host=target,
                mitre_technique="T1552.001",
                exploit_suggestion=f"Access: gcloud secrets versions access latest --secret={secret_names[0]} {proj_flag}",
            ))

        # ── 7. Cloud Functions ────────────────────────────────────────────
        fn_out = await self.collect_tool("gcloud", target,
            {"options": f"functions list {proj_flag} --format=json 2>&1"})
        fn_names = re.findall(r'"name"\s*:\s*"[^"]*/functions/([^"]+)"', fn_out)
        if fn_names:
            await self.store_finding(Finding(
                title=f"GCP Cloud Functions: {len(fn_names)} Function(s) Found",
                description=f"Cloud Functions: {', '.join(fn_names[:5])}. Check triggers for SSRF/injection and env vars for secrets.",
                severity="MEDIUM", evidence=fn_out[:400], tool="gcloud", host=target,
                mitre_technique="T1526",
                exploit_suggestion="Inspect env: gcloud functions describe <name> --format=json | grep -i env",
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
