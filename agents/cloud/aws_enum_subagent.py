"""
aws_enum_subagent.py — AWS resource enumeration and privilege escalation.

AGENT_NAME  : "cloud"
SUBAGENT_NAME: "aws_enum"

Methodology:
  1. Enumerate IAM identity (sts:GetCallerIdentity)
  2. List IAM policies, roles, users, groups
  3. Enumerate S3 buckets (list + acl check for public buckets)
  4. Enumerate EC2 instances, security groups
  5. Enumerate Lambda functions
  6. Check for privilege escalation paths (iam:PassRole, iam:CreateAccessKey, etc.)
  7. Attempt S3 anonymous access on discovered buckets
"""
from __future__ import annotations
import json, logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_BUCKET_RE    = re.compile(r'"Name"\s*:\s*"([^"]+)"', re.I)
_PUBLIC_RE    = re.compile(r'(AllUsers|AuthenticatedUsers|READ|WRITE|FULL_CONTROL)', re.I)
_EC2_IP_RE    = re.compile(r'"PublicIpAddress"\s*:\s*"([\d.]+)"', re.I)
_ADMIN_POL_RE = re.compile(r'(AdministratorAccess|PowerUserAccess|\*:\*)', re.I)

# [64] An `aws sts get-caller-identity` ERROR is NOT proof of valid credentials — the
# identity finding must only fire on a real, parseable identity (Account + Arn).
_AWS_ERR_RE = re.compile(
    r"an error occurred|invalidclienttokenid|accessdenied|signaturedoesnotmatch|"
    r"unable to locate credentials|expiredtoken|authfailure|could not connect|"
    r"you must specify a region|invalidaccesskeyid", re.I)
_PRIVESC_RE   = re.compile(r'(iam:PassRole|iam:CreateAccessKey|iam:AttachUserPolicy|iam:PutUserPolicy|lambda:InvokeFunction)', re.I)


class AwsEnumSubagent(BaseSubagent):
    """Enumerate AWS resources and identify privilege escalation paths."""

    AGENT_NAME    = "cloud"
    SUBAGENT_NAME = "aws_enum"

    async def run(self, target: str, region: str = "us-east-1",
                  profile: str = "", **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        prof   = f"--profile {profile}" if profile else ""
        reg    = f"--region {region}"
        base   = f"aws {prof} {reg}"

        # ── 1. Identity ───────────────────────────────────────────────────
        ident_out = await self.collect_tool("aws", target,
            {"options": f"{prof} {reg} sts get-caller-identity --output json 2>&1"})
        try:
            ident = json.loads(ident_out)
            account = ident.get("Account")
            arn     = ident.get("Arn")
        except Exception:
            account, arn = None, None

        # [64] Only report a confirmed identity when the call returned a REAL one — an error
        # (InvalidClientTokenId / AccessDenied / "Unable to locate credentials") is not valid
        # creds, so it must never be shipped as "Credentials are valid".
        _authed = bool(account and arn and not _AWS_ERR_RE.search(ident_out))
        if _authed:
            await self.store_finding(Finding(
                title=f"AWS: Identity Confirmed — Account {account}",
                description=f"AWS caller identity: ARN={arn}, Account={account}. Credentials are valid.",
                severity="INFO", evidence=ident_out[:300], tool="aws", host=target,
                mitre_technique="T1526",
            ))

        # ── 2. IAM enumeration ────────────────────────────────────────────
        users_out  = await self.collect_tool("aws", target, {"options": f"{prof} {reg} iam list-users --output json 2>&1"})
        roles_out  = await self.collect_tool("aws", target, {"options": f"{prof} {reg} iam list-roles --output json 2>&1"})
        pol_out    = await self.collect_tool("aws", target, {"options": f"{prof} {reg} iam list-policies --scope Local --output json 2>&1"})

        admin_found = bool(_ADMIN_POL_RE.search(pol_out + roles_out))
        privesc     = bool(_PRIVESC_RE.search(pol_out + roles_out))

        if admin_found:
            await self.store_finding(Finding(
                title="AWS IAM: Admin-Level Policy or Role Detected",
                description="AdministratorAccess or wildcard (*:*) policy found in IAM. Could be attached to current identity for privilege escalation.",
                severity="CRITICAL", evidence=pol_out[:800], tool="aws", host=target,
                mitre_technique="T1078.004",
                exploit_suggestion="Check if policy is attached to current role: aws iam list-attached-user-policies --user-name <user>",
            ))

        if privesc:
            await self.store_finding(Finding(
                title="AWS IAM: Privilege Escalation Path Detected",
                description=f"Dangerous IAM permissions found that enable privilege escalation: {_PRIVESC_RE.findall(pol_out + roles_out)[:5]}",
                severity="HIGH", evidence=pol_out[:600], tool="aws", host=target,
                mitre_technique="T1078.004",
                exploit_suggestion="Use Pacu or enumerate: aws iam create-access-key --user-name <admin_user>",
            ))

        # ── 3. S3 bucket enumeration ──────────────────────────────────────
        s3_out = await self.collect_tool("aws", target, {"options": f"{prof} {reg} s3api list-buckets --output json 2>&1"})
        buckets = _BUCKET_RE.findall(s3_out)

        for bucket in buckets[:10]:
            acl_out = await self.collect_tool("aws", target,
                {"options": f"{prof} s3api get-bucket-acl --bucket {bucket} --output json 2>&1"})
            public = bool(_PUBLIC_RE.search(acl_out))

            # Try anonymous list
            anon_out = await self.collect_tool("aws", target,
                {"options": f"s3 ls s3://{bucket} --no-sign-request 2>&1"})
            anon_readable = "PRE " in anon_out or (len(anon_out.strip()) > 10 and "Error" not in anon_out and "AccessDenied" not in anon_out)

            if public or anon_readable:
                await self.store_finding(Finding(
                    title=f"AWS S3: Public Bucket — s3://{bucket}",
                    description=f"S3 bucket '{bucket}' is publicly accessible. Anonymous listing: {anon_readable}. ACL public grant: {public}.",
                    severity="HIGH",
                    evidence=f"ACL:\n{acl_out[:400]}\nAnon list:\n{anon_out[:300]}",
                    tool="aws", host=target, mitre_technique="T1530",
                    exploit_suggestion=f"Download: aws s3 sync s3://{bucket} /tmp/{bucket} --no-sign-request",
                ))

        # ── 4. EC2 instances ──────────────────────────────────────────────
        ec2_out = await self.collect_tool("aws", target,
            {"options": f"{prof} {reg} ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,State.Name,Tags]' --output json 2>&1"})
        public_ips = _EC2_IP_RE.findall(ec2_out)
        if public_ips:
            await self.store_finding(Finding(
                title=f"AWS EC2: {len(public_ips)} Instance(s) with Public IPs",
                description=f"EC2 instances with public IPs discovered: {', '.join(public_ips[:5])}. These are potential lateral movement targets.",
                severity="MEDIUM", evidence=ec2_out[:600], tool="aws", host=target,
                mitre_technique="T1526",
                exploit_suggestion="Scan discovered IPs for open ports, check security group rules: aws ec2 describe-security-groups",
            ))

        # ── 5. Lambda functions ───────────────────────────────────────────
        lambda_out = await self.collect_tool("aws", target,
            {"options": f"{prof} {reg} lambda list-functions --output json 2>&1"})
        fn_names = re.findall(r'"FunctionName"\s*:\s*"([^"]+)"', lambda_out)
        if fn_names:
            await self.store_finding(Finding(
                title=f"AWS Lambda: {len(fn_names)} Function(s) Enumerated",
                description=f"Lambda functions found: {', '.join(fn_names[:5])}. Check for hardcoded secrets in env vars or insecure triggers.",
                severity="MEDIUM", evidence=lambda_out[:600], tool="aws", host=target,
                mitre_technique="T1526",
                exploit_suggestion="Check env vars: aws lambda get-function-configuration --function-name <name> | grep -i 'env\\|secret\\|key'",
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
