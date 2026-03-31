"""
azure_enum_subagent.py — Azure subscription enumeration and privilege assessment.

AGENT_NAME  : "cloud"
SUBAGENT_NAME: "azure_enum"

Methodology:
  1. az account show — confirm identity and subscription
  2. az role assignment list — enumerate RBAC assignments
  3. az ad user list / az ad group list — enumerate AD objects
  4. az storage account list — find storage accounts + blob containers
  5. az vm list — enumerate VMs with public IPs
  6. az keyvault list + az keyvault secret list — check Key Vault access
  7. Check for Owner/Contributor role — immediate privilege escalation
"""
from __future__ import annotations
import json, logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_OWNER_RE    = re.compile(r'(Owner|Contributor|User Access Administrator)', re.I)
_STORAGE_RE  = re.compile(r'"name"\s*:\s*"([^"]+)"', re.I)
_VM_IP_RE    = re.compile(r'"ipAddress"\s*:\s*"([\d.]+)"', re.I)
_SECRET_RE   = re.compile(r'"id"\s*:\s*"[^"]*vaults[^"]*secrets[^"]*"', re.I)


class AzureEnumSubagent(BaseSubagent):
    """Enumerate Azure resources and assess privilege level."""

    AGENT_NAME    = "cloud"
    SUBAGENT_NAME = "azure_enum"

    async def run(self, target: str, subscription: str = "", **kwargs: Any) -> SubagentResult:
        result  = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        sub_flag = f"--subscription {subscription}" if subscription else ""

        # ── 1. Account identity ───────────────────────────────────────────
        acct_out = await self.collect_tool("az", target, {"options": f"account show {sub_flag} -o json 2>&1"})
        try:
            acct = json.loads(acct_out)
            sub_name = acct.get("name", "?")
            user     = acct.get("user", {}).get("name", "?")
        except Exception:
            sub_name, user = "?", "?"

        await self.store_finding(Finding(
            title=f"Azure: Authenticated as '{user}' on Subscription '{sub_name}'",
            description=f"Azure CLI credentials valid. Subscription: {sub_name}. User/SP: {user}.",
            severity="INFO", evidence=acct_out[:400], tool="az", host=target,
            mitre_technique="T1526",
        ))

        # ── 2. RBAC role assignments ──────────────────────────────────────
        roles_out = await self.collect_tool("az", target,
            {"options": f"role assignment list {sub_flag} --all -o json 2>&1"})
        high_roles = _OWNER_RE.findall(roles_out)
        if high_roles:
            await self.store_finding(Finding(
                title=f"Azure RBAC: High-Privilege Roles Found — {', '.join(set(high_roles))}",
                description=f"Subscription-level Owner or Contributor assignments detected. Role: {set(high_roles)}.",
                severity="CRITICAL", evidence=roles_out[:800], tool="az", host=target,
                mitre_technique="T1078.004",
                exploit_suggestion="With Owner role: az ad sp create-for-rbac to create new service principal or add user",
            ))

        # ── 3. Storage accounts + public blobs ────────────────────────────
        storage_out = await self.collect_tool("az", target,
            {"options": f"storage account list {sub_flag} -o json 2>&1"})
        storage_names = re.findall(r'"name"\s*:\s*"([a-z0-9]+)"', storage_out)

        for sa in storage_names[:5]:
            # Check public access
            keys_out = await self.collect_tool("az", target,
                {"options": f"storage account keys list --account-name {sa} {sub_flag} -o json 2>&1"})
            has_keys = "value" in keys_out.lower()
            # List containers
            cont_out = await self.collect_tool("az", target,
                {"options": f"storage container list --account-name {sa} {sub_flag} -o json 2>&1"})
            public_conts = re.findall(r'"name"\s*:\s*"([^"]+)".*?"publicAccess"\s*:\s*"(?!None)([^"]+)"', cont_out, re.S)

            if public_conts or has_keys:
                await self.store_finding(Finding(
                    title=f"Azure Storage: {'Public Container' if public_conts else 'Keys Accessible'} — {sa}",
                    description=f"Storage account '{sa}': keys accessible={has_keys}, public containers={[c[0] for c in public_conts[:3]]}.",
                    severity="HIGH", evidence=cont_out[:600], tool="az", host=target,
                    mitre_technique="T1530",
                    exploit_suggestion=f"Download: az storage blob download-batch -d /tmp/{sa} --account-name {sa} -s <container>",
                ))

        # ── 4. VMs with public IPs ────────────────────────────────────────
        vm_out = await self.collect_tool("az", target,
            {"options": f"vm list-ip-addresses {sub_flag} -o json 2>&1"})
        pub_ips = _VM_IP_RE.findall(vm_out)
        if pub_ips:
            await self.store_finding(Finding(
                title=f"Azure VMs: {len(pub_ips)} VM(s) with Public IPs",
                description=f"VMs with public IPs: {', '.join(pub_ips[:5])}. Lateral movement targets.",
                severity="MEDIUM", evidence=vm_out[:400], tool="az", host=target,
                mitre_technique="T1526",
            ))

        # ── 5. Key Vault secrets ──────────────────────────────────────────
        kv_out = await self.collect_tool("az", target,
            {"options": f"keyvault list {sub_flag} -o json 2>&1"})
        vaults = re.findall(r'"name"\s*:\s*"([^"]+)"', kv_out)
        for vault in vaults[:3]:
            secrets_out = await self.collect_tool("az", target,
                {"options": f"keyvault secret list --vault-name {vault} -o json 2>&1"})
            secret_names = re.findall(r'"id"\s*:\s*"[^"]*secrets/([^/"]+)"', secrets_out)
            if secret_names:
                await self.store_finding(Finding(
                    title=f"Azure Key Vault: {len(secret_names)} Secret(s) Accessible in '{vault}'",
                    description=f"Key Vault '{vault}' secrets accessible: {', '.join(secret_names[:5])}.",
                    severity="CRITICAL", evidence=secrets_out[:500], tool="az", host=target,
                    mitre_technique="T1552.001",
                    exploit_suggestion=f"Download: az keyvault secret show --vault-name {vault} --name <secret-name>",
                ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
