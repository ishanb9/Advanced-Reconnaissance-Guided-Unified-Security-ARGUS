"""
docker_audit_subagent.py — Docker daemon security audit.

AGENT_NAME  : "container"
SUBAGENT_NAME: "docker_audit"

Methodology:
  1. Check Docker socket exposure and daemon config
  2. List running containers — privileged, capabilities, mounts, network mode
  3. Inspect images for hardcoded secrets / env vars
  4. Check Docker API exposure on TCP (2375/2376)
  5. Run docker-bench-security if available
  6. Enumerate Docker volumes and network bridges
"""
from __future__ import annotations
import json, logging, re
from typing import Any
from agents.base_subagent import BaseSubagent, Finding, SubagentResult

logger = logging.getLogger(__name__)

_PRIV_RE    = re.compile(r'"Privileged"\s*:\s*true', re.I)
_SOCK_RE    = re.compile(r'docker\.sock', re.I)
_SECRET_RE  = re.compile(r'(PASSWORD|SECRET|TOKEN|API_KEY|AWS_)\s*=\s*\S+', re.I)
_NET_HOST_RE = re.compile(r'"NetworkMode"\s*:\s*"host"', re.I)
_CAP_RE     = re.compile(r'"CapAdd"\s*:\s*\[[^\]]+\]', re.I)


class DockerAuditSubagent(BaseSubagent):
    """Audit Docker daemon and container configurations for security issues."""

    AGENT_NAME    = "container"
    SUBAGENT_NAME = "docker_audit"

    async def run(self, target: str, **kwargs: Any) -> SubagentResult:
        result = SubagentResult(session_id=self.session_id, subagent_name=self.SUBAGENT_NAME, target=target)

        # ── 1. Docker socket / API exposure ──────────────────────────────
        sock_out = await self.collect_tool("bash", target,
            {"options": "-c \"ls -la /var/run/docker.sock 2>/dev/null; "
                        "curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>/dev/null | head -5\""})
        tcp_out = await self.collect_tool("curl", target,
            {"options": f"-s --connect-timeout 3 http://{target}:2375/version 2>&1"})
        tcp_tls = await self.collect_tool("curl", target,
            {"options": f"-sk --connect-timeout 3 https://{target}:2376/version 2>&1"})

        if "ApiVersion" in sock_out or "ApiVersion" in tcp_out:
            exposed_via = "UNIX socket" if "ApiVersion" in sock_out else f"TCP port 2375 on {target}"
            await self.store_finding(Finding(
                title=f"Docker: Daemon API Exposed via {exposed_via}",
                description=f"Docker API accessible without authentication via {exposed_via}. Full container control possible.",
                severity="CRITICAL",
                evidence=(sock_out + tcp_out)[:600], tool="curl", host=target,
                mitre_technique="T1610",
                exploit_suggestion=f"Escape: docker -H tcp://{target}:2375 run -v /:/host -it --rm alpine chroot /host sh" if "TCP" in exposed_via
                                  else "Escape: docker -H unix:///var/run/docker.sock run -v /:/host -it --rm alpine chroot /host sh",
            ))

        # ── 2. Running container inspection ──────────────────────────────
        ps_out = await self.collect_tool("docker", target, {"options": "ps --no-trunc -q 2>&1"})
        container_ids = [l.strip() for l in ps_out.splitlines() if len(l.strip()) == 64]

        for cid in container_ids[:10]:
            inspect_out = await self.collect_tool("docker", target, {"options": f"inspect {cid} 2>&1"})

            privileged  = bool(_PRIV_RE.search(inspect_out))
            sock_mount  = bool(_SOCK_RE.search(inspect_out))
            host_net    = bool(_NET_HOST_RE.search(inspect_out))
            caps        = _CAP_RE.findall(inspect_out)
            env_secrets = _SECRET_RE.findall(inspect_out)

            issues = []
            if privileged:  issues.append("PRIVILEGED")
            if sock_mount:  issues.append("DOCKER_SOCK_MOUNTED")
            if host_net:    issues.append("HOST_NETWORK")
            if caps:        issues.append(f"CAPS:{caps[0][:50]}")
            if env_secrets: issues.append(f"SECRETS_IN_ENV:{len(env_secrets)}")

            if issues:
                sev = "CRITICAL" if privileged or sock_mount else "HIGH"
                await self.store_finding(Finding(
                    title=f"Docker Container {cid[:12]}: Security Issues — {', '.join(issues)}",
                    description=f"Container {cid[:12]} has dangerous configuration: {', '.join(issues)}. "
                                f"Env secrets found: {env_secrets[:3]}",
                    severity=sev,
                    evidence=inspect_out[:800], tool="docker", host=target,
                    mitre_technique="T1611",
                    exploit_suggestion="Privileged: docker exec <id> nsenter --target 1 --mount --uts --ipc --net --pid -- bash" if privileged else
                                      "Socket mount: docker exec <id> docker run -v /:/host -it alpine chroot /host sh",
                ))

        # ── 3. docker-bench-security ──────────────────────────────────────
        bench_out = await self.collect_tool("bash", target,
            {"options": "-c \"docker run --rm --net host --pid host --userns host --cap-add audit_control "
                        "-v /etc:/etc:ro -v /usr/bin/containerd:/usr/bin/containerd:ro "
                        "-v /usr/bin/runc:/usr/bin/runc:ro -v /usr/lib/systemd:/usr/lib/systemd:ro "
                        "-v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro "
                        "--label docker_bench_security docker/docker-bench-security 2>&1 | tail -30\""})

        warn_count = bench_out.count("[WARN]")
        if warn_count > 0:
            await self.store_finding(Finding(
                title=f"Docker Bench Security: {warn_count} Warning(s) Found",
                description=f"docker-bench-security identified {warn_count} configuration warnings. Review output for CIS Docker benchmark failures.",
                severity="MEDIUM", evidence=bench_out[:1000], tool="docker", host=target,
                mitre_technique="T1610",
            ))

        # ── 4. Images with secrets in ENV ─────────────────────────────────
        images_out = await self.collect_tool("docker", target, {"options": "images --no-trunc -q 2>&1"})
        image_ids  = [l.strip() for l in images_out.splitlines() if l.strip().startswith("sha256:")]
        for img_id in image_ids[:5]:
            img_inspect = await self.collect_tool("docker", target, {"options": f"inspect {img_id} 2>&1"})
            img_secrets = _SECRET_RE.findall(img_inspect)
            if img_secrets:
                await self.store_finding(Finding(
                    title=f"Docker Image {img_id[:20]}: Secrets in ENV Layer",
                    description=f"Docker image has secrets baked into ENV layers: {img_secrets[:3]}.",
                    severity="HIGH", evidence=img_inspect[:500], tool="docker", host=target,
                    mitre_technique="T1552.001",
                    exploit_suggestion="Extract: docker history --no-trunc <image> | grep -i 'ENV\\|ARG'",
                ))

        result.findings = list(self._findings)
        result.tool_outputs = dict(self._tool_outputs)
        return result
