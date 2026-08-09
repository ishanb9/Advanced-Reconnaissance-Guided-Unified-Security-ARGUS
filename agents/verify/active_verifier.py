"""agents/verify/active_verifier.py — E1 runner: SAFE, read-only, evidence-producing active
verification of a classified device, gated fail-closed on the authorized scope (E3 boundary).

The runner NEVER decides severity itself — it captures a real request/response and hands it to
the pure ``evaluate_probe`` (knowledge.device_capability_playbooks), which elevates severity
ONLY when the captured evidence proves a capability.  The network ``fetch`` is injectable, so
the runner is fully unit-testable with mocked device responses; the default fetch is a
best-effort READ-ONLY HTTP reader (GET / a read/describe SOAP POST) with a short timeout.

Scope is a HARD boundary: before ANY probe is sent, the target is checked against the
authorized scope via the governor.  Out of scope → zero traffic is sent (fail-closed).
"""
from __future__ import annotations

import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

from knowledge.device_capability_playbooks import (
    playbook_for, evaluate_probe, package_finding, CapabilityProbe)


FetchFn = Callable[[str, CapabilityProbe], Awaitable[Dict[str, Any]]]


def _scope_allows(host: str, scope_hosts: Optional[List[str]]) -> "tuple[bool, str]":
    """Fail-closed scope gate via the governor.  Returns (allowed, reason).  A scope that is
    empty OR contains only blank/whitespace entries means 'no authorized scope provided' →
    deny (host_in_scope treats an all-blank scope as unrestricted, so the verifier must reject
    it here or a `[""]` scope would blast any target)."""
    _clean_scope = [str(h).strip() for h in (scope_hosts or []) if str(h).strip()]
    if not _clean_scope:
        return False, "no authorized scope provided — refusing to send active traffic"
    scope_hosts = _clean_scope
    try:
        from knowledge.safety_governor import evaluate
        v = evaluate({"tool_name": "http-read", "args": "", "target_host": host,
                      "scope_hosts": list(scope_hosts)}, enforce=("scope",))
        if v.get("decision") == "deny":
            return False, str(v.get("reason") or "target is out of the authorized scope")
        return True, ""
    except Exception as exc:   # governor unavailable → fail closed
        return False, f"scope check unavailable ({type(exc).__name__}) — failing closed"


async def _default_read_only_fetch(host: str, probe: CapabilityProbe) -> Dict[str, Any]:
    """Best-effort READ-ONLY HTTP fetch derived from the probe's request template.  Issues a
    GET (or a POST carrying ONLY the probe's read/describe SOAP body) with a short timeout.
    Any parse/transport error → {"ok": False} so the evaluator degrades to unconfirmed.
    Kali-gated: requires httpx + network reachability; never raises."""
    try:
        import httpx  # type: ignore
    except Exception:
        return {"ok": False, "error": "httpx not available (live probing disabled)"}
    req = probe.request.replace("{host}", host)
    m = re.search(r"https?://\S+", req)
    if not m:
        return {"ok": False, "error": "no URL in probe (not an HTTP probe)"}
    url = m.group(0).rstrip("'\"")
    # placeholders like <upnp_port> mean the URL is not concretely resolvable without more
    # recon → treat as unconfirmed rather than guessing.
    if "<" in url and ">" in url:
        return {"ok": False, "error": "probe URL needs recon-derived value — human-gated"}
    soap = None
    dm = re.search(r"--data\s+'([^']+)'", req)
    if probe.method.upper() == "POST" and dm:
        soap = dm.group(1)
    try:
        # verify=False is intentional for device recon: embedded devices (cameras/printers/
        # NAS/controllers) ship self-signed certs, so TLS verification would block the
        # legitimate READ-ONLY probe of an AUTHORIZED in-scope host.  This mirrors the `curl
        # -sk` convention used throughout the skill playbooks; the fetch never sends secrets.
        # follow_redirects=False is a SCOPE-SAFETY guarantee: a 3xx from an in-scope device must
        # NOT be auto-followed, or it could bounce this probe to an OUT-OF-SCOPE host.  A redirect
        # simply becomes a non-200 status the evaluator treats as unconfirmed.
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as cli:
            if probe.method.upper() == "POST":
                resp = await cli.post(url, content=(soap or ""),
                                      headers={"Content-Type": "application/soap+xml"})
            else:
                resp = await cli.get(url)
            body = resp.text[:20000]
            return {"ok": True, "status": resp.status_code,
                    "headers": {k: v for k, v in resp.headers.items()}, "body": body}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


async def verify_device_capabilities(
    host: str,
    device_kind: str,
    *,
    scope_hosts: Optional[List[str]] = None,
    fetch: Optional[FetchFn] = None,
    emit: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None,
) -> List[Dict[str, Any]]:
    """Run the SAFE read-only capability playbook for ``device_kind`` against ``host`` and
    return one evidence-graded result per probe.  Sends NO traffic if the host is out of the
    authorized scope.  Each result carries the pure verdict + an E4 package (repro + captured
    artifact + impact + remediation for proven; a labelled 'unconfirmed' + next-step otherwise).
    """
    allowed, why = _scope_allows(host, scope_hosts)
    if not allowed:
        return [{"probe_id": "scope-gate", "proven": False, "severity": "info",
                 "blocked": True, "capability": "", "artifact": "",
                 "unconfirmed_reason": f"NOT PROBED — {why}",
                 "package": {"status": "blocked", "severity": "info",
                             "next_step": why, "reproduction": [], "artifact": ""}}]
    _fetch = fetch or _default_read_only_fetch
    out: List[Dict[str, Any]] = []
    for probe in playbook_for(device_kind):
        if probe.safety != "safe":     # never auto-run a non-safe (active-login/mutating) probe
            continue
        try:
            captured = await _fetch(host, probe)
        except Exception as exc:       # a fetch that raises must not crash the phase
            captured = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        res = evaluate_probe(probe, captured)
        rec = {**res.to_dict(), "host": host, "device_kind": device_kind,
               "package": package_finding(probe, res, host)}
        out.append(rec)
        if emit is not None:
            try:
                await emit("device_capability_verified", rec)
            except Exception:
                pass
    return out
