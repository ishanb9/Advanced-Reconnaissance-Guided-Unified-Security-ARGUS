"""
domain_recon_orchestrator.py — domain → subdomain hunt → human pick → scan.

When ARGUS is given a DOMAIN (not an IP/CIDR) with subdomain-hunting enabled,
this orchestrator runs the full real-world recon-to-engagement flow:

  1. HUNT   — enumerate subdomains across the public network (passive crt.sh +
              subfinder, active gobuster-dns brute) and resolve + scope-classify
              each (subdomain_hunter.hunt).
  2. PRESENT— stream the candidate list to the GUI (target_selection_request).
  3. GATE   — BLOCK on a mandatory human selection (target_selection.await_selection,
              fail-closed: no pick → attack nothing).
  4. SCAN   — feed the operator's chosen hosts into the existing CIDROrchestrator,
              which spawns one MasterAgent per selected target.

It mirrors the MasterAgent / CIDROrchestrator control surface (pause / resume /
request_stop / _intel) so agent_server can drive it uniformly.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Callable, Coroutine, Dict, List, Optional

import db.mongo_client as _db
from db.schemas import WebSocketMessage
from agents.cidr_orchestrator import CIDROrchestrator
from agents.recon import subdomain_hunter as _hunter
from agents.recon import dns_records as _dns
from agents import target_selection as _sel

logger = logging.getLogger(__name__)

# How long the scan blocks waiting for the operator to pick targets.
# Fail-closed on expiry (scan nothing).  Generous by default.
SELECTION_TIMEOUT = int(os.environ.get("TARGET_SELECTION_TIMEOUT", "1800"))


class DomainReconOrchestrator:
    def __init__(
        self,
        session_id:         str,
        domain:             str,
        broadcast:          Callable[[WebSocketMessage], Coroutine[Any, Any, None]],
        session_kwargs:     Dict,
        max_parallel_hosts: int = 5,
        passive:            bool = True,
        active:             bool = True,
    ) -> None:
        self.session_id         = session_id
        self.domain             = (domain or "").strip().lower().strip(".")
        self.broadcast          = broadcast
        self.session_kwargs     = session_kwargs
        self.max_parallel_hosts = max_parallel_hosts
        self.passive            = passive
        self.active             = active
        self._stop              = False
        self._inner:            Optional[CIDROrchestrator] = None
        self._pause_event:      asyncio.Event = asyncio.Event()
        self._pause_event.set()

    # ── Control surface (delegates to the inner orchestrator once scanning) ──

    def request_stop(self) -> None:
        self._stop = True
        try:
            _sel.resolve(self.session_id, [])   # unblock the gate → scan nothing
        except Exception:
            pass
        if self._inner:
            self._inner.request_stop()

    def stop_all_agents(self) -> None:
        self.request_stop()

    async def pause(self) -> str:
        # Before the inner orchestrator exists (hunt / DNS sweep / selection gate)
        # this object IS the run, so it must report a real pause.  Returning ""
        # read as "nothing paused", and the caller then left the DB row parked at
        # 'paused' with nothing able to clear it.
        self._pause_event.clear()
        if self._inner:
            return await self._inner.pause()
        return f"paused during domain recon of {self.domain}"

    async def resume(self) -> bool:
        was_paused = not self._pause_event.is_set()
        self._pause_event.set()
        if self._inner:
            return await self._inner.resume()
        return was_paused

    def inject_guidance(self, guidance: dict) -> None:
        if self._inner:
            self._inner.inject_guidance(guidance)

    def confirm_action(self, phase: str) -> None:
        if self._inner:
            self._inner.confirm_action(phase)

    @property
    def _intel(self) -> dict:
        return self._inner._intel if self._inner else {}

    # ── Emit helper ──────────────────────────────────────────────────────

    async def _emit(self, mtype: str, data: dict) -> None:
        try:
            await self.broadcast(WebSocketMessage(
                type=mtype, session_id=self.session_id, agent="recon", data=data,
            ))
        except Exception:
            pass

    # ── Main entry point ─────────────────────────────────────────────────

    def _authz_preview(self, candidates: List[Any]) -> Dict[str, Dict]:
        """The DERIVED authorization for every candidate, for pre-launch review.

        Sent with the selection request so the operator sees — before anything is
        touched — exactly what ARGUS would be allowed to do to each asset, and can
        change it.  Read-only preview; the operator's edits come back on submit."""
        try:
            from knowledge.authorization import policy_from_candidates
            _ceiling = str((self.session_kwargs or {}).get("scan_intrusiveness")
                           or "intrusive")
            pol = policy_from_candidates(candidates, engagement_ceiling=_ceiling)
            out: Dict[str, Dict] = {}
            for c in candidates or []:
                host = str(getattr(c, "host", "") or (c.get("host") if isinstance(c, dict) else ""))
                if host:
                    out[host] = pol.resolve(host).to_dict()
            return out
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("[authz] preview build failed: %s", exc)
            return {}

    def _build_host_authz(self, candidates: List[Any],
                          selected: List[str],
                          overrides: Optional[Dict[str, str]] = None) -> Dict[str, Dict]:
        """Resolve ONE authorization record per SELECTED host from the hunter's
        classification.  Fail-safe: a host we cannot classify resolves through the
        policy's PASSIVE_ONLY default rather than inheriting the engagement's."""
        try:
            from knowledge.authorization import (policy_from_candidates, profile as _prof,
                                                 min_ceiling as _min_ceil)
            _ceiling = str((self.session_kwargs or {}).get("scan_intrusiveness")
                           or "intrusive")
            pol = policy_from_candidates(candidates, engagement_ceiling=_ceiling)
            overrides = {str(k): str(v) for k, v in (overrides or {}).items()}
            out: Dict[str, Dict] = {}
            for host in (selected or []):
                host = str(host)
                derived = pol.resolve(host)
                ov = overrides.get(host) or overrides.get(host.lower())
                if ov:
                    # The HUMAN is the authorization authority — they may know they own
                    # an asset the classifier could only call third-party.  Their choice
                    # is honoured, still capped by the engagement-wide ceiling, and
                    # recorded loudly with provenance so the deviation is auditable.
                    a = _prof(ov).capped_by(_min_ceil(_prof(ov).ceiling, _ceiling))
                    from dataclasses import replace as _rep
                    a = _rep(a, owner=derived.owner, public=derived.public,
                             source=f"operator_override:{ov}",
                             note=(f"OPERATOR-SET '{ov}' (derived was "
                                   f"{derived.source or 'default'}: "
                                   f"{derived.exploitation}) — {a.note}"))
                    logger.warning("[authz] OPERATOR OVERRIDE %s: %s -> %s "
                                   "(ceiling=%s exploitation=%s)",
                                   host, derived.exploitation, ov,
                                   a.ceiling, a.exploitation)
                else:
                    a = derived
                out[host] = a.to_dict()
                logger.info("[authz] %s -> ceiling=%s exploitation=%s owner=%s src=%s",
                            host, a.ceiling, a.exploitation, a.owner, a.source)
            return out
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("[authz] per-host authorization build failed (%s) — each "
                           "host will derive its own from reachability class", exc)
            return {}

    @staticmethod
    def _records_headline(rec: Dict[str, Any]) -> str:
        """One-line operator summary of the record sweep.  Names an OPEN ZONE
        TRANSFER explicitly — it is the highest-value thing a DNS pass can find and
        must not be buried in a record dump."""
        s = rec.get("summary") or {}
        bits = [f"{s.get('addresses', 0)} address(es)",
                f"{s.get('nameservers', 0)} NS",
                f"{s.get('mail_exchangers', 0)} MX",
                f"{s.get('txt_records', 0)} TXT"]
        if s.get("srv_records"):
            bits.append(f"{s['srv_records']} SRV")
        if s.get("wildcard"):
            bits.append("wildcard DNS")
        # Only claim an email policy is MISSING when the TXT query actually ran.
        # Without dig the sweep degrades to address records only, and has_spf /
        # has_dmarc are then False because nothing was asked — reporting that as
        # "no SPF, no DMARC" states an unchecked absence as fact.
        if s.get("txt_queried"):
            if not s.get("has_spf"):
                bits.append("no SPF")
            if not s.get("has_dmarc"):
                bits.append("no DMARC")
        else:
            bits.append("SPF/DMARC not checked")
        head = f"DNS records for {rec.get('apex') or ''}: " + ", ".join(bits)
        open_axfr = s.get("zone_transfer_open") or []
        if open_axfr:
            head += (f" — ZONE TRANSFER OPEN on {', '.join(open_axfr)} "
                     "(full zone disclosed)")
        return head

    @staticmethod
    def _dns_findings(rec: Dict[str, Any], domain: str) -> List[Dict[str, Any]]:
        """Turn the record sweep into FINDINGS so it reaches the report.

        The sweep used to emit one WebSocket event and stop there, so an open zone
        transfer — the single highest-value thing a DNS pass can find — showed in
        the live feed for a moment and then existed nowhere: not in the findings
        store, not in the report, not in the retest list.

        Severity follows the platform's evidence rule.  A zone transfer is graded
        HIGH because there IS a captured artifact: parse_axfr only reports success
        when the response carried the zone's SOA plus real record content, so an
        exit-0 refusal cannot reach here.  Everything else is a configuration
        observation graded LOW/INFO — real, worth reporting, not inflated.  Nothing
        is emitted for a check that did not run.
        """
        s = rec.get("summary") or {}
        out: List[Dict[str, Any]] = []

        for ns in (s.get("zone_transfer_open") or []):
            leaked = ((rec.get("zone_transfer") or {}).get(ns) or {})
            hosts = leaked.get("hosts") or []
            out.append({
                "severity": "high", "host": ns, "tool_used": "dig",
                "title": f"DNS zone transfer (AXFR) allowed by {ns}",
                "description": (
                    f"The nameserver {ns} served a full AXFR of the {domain} zone to "
                    f"an unauthenticated client, disclosing {len(hosts)} record "
                    f"name(s) including internal hostnames that are not otherwise "
                    f"published. This hands an attacker the complete inventory of "
                    f"the zone in one request.\n\n"
                    f"Reproduce: dig AXFR {domain} @{ns}\n\n"
                    f"Remediation: restrict zone transfers to authorised secondary "
                    f"nameservers (allow-transfer / TSIG)."),
                "raw_output": (leaked.get("raw") or "")[:4000],
                "extra": {"leaked_hosts": hosts[:200], "nameserver": ns,
                          "record_count": len(hosts)},
            })

        # Email-policy gaps — ONLY when the TXT query actually completed.
        if s.get("txt_queried"):
            pol = rec.get("txt_policies") or {}
            if not s.get("has_spf"):
                out.append({
                    "severity": "low", "host": domain, "tool_used": "dig",
                    "title": f"No SPF record published for {domain}",
                    "description": (
                        f"A TXT lookup for {domain} returned no v=spf1 record, so "
                        f"receiving mail servers have no published list of hosts "
                        f"authorised to send as this domain, easing spoofing of it "
                        f"in phishing.\n\nReproduce: dig TXT {domain}\n\n"
                        f"Remediation: publish an SPF record ending in -all once the "
                        f"legitimate senders are enumerated."),
                    "raw_output": "\n".join(rec.get("txt") or [])[:2000],
                    "extra": {"txt_records": rec.get("txt") or []},
                })
            elif pol.get("spf_all_qualifier") in ("?", "+"):
                out.append({
                    "severity": "low", "host": domain, "tool_used": "dig",
                    "title": f"SPF record for {domain} is permissive "
                             f"({pol.get('spf_all_qualifier')}all)",
                    "description": (
                        f"The SPF record ends in '{pol.get('spf_all_qualifier')}all', "
                        f"which tells receivers to accept mail from senders the "
                        f"record does not authorise — the policy is published but "
                        f"does not constrain anything.\n\nReproduce: dig TXT {domain}"
                        f"\n\nRemediation: move to ~all and then -all."),
                    "raw_output": "\n".join(pol.get("spf") or [])[:2000],
                    "extra": {"spf": pol.get("spf") or []},
                })
            if not s.get("has_dmarc"):
                out.append({
                    "severity": "low", "host": domain, "tool_used": "dig",
                    "title": f"No DMARC policy published for {domain}",
                    "description": (
                        f"No v=DMARC1 record was returned for {domain}, so SPF/DKIM "
                        f"failures carry no handling instruction and the domain owner "
                        f"receives no reporting on abuse of the domain.\n\n"
                        f"Reproduce: dig TXT _dmarc.{domain}\n\n"
                        f"Remediation: publish _dmarc with p=none plus rua reporting, "
                        f"then tighten to quarantine/reject."),
                    "raw_output": "\n".join(rec.get("txt") or [])[:2000],
                    "extra": {},
                })
            elif str(pol.get("dmarc_policy") or "").lower() == "none":
                out.append({
                    "severity": "info", "host": domain, "tool_used": "dig",
                    "title": f"DMARC policy for {domain} is monitor-only (p=none)",
                    "description": (
                        "A DMARC record is published with p=none, which reports but "
                        "does not act on authentication failures.\n\n"
                        f"Reproduce: dig TXT _dmarc.{domain}\n\n"
                        "Remediation: progress to p=quarantine then p=reject once the "
                        "reports show legitimate senders align."),
                    "raw_output": "\n".join(pol.get("dmarc") or [])[:2000],
                    "extra": {},
                })

        if s.get("wildcard"):
            out.append({
                "severity": "info", "host": domain, "tool_used": "dig",
                "title": f"Wildcard DNS is configured for *.{domain}",
                "description": (
                    f"Any name under {domain} resolves, so subdomain brute-force "
                    f"results from this domain cannot be trusted without a second "
                    f"check and enumeration findings may be inflated.\n\n"
                    f"Reproduce: dig +short unlikely-random-name.{domain}"),
                "raw_output": "", "extra": {},
            })
        return out

    async def _store_dns_findings(self, rec: Dict[str, Any]) -> int:
        """Persist the record-sweep findings.  Returns how many were stored."""
        try:
            from db.schemas import AgentName as _AN, AttackPhase as _AP, \
                FindingSeverity as _FS
        except Exception:                                        # noqa: BLE001
            return 0
        stored = 0
        for f in self._dns_findings(rec, self.domain):
            try:
                await _db.store_finding(
                    session_id=self.session_id,
                    agent=getattr(_AN, "RECON", None) or "recon",
                    phase=getattr(_AP, "RECONNAISSANCE", None) or "reconnaissance",
                    severity=_FS(f["severity"]),
                    title=f["title"], description=f["description"],
                    host=f["host"], tool_used=f.get("tool_used") or "dig",
                    raw_output=f.get("raw_output") or "",
                    extra=f.get("extra") or {},
                )
                stored += 1
                await self._emit("finding", {
                    "severity": f["severity"], "title": f["title"],
                    "host": f["host"], "description": f["description"],
                    "message": f"[{f['severity'].upper()}] {f['title']}",
                })
            except Exception as _fexc:                           # noqa: BLE001
                logger.warning("[dns] could not store finding %r: %s",
                               f.get("title"), _fexc)
        if stored:
            logger.info("[dns] stored %d finding(s) from the record sweep", stored)
        return stored

    async def _merge_record_candidates(self, candidates: List[Any], records: Any
                                       ) -> List[Any]:
        """Add hostnames the DNS sweep revealed to the pickable candidate list.

        Classified with the hunter's OWN apex/network rules so a third-party mail or
        DNS provider is flagged rather than silently offered as in-scope.  Never
        probes anything — these are candidates for the human to accept or ignore."""
        if records is None:
            return candidates
        try:
            known = {c.host for c in candidates}
            apex_ips: set = set()
            for c in candidates:
                if getattr(c, "host", "") == self.domain:
                    apex_ips = set(getattr(c, "ips", []) or [])
                    break
            extra: List[Any] = []
            for host in records.all_hosts():
                if not host or host in known:
                    continue
                known.add(host)
                ips = list((records.ns_ips.get(host) or records.mx_ips.get(host) or []))
                in_net, third, note = _hunter.classify(host, ips, apex_ips)
                src = "dns:zone-transfer" if any(
                    host in ((r or {}).get("hosts") or [])
                    for r in (records.zone_transfer or {}).values()) else "dns:record"
                extra.append(_hunter.SubdomainCandidate(
                    host=host, ips=ips, sources=[src],
                    in_apex_network=in_net, third_party=third,
                    note=(note or "") or "discovered via DNS records"))
            if extra:
                logger.info("[domain_recon] %d extra candidate(s) from DNS records",
                            len(extra))
            return list(candidates) + extra
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("[domain_recon] record-candidate merge failed: %s", exc)
            return candidates

    async def _finish(self, status: str, message: str) -> None:
        """Move the session OUT of 'active' and say so.

        Every early return from run() used to leave the session 'active' forever:
        the UI kept showing a scan in progress that would never advance, the report
        was never offered, and the row could not be told apart from a live run.  A
        domain run has several legitimate endings — no domain, hunt error, operator
        stop, nothing selected — and each is terminal.
        """
        try:
            await _db.update_session(self.session_id, {"status": status})
        except Exception as _sexc:                               # noqa: BLE001
            logger.warning("[domain_recon] could not set terminal status %r: %s",
                           status, _sexc)
        await self._emit("scan_complete" if status == "completed" else "scan_failed",
                         {"session_id": self.session_id, "status": status,
                          "domain": self.domain, "message": message})

    async def run(self) -> Dict:
        if not self.domain:
            await self._emit("domain_recon_error", {"message": "no domain given"})
            await self._finish("failed", "No domain supplied — nothing to scan.")
            return {"error": "no domain"}

        # ── Step 1: HUNT ──────────────────────────────────────────────
        await self._emit("subdomain_hunt_start", {
            "domain":  self.domain,
            "passive": self.passive,
            "active":  self.active,
            "message": f"Hunting subdomains of {self.domain} (passive + active)…",
        })

        async def _progress(msg: str) -> None:
            await self._emit("subdomain_hunt_progress", {"message": msg})

        # Run the SUBDOMAIN hunt and the full DNS RECORD sweep concurrently — they
        # hit different sources and neither needs the other's output.  The record
        # sweep is the DNSDumpster-equivalent pass (A/AAAA/NS/MX/TXT/SOA/CNAME/CAA/
        # SRV/PTR + zone-transfer attempt + wildcard detection); the operator sees it
        # alongside the candidate list so the pick is an informed one.
        async def _records() -> Any:
            try:
                return await _dns.sweep(self.domain, on_progress=_progress)
            except Exception as exc:                              # noqa: BLE001
                logger.warning("[domain_recon] dns sweep failed: %s", exc)
                return None

        try:
            candidates, records = await asyncio.gather(
                _hunter.hunt(self.domain, passive=self.passive, active=self.active,
                             on_progress=_progress),
                _records(),
            )
        except Exception as exc:                                  # noqa: BLE001
            logger.warning("[domain_recon] hunt failed: %s", exc)
            await self._emit("domain_recon_error", {"message": f"hunt failed: {exc}"})
            await self._finish("failed", f"Subdomain hunt failed: {exc}")
            return {"error": str(exc)}

        if self._stop:
            await self._finish("completed", "Stopped by the operator during recon.")
            return {"stopped": True}

        # Offer the hostnames the RECORD sweep revealed (NS / MX / CNAME / SRV
        # targets, plus anything a zone transfer leaked) as additional pickable
        # candidates.  They are classified by the SAME apex/network rules as the
        # hunt's results, so third-party mail or DNS providers arrive clearly
        # flagged — and nothing is touched until the human selects it.
        candidates = await self._merge_record_candidates(candidates, records)

        cand_dicts = [c.to_dict() for c in candidates]
        rec_dict = records.to_dict() if records is not None else {}
        try:
            await _db.update_session(self.session_id, {
                "subdomain_candidates": cand_dicts,
                "dns_records":          rec_dict,
            })
        except Exception:
            pass
        if rec_dict:
            await self._emit("dns_records_complete", {
                "domain": self.domain, "records": rec_dict,
                "summary": rec_dict.get("summary") or {},
                "message": self._records_headline(rec_dict),
            })
            # Persist what the sweep proved BEFORE the human gate.  These findings
            # are about the domain itself, not any host the operator picks, so they
            # must survive even a "scan nothing" answer — otherwise an open zone
            # transfer is discovered and then thrown away.
            await self._store_dns_findings(rec_dict)

        # ── Step 2 + 3: PRESENT + blocking GATE ───────────────────────
        allowed = [c.host for c in candidates]
        _sel.create_request(self.session_id, allowed=allowed)
        await self._emit("target_selection_request", {
            "selection_id": self.session_id,
            "domain":       self.domain,
            "candidates":   cand_dicts,
            "count":        len(cand_dicts),
            "in_network":   sum(1 for c in candidates if c.in_apex_network),
            "third_party":  sum(1 for c in candidates if c.third_party),
            "timeout_sec":  SELECTION_TIMEOUT,
            # Full DNS record set travels WITH the pick request so the operator
            # decides from the same data DNSDumpster would have shown them.
            "dns_records":  rec_dict,
            "dns_summary":  rec_dict.get("summary") or {},
            # DERIVED per-host authorization for EVERY candidate, so the operator
            # reviews (and can adjust) what ARGUS may do to each asset BEFORE launch
            # rather than discovering it from denials mid-scan.
            "authorization": self._authz_preview(candidates),
            "authz_profiles": [
                {"id": "passive_only", "label": "Passive only",
                 "detail": "OSINT/read-only — no active probing"},
                {"id": "assess", "label": "Assess",
                 "detail": "Active probing + vuln ID — NO exploitation"},
                {"id": "external", "label": "External (approve exploits)",
                 "detail": "Full depth; every exploit needs your approval"},
                {"id": "full", "label": "Full autonomous",
                 "detail": "Autonomous exploitation — internal/lab or explicit SoW"},
            ],
            "message": (f"Found {len(cand_dicts)} candidate target(s) for "
                        f"{self.domain}. Select which to engage — nothing is "
                        f"attacked until you choose."),
        })

        # Also collect the operator's REVIEWED per-host authorization (what they said
        # ARGUS may do to each asset).  Empty map => keep the derived, fail-closed policy.
        # Pause-aware: the pick clock stops while the operator has the run paused,
        # so pausing to go and confirm scope cannot silently expire the gate into
        # "select nothing".
        selected, authz_overrides = await _sel.await_decision_gated(
            self.session_id, timeout=SELECTION_TIMEOUT,
            is_paused=lambda: not self._pause_event.is_set())

        if self._stop:
            await self._finish("completed",
                               "Stopped by the operator at the target-selection gate.")
            return {"stopped": True}

        if not selected:
            await self._emit("target_selection_empty", {
                "selection_id": self.session_id,
                "message": ("No targets selected (or selection timed out) — "
                            "attacking nothing. Re-run and pick targets to engage."),
            })
            # Selecting nothing is a COMPLETE run, not an abandoned one: the recon
            # and the DNS findings above are real output.  Leaving it 'active' (as
            # it did) parks the session forever — the UI shows a scan in progress
            # that will never move and the report is never offered.
            await self._finish("completed",
                               "No targets selected — domain recon and DNS record "
                               "findings are complete; nothing was engaged.")
            return {"selected": [], "candidates": cand_dicts}

        await self._emit("target_selection_confirmed", {
            "selection_id": self.session_id,
            "selected":     selected,
            "count":        len(selected),
            "message": f"Engaging {len(selected)} operator-selected target(s).",
        })
        try:
            await _db.update_session(self.session_id, {"selected_targets": selected})
        except Exception:
            pass

        # ── Step 4: SCAN the selected set via the multi-target orchestrator ──
        self._inner = CIDROrchestrator(
            session_id         = self.session_id,
            target_input       = ",".join(selected),
            broadcast          = self.broadcast,
            session_kwargs     = self.session_kwargs,
            max_parallel_hosts = self.max_parallel_hosts,
            # The hunt already resolved these and the operator explicitly picked them.
            # Without this, CIDROrchestrator re-runs `nmap -sn` and its IP-capturing
            # regex replaces every chosen SUBDOMAIN with a bare IP — losing the vhost
            # name that web testing depends on (only triggered above 4 picks, which is
            # why it went unnoticed).
            presolved          = True,
            # PER-HOST AUTHORIZATION — the point at which the hunter's in-apex /
            # third-party classification finally REACHES enforcement instead of being
            # display-only.  A third-party CDN/mail host the operator picked is
            # authorized passive-only; a public client asset gets human-approved
            # exploitation; a private/lab asset may run autonomously.
            host_authz         = self._build_host_authz(candidates, selected,
                                                        authz_overrides),
        )
        if not self._pause_event.is_set():
            await self._inner.pause()
        _result = await self._inner.run()
        # The inner orchestrator reports per-host results but never moves the SESSION
        # out of 'active' — on the domain path nothing else does either, so a finished
        # multi-host run looked identical to one still in progress.
        _hosts = [k for k in (_result or {}) if k not in ("error", "live_hosts", "stopped")]
        if (_result or {}).get("error"):
            await self._finish("failed",
                               f"Domain scan failed: {(_result or {}).get('error')}")
        else:
            await self._finish("completed",
                               f"Domain scan complete for {self.domain} — "
                               f"{len(_hosts)} host(s) engaged.")
        return _result


__all__ = ["DomainReconOrchestrator", "SELECTION_TIMEOUT"]
