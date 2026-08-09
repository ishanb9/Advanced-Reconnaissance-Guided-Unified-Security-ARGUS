"""knowledge/device_capability_playbooks.py — data-driven device-class capability playbooks.

The prior behaviour for device / IoT / AV / OT / peripheral surfaces was "banner-match →
INFO, present-not-exploitable".  That under-reports: a manual assessment goes deeper by
actually *reading* a device's unauthenticated control/description surface and rating it on
what the response PROVES.  This module encodes, PER DEVICE CLASS, a set of SAFE, read-only,
unauthenticated ACTIVE checks and the EVIDENCE→CAPABILITY→SEVERITY rules that grade them.

Design guarantees (do not regress):
  * Data-driven: playbooks are keyed by a generic device-class FAMILY (smart_tv, av_controller,
    printer, camera, nas, router, voip, mobile, ...), never by a vendor name.  Evidence rules
    match capability SIGNATURES (SOAP action names, XML elements, HTTP status+markers), not
    vendors — so no vendor literal drives control flow.
  * Read-only + safe: every probe is a GET / a read/describe SOAP action / an SNMP GET.  None
    write, reboot, authenticate, or change state.  Each carries `safety="safe"`.
  * Evidence-or-silence: `evaluate_probe` elevates severity ONLY when the CAPTURED response
    proves the capability.  A probe that errored, was blocked, or didn't expose the capability
    yields an honest "unconfirmed" (never a guess), with a next-step for a human-gated test.

Pure + dependency-light: everything here is a pure function over recorded responses, so it is
unit-testable with mocked device output spanning many classes — no network required.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Evidence rule ────────────────────────────────────────────────────────────────
@dataclass
class EvidenceRule:
    """One capability the probe can PROVE, and the severity to assign IF the captured
    response matches.  A rule fires only when: the HTTP status is in ``status_in`` (or
    status is ignored when status_in is empty), ``body_re`` matches the captured body, and
    ``absent_re`` (when set) does NOT match (e.g. an auth challenge must be absent, so we
    only claim "unauthenticated" access when there was genuinely no auth)."""
    capability: str
    severity: str                       # info | low | medium | high  (evidence-derived)
    body_re: str = ""
    status_in: tuple = (200,)
    absent_re: str = ""                 # capability disproven if this matches (e.g. 401 challenge)
    impact: str = ""                    # business-impact statement
    remediation: str = ""               # finding-specific remediation


@dataclass
class CapabilityProbe:
    probe_id: str
    transport: str                      # http | http-soap | snmp | ipp | upnp
    request: str                        # a human/agent-runnable, READ-ONLY request template ({host})
    evidence: List[EvidenceRule]
    method: str = "GET"
    note: str = ""                      # why this is safe / read-only
    safety: str = "safe"


# ── The playbooks (class family → ordered safe probes) ───────────────────────────
# Each probe's request is a real, read-only command a human can rerun; the evaluator scores
# the CAPTURED response.  Severity words here are the CEILING a proof can reach — the shared
# severity_policy still floors anything unsupported to INFO, so these can never over-report.
_PB: Dict[str, List[CapabilityProbe]] = {
    "smart_tv": [
        CapabilityProbe(
            probe_id="dial-app-list", transport="http",
            request="curl -sS -m 5 http://{host}:8008/apps",
            note="DIAL/Chromecast app-discovery endpoint — read-only GET, no control action.",
            evidence=[
                EvidenceRule(
                    capability="Unauthenticated DIAL app-control surface exposed (app state readable / launchable without auth)",
                    severity="medium", status_in=(200,),
                    body_re=r"<service[^>]*dial|<name>[^<]+</name>|urn:dial-multiscreen-org",
                    absent_re=r"401 Unauthorized|WWW-Authenticate",
                    impact="An unauthenticated peer on the segment can enumerate and launch apps on the display, enabling content injection / nuisance control.",
                    remediation="Disable DIAL/second-screen control on untrusted segments, or require pairing; place the display on an isolated AV VLAN."),
            ]),
        CapabilityProbe(
            probe_id="upnp-describe", transport="http",
            request="curl -sS -m 5 http://{host}:<upnp_port>/description.xml   # location from the SSDP LOCATION header",
            note="UPnP device description — read-only describe; reveals services + control URLs.",
            evidence=[
                EvidenceRule(
                    capability="UPnP AV control service (AVTransport/RenderingControl) described without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"urn:schemas-upnp-org:service:(AVTransport|RenderingControl)",
                    absent_re=r"401 Unauthorized",
                    impact="Media playback/volume and transport can be driven by any device on the segment (unauthenticated UPnP control).",
                    remediation="Restrict UPnP to trusted segments / disable if unused; segment media devices away from user and server VLANs."),
                EvidenceRule(
                    capability="UPnP device description readable (model/services disclosed)",
                    severity="low", status_in=(200,),
                    body_re=r"<friendlyName>|<serviceType>",
                    impact="Model/firmware/service inventory is disclosed unauthenticated, aiding targeted attacks.",
                    remediation="Limit UPnP SSDP scope; keep firmware current."),
            ]),
    ],
    "av_controller": [
        CapabilityProbe(
            probe_id="crossdomain-policy", transport="http",
            request="curl -sS -m 5 http://{host}/crossdomain.xml",
            note="Flash/Flex cross-domain policy — read-only GET.",
            evidence=[
                EvidenceRule(
                    capability="Permissive cross-domain policy (allow-access-from domain=\"*\")",
                    severity="medium", status_in=(200,),
                    body_re=r"allow-access-from\s+domain\s*=\s*\"\*\"",
                    impact="A malicious web origin can script the controller's HTTP API cross-domain, enabling remote control of AV/room systems.",
                    remediation="Replace the wildcard cross-domain policy with an explicit allow-list, or remove it; front the controller with an authenticating proxy."),
            ]),
        CapabilityProbe(
            probe_id="control-api-describe", transport="http",
            request="curl -sS -m 5 http://{host}/   # read the control web root / API index",
            note="Read-only fetch of the control web root to see whether the control API answers without auth.",
            evidence=[
                EvidenceRule(
                    capability="Control/automation web API reachable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"(?i)(control(system)?|automation|room\s*control|processor|scheduler)\b",
                    absent_re=r"401 Unauthorized|login|WWW-Authenticate|password",
                    impact="The building/AV automation surface answers unauthenticated — an on-segment attacker can enumerate and potentially drive room control.",
                    remediation="Require authentication on the control interface; isolate the controller on a management VLAN reachable only from authorized operators."),
            ]),
    ],
    "printer": [
        CapabilityProbe(
            probe_id="ipp-attributes", transport="ipp",
            request="ipptool -tv ipp://{host}/ipp/print get-printer-attributes.test   # read-only Get-Printer-Attributes",
            note="IPP Get-Printer-Attributes — a READ operation; no job is submitted.",
            evidence=[
                EvidenceRule(
                    capability="IPP printer attributes readable unauthenticated (model, state, saved jobs metadata)",
                    severity="low", status_in=(200,),
                    body_re=r"printer-state|printer-make-and-model|marker-levels|job-",
                    impact="Printer inventory / queued-job metadata is disclosed unauthenticated; queued documents may be exposed on some models.",
                    remediation="Require authentication for IPP; disable raw 9100; restrict printers to a print VLAN."),
            ]),
        CapabilityProbe(
            probe_id="web-admin-unauth", transport="http",
            request="curl -sS -m 5 -D - http://{host}/   # read admin landing (no login submitted)",
            note="Read the printer web root to see if the admin console is reachable without auth.",
            evidence=[
                EvidenceRule(
                    capability="Printer administration console reachable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"(?i)(printer|device)\s*(settings|configuration|admin)|address\s*book|scan\s*to",
                    absent_re=r"401 Unauthorized|WWW-Authenticate|please log ?in",
                    impact="Config/address-book/scan-to settings are changeable by an on-segment attacker (data exfiltration via scan-to, config tampering).",
                    remediation="Set an admin password; disable unauthenticated web admin; segment printers."),
            ]),
    ],
    "camera": [
        CapabilityProbe(
            probe_id="onvif-getdeviceinfo", transport="http-soap",
            request=("curl -sS -m 5 -X POST http://{host}/onvif/device_service "
                     "-H 'Content-Type: application/soap+xml' "
                     "--data '<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
                     "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"
                     "</s:Body></s:Envelope>'"),
            method="POST",
            note="ONVIF GetDeviceInformation — a READ/describe SOAP action; discloses info, changes nothing.",
            evidence=[
                EvidenceRule(
                    capability="ONVIF device information readable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"GetDeviceInformationResponse|<tds:Manufacturer|<tds:SerialNumber",
                    absent_re=r"NotAuthorized|Sender not Authorized|401",
                    impact="Camera make/model/firmware/serial disclosed unauthenticated; combined with known CVEs this enables targeted takeover.",
                    remediation="Enforce ONVIF authentication (WS-UsernameToken); disable anonymous ONVIF; isolate cameras on a CCTV VLAN."),
            ]),
        CapabilityProbe(
            probe_id="isapi-deviceinfo", transport="http",
            request="curl -sS -m 5 http://{host}/ISAPI/System/deviceInfo",
            note="ISAPI System/deviceInfo — read-only describe GET.",
            evidence=[
                EvidenceRule(
                    capability="Camera device-info API readable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"<deviceType>|<model>|<firmwareVersion>|DeviceInfo",
                    absent_re=r"401|<statusString>Unauthorized",
                    impact="Unauthenticated device/firmware disclosure narrows the CVE set for a targeted attack.",
                    remediation="Require authentication on the device API; disable ISAPI anonymous access; update firmware."),
            ]),
    ],
    "nas": [
        CapabilityProbe(
            probe_id="nas-web-unauth", transport="http",
            request="curl -sS -m 5 -D - http://{host}:5000/   # read the NAS web portal landing",
            note="Read the NAS web portal to see if management answers without auth.",
            evidence=[
                EvidenceRule(
                    capability="NAS management portal reachable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"(?i)(diskstation|nas|file\s*station|storage\s*manager|shared\s*folder)",
                    absent_re=r"401 Unauthorized|WWW-Authenticate|login",
                    impact="Storage management surface is reachable unauthenticated (share enumeration / config exposure).",
                    remediation="Require authentication; disable the default admin; restrict management to a trusted segment."),
            ]),
    ],
    "router": [
        CapabilityProbe(
            probe_id="router-web-unauth", transport="http",
            request="curl -sS -m 5 -D - http://{host}/   # read the router admin landing",
            note="Read the router web root to detect an unauthenticated admin surface.",
            evidence=[
                EvidenceRule(
                    capability="Router/appliance admin UI reachable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"(?i)(router|gateway|firewall|routeros|admin)\b.*(config|status|dashboard|setup)",
                    absent_re=r"401 Unauthorized|WWW-Authenticate|please log ?in",
                    impact="Network-infrastructure admin answers unauthenticated — a foothold for traffic redirection / pivot.",
                    remediation="Set a strong admin credential; disable WAN/inter-segment admin; restrict to a management VLAN."),
            ]),
    ],
    "voip": [
        CapabilityProbe(
            probe_id="voip-web-unauth", transport="http",
            request="curl -sS -m 5 -D - http://{host}/   # read the phone web admin landing",
            note="Read the phone web root to detect an unauthenticated admin / config surface.",
            evidence=[
                EvidenceRule(
                    capability="VoIP phone web admin / config readable without authentication",
                    severity="medium", status_in=(200,),
                    body_re=r"(?i)(voip|sip|phone)\b.*(status|config|account)|servlet\?",
                    absent_re=r"401 Unauthorized|WWW-Authenticate|loginForm",
                    impact="Phone config (SIP AuthID, provisioning) may be disclosed unauthenticated, enabling toll fraud / eavesdrop.",
                    remediation="Require web-admin auth; disable unauthenticated provisioning retrieval; segment voice VLAN."),
            ]),
    ],
    "generic_embedded": [
        CapabilityProbe(
            probe_id="embedded-web-unauth", transport="http",
            request="curl -sS -m 5 -D - http://{host}/   # read the device web root",
            note="Read the device web root; only claim a capability if the response proves it.",
            evidence=[
                EvidenceRule(
                    capability="Embedded device management reachable without authentication",
                    severity="low", status_in=(200,),
                    body_re=r"(?i)(setup|configuration|admin|device)\s*(page|panel|console)",
                    absent_re=r"401 Unauthorized|WWW-Authenticate|login",
                    impact="An unauthenticated management surface is exposed; capability/impact depends on the device.",
                    remediation="Require authentication; restrict management access; keep firmware current."),
            ]),
    ],
}


# device-classifier TaxonomyKind (string) → playbook family.  Data mapping, no control flow
# on vendor names.  Unmapped kinds fall back to the generic embedded probe set.
_KIND_TO_FAMILY: Dict[str, str] = {
    "iot_media": "smart_tv", "iot_smart_home": "smart_tv",
    "iot_camera": "camera", "iot_printer": "printer",
    "iot_router": "router", "network_device": "router",
    "iot_voip": "voip",
    "iot_industrial": "av_controller",   # OT/AV control processors share the control-API model
    "embedded_generic": "generic_embedded",
}


def family_for_kind(kind: str) -> str:
    return _KIND_TO_FAMILY.get(str(kind or "").strip().lower(), "generic_embedded")


def playbook_for(kind: str) -> List[CapabilityProbe]:
    """Ordered SAFE read-only probes for a device class (by classifier kind or family name)."""
    k = str(kind or "").strip().lower()
    fam = k if k in _PB else family_for_kind(k)
    return list(_PB.get(fam, _PB["generic_embedded"]))


def all_families() -> List[str]:
    return sorted(_PB.keys())


# ── Verification result + pure evaluator (E1) ────────────────────────────────────
@dataclass
class VerificationResult:
    probe_id: str
    proven: bool
    severity: str                       # evidence-derived when proven; "info" otherwise
    capability: str
    artifact: str                       # the captured request/response evidence
    unconfirmed_reason: str = ""
    impact: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"probe_id": self.probe_id, "proven": self.proven, "severity": self.severity,
                "capability": self.capability, "artifact": self.artifact[:4000],
                "unconfirmed_reason": self.unconfirmed_reason, "impact": self.impact,
                "remediation": self.remediation}


def _captured_blob(captured: Dict[str, Any]) -> str:
    hdrs = captured.get("headers") or {}
    hdr_txt = "\n".join(f"{k}: {v}" for k, v in hdrs.items()) if isinstance(hdrs, dict) else str(hdrs)
    return f"HTTP {captured.get('status')}\n{hdr_txt}\n\n{captured.get('body') or ''}"


def evaluate_probe(probe: CapabilityProbe, captured: Dict[str, Any]) -> VerificationResult:
    """Grade a SAFE probe from its CAPTURED response.  Elevates severity ONLY when the
    response proves a capability; otherwise returns an honest unconfirmed result.

    ``captured`` = {"ok": bool, "status": int|None, "headers": dict, "body": str, "error": str}.
    ``ok=False`` (blocked / errored / no response) → unconfirmed, never a guess.
    """
    pid = probe.probe_id
    if not captured or not captured.get("ok"):
        return VerificationResult(
            probe_id=pid, proven=False, severity="info",
            capability="", artifact=_captured_blob(captured or {}),
            unconfirmed_reason=("no usable response (blocked, filtered, timed out, or errored) — "
                                "requires a human-gated active test to confirm"))
    body = str(captured.get("body") or "")
    status = captured.get("status")
    blob = _captured_blob(captured)
    for rule in probe.evidence:
        if rule.status_in and status not in rule.status_in:
            continue
        if rule.body_re and not re.search(rule.body_re, body, re.I | re.S):
            continue
        if rule.absent_re and re.search(rule.absent_re, blob, re.I | re.S):
            continue          # the capability is DISPROVEN (e.g. an auth challenge is present)
        return VerificationResult(
            probe_id=pid, proven=True, severity=rule.severity, capability=rule.capability,
            artifact=blob, impact=rule.impact, remediation=rule.remediation)
    # ran cleanly but the capability was not exposed — an honest negative, not a finding.
    return VerificationResult(
        probe_id=pid, proven=False, severity="info", capability="", artifact=blob,
        unconfirmed_reason="probe ran but the target did not expose the capability (no proof) — "
                           "not reported as a vulnerability")


# ── PoC + remediation packaging (E4) ─────────────────────────────────────────────
def package_finding(probe: CapabilityProbe, result: VerificationResult, host: str) -> Dict[str, Any]:
    """Assemble a client-ready package from REAL captured evidence: a runnable reproduction,
    the captured request/response artifact, a business-impact statement, and a concrete,
    finding-specific remediation.  Unproven results are packaged as clearly-labelled
    'unconfirmed' with the exact next step (human-gated active test)."""
    repro = probe.request.replace("{host}", str(host or "<host>"))
    if result.proven:
        return {
            "status": "proven",
            "title": result.capability,
            "severity": result.severity,
            "reproduction": [repro],
            "artifact": result.artifact,          # the real captured request/response
            "business_impact": result.impact,
            "remediation": result.remediation,
            "evidence_tag": "DEMONSTRATED",
        }
    return {
        "status": "unconfirmed",
        "title": f"Unconfirmed: {probe.probe_id} on {host}",
        "severity": "info",
        "reproduction": [repro],
        "artifact": result.artifact,
        "business_impact": "",
        "remediation": "",
        "next_step": (result.unconfirmed_reason
                      or "run the read-only probe under human authorization and re-evaluate"),
        "evidence_tag": "OBSERVED",
    }
