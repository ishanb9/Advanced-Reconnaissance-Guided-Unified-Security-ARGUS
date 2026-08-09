"""knowledge/authorization.py — PER-TARGET authorization for authorized engagements.

Why this exists
---------------
ARGUS is used against PUBLIC networks under authorized engagements, not only internal
labs.  Authorization is therefore NOT a property of the run — it is a property of each
TARGET.  Before this module the platform had exactly one engagement-wide picture:

  * one ``authorized`` boolean (intel['authorized'] / ot_authorized),
  * one ``scan_intrusiveness`` ceiling in a session_kwargs dict built ONCE from the
    HTTP body before any discovery happened,
  * a scope list that ``_build_scope`` fills with THE TARGET ITSELF, so the governor's
    scope check is self-satisfying and can never fire on a wrongly-chosen host.

The consequence: a third-party CDN edge, a shared-hosting neighbour, or a cloud mail
provider that merely appears in a client's DNS was scanned with byte-identical
authorization to the client's own web server.  The subdomain hunter already labels
those hosts ``third_party`` — but that label was display-only and never reached an
enforcement point.

Model
-----
``TargetAuthorization`` says what the operator may do to ONE host: an intrusiveness
ceiling, plus a TRI-STATE exploitation decision, plus ownership.  Exploitation is
deliberately three-valued because "public target" is not the same as "forbidden":

    deny             — never, not even with a human present (third-party infra)
    require_approval — a HUMAN authorizes each exploit; never autonomous
    allow            — autonomous exploitation permitted (internal lab / explicit SoW)

``require_approval`` is the correct default for PUBLIC targets under an authorized
external engagement: real exploitation is in scope, but a human signs off on each one.

``AuthorizationPolicy`` maps hosts (exact, suffix-wildcard, or CIDR) to those records.
FAIL CLOSED is the whole point: a host matching no entry gets ``default``, which is
PASSIVE_ONLY unless the caller deliberately says otherwise.  An unknown host is never
implicitly authorized.

This module is PURE — no I/O, no network, no globals — so the policy is exhaustively
unit-testable and reviewable during engagement scoping.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Ceilings, least → most permissive.  Same tokens knowledge.safety_governor's
# ``ceiling`` argument understands, so a resolved authorization feeds straight into
# the existing governor with no new plumbing.
# Ordered least → most permissive.  "disruptive" MUST be here: it is the most
# permissive value the launch form offers, but it was missing, so ceiling_rank()
# hit its ValueError branch and returned 0 — the MOST restrictive.  Choosing the
# strongest ceiling in the UI therefore inverted to "safe" and denied every active
# tool on every host.  An unknown token still fails closed; the fix is that the
# UI's own vocabulary is no longer unknown.
CEILING_ORDER = ("safe", "light", "intrusive", "disruptive")

# Exploitation decisions (the tri-state).  These deliberately reuse the governor's own
# decision vocabulary so run_tool / the operator can route them without translation.
EXPLOIT_DENY = "deny"
EXPLOIT_APPROVAL = "require_approval"
EXPLOIT_ALLOW = "allow"
_EXPLOIT_RANK = {EXPLOIT_DENY: 0, EXPLOIT_APPROVAL: 1, EXPLOIT_ALLOW: 2}

OWNER_CLIENT = "client"            # the engagement's own asset — authorized per the SoW
OWNER_THIRD_PARTY = "third_party"  # someone else's infrastructure (CDN/cloud/mail/DNS)
OWNER_UNKNOWN = "unknown"          # ownership not established → treat as third party


def ceiling_rank(c: str) -> int:
    try:
        return CEILING_ORDER.index((c or "").strip().lower())
    except ValueError:
        return 0                   # unrecognised → most restrictive


def min_ceiling(a: str, b: str) -> str:
    """The more RESTRICTIVE of two ceilings, so a per-target grant can never exceed
    the engagement-wide ceiling the operator set for the whole run."""
    return CEILING_ORDER[min(ceiling_rank(a), ceiling_rank(b))]


def min_exploit(a: str, b: str) -> str:
    """The more RESTRICTIVE of two exploitation decisions."""
    ra = _EXPLOIT_RANK.get((a or "").strip().lower(), 0)
    rb = _EXPLOIT_RANK.get((b or "").strip().lower(), 0)
    for k, v in _EXPLOIT_RANK.items():
        if v == min(ra, rb):
            return k
    return EXPLOIT_DENY


def is_public_host(host: str, ips: Optional[Iterable[str]] = None) -> bool:
    """True when a target is (or is probably) on the PUBLIC internet.

    Public means the blast radius leaves the lab, so exploitation should be
    human-authorized rather than autonomous.  Deliberately fail-SAFE: anything not
    provably private/loopback/link-local counts as public, including a bare hostname
    we could not resolve.  Being wrong in this direction only adds a human check.
    """
    cands: List[str] = []
    h = (host or "").strip().lower()
    if h:
        cands.append(h)
    cands.extend(str(i) for i in (ips or []) if str(i).strip())
    saw_addr = False
    for c in cands:
        try:
            addr = ipaddress.ip_address(c.split("%")[0])
        except ValueError:
            continue
        saw_addr = True
        if not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_unspecified):
            return True            # any public address ⇒ public target
    if saw_addr:
        return False               # resolved, and every address was private
    return True                    # unresolved hostname ⇒ assume public (fail-safe)


@dataclass(frozen=True)
class TargetAuthorization:
    """What is authorized against ONE target."""
    ceiling:                str = "safe"          # safe | light | intrusive
    exploitation:           str = EXPLOIT_DENY    # deny | require_approval | allow
    bruteforce:             str = EXPLOIT_DENY    # same tri-state for credential attacks
    destructive_authorized: bool = False          # the governor's `authorized` (OT/destructive)
    owner:                  str = OWNER_UNKNOWN
    life_safety:            bool = False          # asset whose failure risks people
    domain:                 str = "IT"            # IT | OT
    public:                 bool = False          # on the public internet
    note:                   str = ""
    source:                 str = ""              # where this grant came from (audit trail)

    # Convenience for callers that only care "may this ever happen autonomously?"
    @property
    def autonomous_exploitation(self) -> bool:
        return self.exploitation == EXPLOIT_ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {"ceiling": self.ceiling, "exploitation": self.exploitation,
                "bruteforce": self.bruteforce,
                "destructive_authorized": self.destructive_authorized,
                "owner": self.owner, "life_safety": self.life_safety,
                "domain": self.domain, "public": self.public,
                "note": self.note, "source": self.source}

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "TargetAuthorization":
        d = d or {}
        return cls(
            ceiling=str(d.get("ceiling") or "safe").lower(),
            exploitation=str(d.get("exploitation") or EXPLOIT_DENY).lower(),
            bruteforce=str(d.get("bruteforce") or EXPLOIT_DENY).lower(),
            destructive_authorized=bool(d.get("destructive_authorized")),
            owner=str(d.get("owner") or OWNER_UNKNOWN),
            life_safety=bool(d.get("life_safety")),
            domain=str(d.get("domain") or "IT").upper(),
            public=bool(d.get("public")),
            note=str(d.get("note") or ""), source=str(d.get("source") or ""))

    def capped_by(self, engagement_ceiling: str,
                  engagement_exploitation: str = EXPLOIT_ALLOW) -> "TargetAuthorization":
        """Never exceed the run-wide limits the operator chose."""
        return replace(self,
                       ceiling=min_ceiling(self.ceiling, engagement_ceiling),
                       exploitation=min_exploit(self.exploitation, engagement_exploitation),
                       bruteforce=min_exploit(self.bruteforce, engagement_exploitation))


# ── Standard profiles ────────────────────────────────────────────────────────
# PASSIVE_ONLY — the fail-closed default: read what is already public, send nothing
# that could be construed as an attack.
PASSIVE_ONLY = TargetAuthorization(
    ceiling="safe", exploitation=EXPLOIT_DENY, bruteforce=EXPLOIT_DENY,
    owner=OWNER_UNKNOWN, note="passive/OSINT only — ownership or authorization unproven",
    source="profile:passive_only")

# ASSESS — active probing and vulnerability identification, no weaponisation at all.
ASSESS = TargetAuthorization(
    ceiling="light", exploitation=EXPLOIT_DENY, bruteforce=EXPLOIT_DENY,
    owner=OWNER_CLIENT, note="active assessment authorized; exploitation NOT authorized",
    source="profile:assess")

# EXTERNAL — the right default for a PUBLIC target under an authorized engagement:
# full-depth testing is in scope, but a HUMAN authorizes each exploit and each brute.
EXTERNAL = TargetAuthorization(
    ceiling="intrusive", exploitation=EXPLOIT_APPROVAL, bruteforce=EXPLOIT_APPROVAL,
    owner=OWNER_CLIENT, public=True,
    note="public target — exploitation authorized ONLY with per-action human approval",
    source="profile:external")

# FULL — autonomous exploitation (internal labs, SoWs that explicitly permit it).
FULL = TargetAuthorization(
    ceiling="intrusive", exploitation=EXPLOIT_ALLOW, bruteforce=EXPLOIT_ALLOW,
    owner=OWNER_CLIENT, note="full autonomous exploitation authorized",
    source="profile:full")

PROFILES: Dict[str, TargetAuthorization] = {
    "passive_only": PASSIVE_ONLY, "passive": PASSIVE_ONLY,
    "assess": ASSESS, "assessment": ASSESS, "vuln_assessment": ASSESS,
    "external": EXTERNAL, "public": EXTERNAL, "approve_to_exploit": EXTERNAL,
    "full": FULL, "internal": FULL, "lab": FULL, "red_team": FULL, "exploit": FULL,
}


def profile(name: str) -> TargetAuthorization:
    """Resolve a profile name; anything unrecognised falls back to PASSIVE_ONLY."""
    return PROFILES.get((name or "").strip().lower(), PASSIVE_ONLY)


def profile_for_target(host: str, ips: Optional[Iterable[str]] = None, *,
                       internal_profile: str = "full",
                       public_profile: str = "external") -> TargetAuthorization:
    """Pick the right profile from the target's own reachability class.

    A PUBLIC target gets ``public_profile`` (EXTERNAL — human approves each exploit);
    a provably private/lab address gets ``internal_profile`` (FULL — autonomous)."""
    if is_public_host(host, ips):
        return replace(profile(public_profile), public=True)
    return replace(profile(internal_profile), public=False)


# ── Host matching ────────────────────────────────────────────────────────────
def _norm(h: str) -> str:
    h = (h or "").strip().lower().rstrip(".")
    h = h.split("://", 1)[-1].split("/", 1)[0]
    if h.count(":") == 1:                 # strip :port, keep bare IPv6
        h = h.split(":", 1)[0]
    return h


def _match_specificity(pattern: str, host: str) -> int:
    """How specifically ``pattern`` matches ``host``; 0 = no match.  Higher wins, so an
    exact host beats a wildcard, which beats a broad CIDR."""
    p, h = _norm(pattern), _norm(host)
    if not p or not h:
        return 0
    if p == h:
        return 10_000                      # exact host
    if p.startswith("*."):
        suffix = p[1:]                     # ".example.com"
        return (1_000 + len(suffix)) if h.endswith(suffix) else 0
    try:
        net = ipaddress.ip_network(p, strict=False)
        addr = ipaddress.ip_address(h)
    except ValueError:
        return 0
    return (100 + net.prefixlen) if addr in net else 0


@dataclass
class AuthorizationPolicy:
    """Ordered host→authorization map with a FAIL-CLOSED default."""
    entries: List[Tuple[str, TargetAuthorization]] = field(default_factory=list)
    default: TargetAuthorization = PASSIVE_ONLY
    engagement_ceiling: str = "intrusive"          # run-wide ceiling cap
    engagement_exploitation: str = EXPLOIT_ALLOW   # run-wide exploitation cap

    def add(self, pattern: str, authz: TargetAuthorization) -> "AuthorizationPolicy":
        if _norm(pattern):
            self.entries.append((_norm(pattern), authz))
        return self

    def resolve(self, host: str) -> TargetAuthorization:
        """Authorization for ``host``.  Most specific entry wins; no match → ``default``
        (fail closed).  Always capped by the engagement-wide limits."""
        best, best_score = self.default, 0
        for pattern, authz in self.entries:
            score = _match_specificity(pattern, host)
            if score > best_score:
                best, best_score = authz, score
        if best_score == 0:
            best = replace(self.default,
                           note=(self.default.note or "") + f" (no entry for {_norm(host)})",
                           source=self.default.source or "default:unlisted")
        return best.capped_by(self.engagement_ceiling, self.engagement_exploitation)

    def to_dict(self) -> Dict[str, Any]:
        return {"entries": [{"pattern": p, "authz": a.to_dict()} for p, a in self.entries],
                "default": self.default.to_dict(),
                "engagement_ceiling": self.engagement_ceiling,
                "engagement_exploitation": self.engagement_exploitation}

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "AuthorizationPolicy":
        d = d or {}
        pol = cls(default=TargetAuthorization.from_dict(d.get("default")),
                  engagement_ceiling=str(d.get("engagement_ceiling") or "intrusive"),
                  engagement_exploitation=str(d.get("engagement_exploitation")
                                              or EXPLOIT_ALLOW))
        for e in (d.get("entries") or []):
            if isinstance(e, dict):
                pol.add(str(e.get("pattern") or ""),
                        TargetAuthorization.from_dict(e.get("authz")))
        return pol


# ── Builders ─────────────────────────────────────────────────────────────────
def policy_from_scope(
    scope_in: Iterable[str],
    *,
    engagement_profile: str = "external",
    engagement_ceiling: str = "intrusive",
    scope_out: Iterable[str] = (),
) -> AuthorizationPolicy:
    """Build a policy from the explicit authorized-scope list (the SoW).

    Hosts in ``scope_in`` get ``engagement_profile``; ``scope_out`` hosts are pinned to
    PASSIVE_ONLY with an explicit exclusion note; everything else falls to the
    fail-closed default.  This is what finally makes the scope list MEAN something at
    the execution boundary — previously scope defaulted to the target itself, so the
    governor's scope check could never fire."""
    base = profile(engagement_profile)
    pol = AuthorizationPolicy(default=PASSIVE_ONLY, engagement_ceiling=engagement_ceiling)
    for pat in scope_out or ():
        if str(pat).strip():
            pol.add(str(pat), replace(
                PASSIVE_ONLY, owner=OWNER_THIRD_PARTY,
                note="EXPLICITLY OUT OF SCOPE — passive only, never probed",
                source="scope_out"))
    for pat in scope_in or ():
        if str(pat).strip():
            pol.add(str(pat), replace(base, owner=OWNER_CLIENT, source="scope_in"))
    return pol


def policy_from_candidates(
    candidates: Iterable[Any],
    *,
    engagement_ceiling: str = "intrusive",
    internal_profile: str = "full",
    public_profile: str = "external",
    third_party_profile: str = "passive_only",
) -> AuthorizationPolicy:
    """Build a policy from the subdomain hunter's CLASSIFIED candidates.

    This is the fix for a label that was previously display-only:

      * ``third_party`` (or ownership not established) → ``third_party_profile``,
        PASSIVE_ONLY by default: the operator may still pick the host, but picking it
        no longer silently grants attack authority over someone else's infrastructure.
      * an in-apex host on a PUBLIC address → ``public_profile`` (EXTERNAL): full-depth
        testing, exploitation only with per-action human approval.
      * an in-apex host on a private/lab address → ``internal_profile`` (FULL).

    Accepts ``SubdomainCandidate`` objects or plain dicts.
    """
    tp = profile(third_party_profile)
    pol = AuthorizationPolicy(default=PASSIVE_ONLY, engagement_ceiling=engagement_ceiling)
    for c in candidates or ():
        get = (c.get if isinstance(c, dict) else lambda k, d=None: getattr(c, k, d))
        host = str(get("host", "") or "")
        if not host:
            continue
        ips = list(get("ips", []) or [])
        in_apex = bool(get("in_apex_network", False))
        third = bool(get("third_party", False))
        if in_apex and not third:
            base = profile_for_target(host, ips, internal_profile=internal_profile,
                                      public_profile=public_profile)
            pol.add(host, replace(base, owner=OWNER_CLIENT,
                                  note=f"in-apex asset — {base.note}",
                                  source="candidate:in_apex"))
        else:
            why = "flagged third-party" if third else "ownership not established"
            pol.add(host, replace(tp, owner=OWNER_THIRD_PARTY,
                                  public=is_public_host(host, ips),
                                  note=f"{why} — {tp.note}",
                                  source="candidate:third_party"))
    return pol


# ── Enforcement helper ───────────────────────────────────────────────────────
_BRUTE_MARKERS = ("hydra", "medusa", "patator", "--brute", "bruteforce", "brute-force",
                  "crackmapexec", "kerbrute", "spray", "ncrack")


# ── Human approval grants ────────────────────────────────────────────────────
# ``require_approval`` is a QUESTION, not a verdict — it means "a human must say
# yes before this happens".  The operator asks and the human answers, but that
# answer used to live only in an operator-local flag, so the enforcement point at
# base_agent.run_tool re-read the profile, still saw ``require_approval``, and
# refused the very action the human had just approved.  Approve-to-exploit could
# therefore never complete on a public target: the tri-state collapsed to a
# two-state deny and the whole point of "let the human authorize the exploit"
# was lost.
#
# A grant is the human's answer, carried to the boundary.  Deliberately narrow:
#
#   * SINGLE USE — consumed by the first matching call, so one click authorizes
#     one action, never a campaign.
#   * SHORT LIVED — a grant older than APPROVAL_TTL_SECONDS is ignored and
#     purged, so an approval cannot be banked and spent much later.
#   * ONLY satisfies ``require_approval``.  A ``deny`` is never satisfiable by a
#     grant: mid-scan the human answers a question, they do not overturn policy.
#     Changing what a host is allowed at all is a PRE-LAUNCH decision made at the
#     target-selection gate, where it is reviewed and recorded as an override.
#   * Created ONLY by the human-approval path.  Nothing an LLM emits reaches
#     grant_approval(), so a model cannot self-authorize.
#
# The match is (host, tool), not (host, tool, args): the operator approves an
# action described as an args DICT, which is rendered into a command STRING
# before it reaches the boundary, so the two sides have no common argument text
# to bind to.  Single-use plus a short TTL keeps the blast radius at exactly one
# invocation of that tool on that host — and the approved action is the next
# thing dispatched.  The args seen at approval time are recorded on the grant for
# the audit trail even though they are not part of the match.
APPROVAL_TTL_SECONDS = 900


def _approval_key(host: str, tool: str) -> str:
    return f"{str(host or '').strip().lower()}|{str(tool or '').strip().lower()}"


def purge_expired_approvals(store: Dict, *, now: Optional[float] = None) -> int:
    """Drop grants past their TTL.  Returns how many were removed."""
    if not isinstance(store, dict) or not store:
        return 0
    import time as _t
    _now = float(now if now is not None else _t.time())
    stale = [k for k, v in store.items()
             if not isinstance(v, dict)
             or (_now - float(v.get("granted_at") or 0)) > APPROVAL_TTL_SECONDS]
    for k in stale:
        store.pop(k, None)
    return len(stale)


def grant_approval(store: Dict, host: str, tool: str, *,
                   args: Any = None, now: Optional[float] = None) -> str:
    """Record that a HUMAN approved one run of ``tool`` against ``host``.

    Call ONLY from the human-approval path.  Returns the grant key.
    """
    import time as _t
    _now = float(now if now is not None else _t.time())
    purge_expired_approvals(store, now=_now)
    key = _approval_key(host, tool)
    store[key] = {"host": str(host or ""), "tool": str(tool or ""),
                  "granted_at": _now, "args": str(args or "")[:500]}
    return key


def consume_approval(store: Dict, host: str, tool: str, *,
                     now: Optional[float] = None) -> Optional[Dict]:
    """Spend a human grant for (host, tool).  Returns it, or None if there is none.

    Consuming REMOVES the grant — a second call for the same pair returns None
    until a human approves again.
    """
    if not isinstance(store, dict) or not store:
        return None
    import time as _t
    _now = float(now if now is not None else _t.time())
    purge_expired_approvals(store, now=_now)
    return store.pop(_approval_key(host, tool), None)


def check_action(authz: TargetAuthorization, *, intrusiveness: str,
                 tool_name: str = "", args: str = "") -> Tuple[str, str]:
    """Decide an action against ONE target's authorization.

    Returns ``(decision, reason)`` where decision is ``allow`` | ``require_approval`` |
    ``deny`` — the SAME vocabulary the safety governor already returns, so callers route
    it without translation.

    Deliberately narrow: this only ever ADDS restrictions the existing governor cannot
    express (per-target exploitation / brute-force consent, public-vs-lab blast radius).
    It never grants anything the governor would otherwise refuse.
    """
    intr = (intrusiveness or "light").strip().lower()
    blob = f"{tool_name} {args}".lower()
    who = f"{authz.owner}{' public' if authz.public else ''} target"
    tail = f" ({authz.note})" if authz.note else ""

    if ceiling_rank(intr) > ceiling_rank(authz.ceiling):
        return EXPLOIT_DENY, (f"action intrusiveness '{intr}' exceeds the per-target "
                              f"ceiling '{authz.ceiling}' for this {who}{tail}")
    if any(k in blob for k in _BRUTE_MARKERS):
        if authz.bruteforce == EXPLOIT_DENY:
            return EXPLOIT_DENY, (f"credential brute-force is NOT authorized against "
                                  f"this {who}{tail}")
        if authz.bruteforce == EXPLOIT_APPROVAL:
            return EXPLOIT_APPROVAL, (f"credential brute-force against this {who} "
                                      f"requires explicit human approval{tail}")
    if intr == "intrusive":
        if authz.exploitation == EXPLOIT_DENY:
            return EXPLOIT_DENY, (f"exploitation is NOT authorized against this "
                                  f"{who}{tail}")
        if authz.exploitation == EXPLOIT_APPROVAL:
            return EXPLOIT_APPROVAL, (f"exploitation against this {who} requires "
                                      f"explicit human approval — not autonomous{tail}")
    return EXPLOIT_ALLOW, ""


__all__ = [
    "TargetAuthorization", "AuthorizationPolicy",
    "PASSIVE_ONLY", "ASSESS", "EXTERNAL", "FULL", "PROFILES",
    "profile", "profile_for_target", "is_public_host",
    "policy_from_scope", "policy_from_candidates", "check_action",
    "grant_approval", "consume_approval", "purge_expired_approvals",
    "APPROVAL_TTL_SECONDS",
    "ceiling_rank", "min_ceiling", "min_exploit", "CEILING_ORDER",
    "EXPLOIT_DENY", "EXPLOIT_APPROVAL", "EXPLOIT_ALLOW",
    "OWNER_CLIENT", "OWNER_THIRD_PARTY", "OWNER_UNKNOWN",
]
