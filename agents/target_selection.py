"""
target_selection.py — human-in-the-loop gate for choosing scan targets.

Operator policy (matches the mandatory exploit-approval model): when ARGUS is
given a DOMAIN and hunts its subdomains across the public network, it must NOT
attack anything until a human reviews the discovered candidates and explicitly
selects which targets to engage.  The DomainReconOrchestrator registers a
selection request and blocks on it; the WebSocket/REST handler in agent_server
resolves it when the operator submits their picks in the Target Selection panel.

Fail-closed by design: a timeout, a missing request, or any error resolves to an
EMPTY selection — so the default outcome is to attack NOTHING (never auto-scan
the whole discovered surface without consent).

Intentionally tiny and dependency-free (stdlib asyncio only) so both the agent
process and the web server can import it cheaply.
"""
from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional


def normalize_selection(selected, allowed: Optional[List[str]] = None) -> List[str]:
    """Coerce operator input into a clean, de-duplicated list of target hosts.

    ``selected`` may be a list of host strings, a list of candidate dicts
    (``{"host": ...}``), a comma/space-separated string, or None.  When
    ``allowed`` is provided, any picked host NOT in the allowed set is dropped
    (the human can only select from what was actually discovered — prevents an
    injected/typo'd host from being scanned).  Returns [] for empty/garbage
    input (fail-closed).
    """
    out: List[str] = []
    if selected is None:
        return out
    if isinstance(selected, str):
        items = [p.strip() for p in selected.replace(",", " ").split()]
    elif isinstance(selected, (list, tuple, set)):
        items = []
        for it in selected:
            if isinstance(it, dict):
                h = str(it.get("host") or it.get("target") or it.get("name") or "").strip()
            else:
                h = str(it or "").strip()
            if h:
                items.append(h)
    else:
        return out

    allow = {a.strip().lower() for a in (allowed or [])} or None
    for h in items:
        hl = h.lower()
        if allow is not None and hl not in allow:
            continue
        if h not in out:
            out.append(h)
    return out


_ALLOWED_PROFILES = ("passive_only", "assess", "external", "full")


def normalize_authz(authz, allowed: Optional[List[str]] = None) -> Dict[str, str]:
    """Coerce the operator's PER-HOST authorization choices into {host: profile}.

    The human reviews each discovered host before launch and says how far ARGUS may
    go against it — the authorization the engagement actually grants for that asset.
    Only known profile names are accepted and only for hosts that were genuinely
    discovered; anything else is dropped, so an unrecognised value can never widen
    authority (the derived, fail-closed policy stands instead).
    """
    out: Dict[str, str] = {}
    if not isinstance(authz, dict):
        return out
    allow = {a.strip().lower() for a in (allowed or [])} or None
    for host, prof in authz.items():
        h = str(host or "").strip()
        p = str(prof or "").strip().lower()
        if not h or p not in _ALLOWED_PROFILES:
            continue
        if allow is not None and h.lower() not in allow:
            continue
        out[h] = p
    return out


class _PendingSelection:
    __slots__ = ("event", "selected", "authz", "allowed", "created_at")

    def __init__(self, allowed: Optional[List[str]] = None) -> None:
        self.event = asyncio.Event()
        self.selected: List[str] = []          # fail-closed default: nothing
        # Per-host authorization the operator reviewed/adjusted before launch.
        # Empty means "use the derived policy", which is itself fail-closed.
        self.authz: Dict[str, str] = {}
        self.allowed: List[str] = list(allowed or [])
        self.created_at = time.time()


# selection_id → pending request
_PENDING: Dict[str, _PendingSelection] = {}


def create_request(selection_id: str, allowed: Optional[List[str]] = None) -> _PendingSelection:
    """Register (or replace) a pending selection keyed by ``selection_id``.

    ``allowed`` is the set of discovered candidate hosts; picks are filtered to
    this set at resolve time so only genuinely-discovered targets are scannable.
    """
    p = _PendingSelection(allowed=allowed)
    _PENDING[selection_id] = p
    return p


async def await_selection(selection_id: str, timeout: float) -> List[str]:
    """Block until the operator submits a selection or ``timeout`` elapses.

    Returns the chosen host list.  Timeout / missing request / error all return
    [] (fail-closed — nothing is attacked without an explicit pick).

    Kept returning a bare list for backwards compatibility; callers that also want
    the operator's per-host authorization choices use ``await_decision``.
    """
    decision = await await_decision(selection_id, timeout)
    return decision[0]


async def await_decision(selection_id: str, timeout: float
                         ) -> "tuple[List[str], Dict[str, str]]":
    """Like ``await_selection`` but also returns the reviewed PER-HOST authorization.

    Returns ``(selected_hosts, {host: profile})``.  On timeout/missing request the
    selection is empty, so nothing is attacked and the authorization map is moot."""
    p = _PENDING.get(selection_id) or create_request(selection_id)
    try:
        await asyncio.wait_for(p.event.wait(), timeout=timeout)
        return list(p.selected), dict(p.authz)
    except asyncio.TimeoutError:
        return [], {}
    finally:
        _PENDING.pop(selection_id, None)


async def await_decision_gated(selection_id: str, timeout: float, *,
                               is_paused=None, poll: float = 1.0
                               ) -> "tuple[List[str], Dict[str, str]]":
    """``await_decision`` where time spent PAUSED does not count against the clock.

    The pick window is long (30 min by default) but it used to keep ticking while
    the operator had the run paused — so pausing to go and confirm scope with the
    client could expire the gate, and expiry means "select nothing".  The operator
    stopped the clock; the clock should stop.

    ``is_paused`` is a zero-arg predicate.  Timing out still fails CLOSED with an
    empty selection, and the pending request is consumed exactly once, so this
    cannot be used to poll the gate open.
    """
    p = _PENDING.get(selection_id) or create_request(selection_id)
    try:
        remaining = float(timeout)
        while remaining > 0:
            if is_paused is not None and is_paused():
                await asyncio.sleep(poll)          # paused: spend no budget
                continue
            step = min(poll, remaining)
            try:
                await asyncio.wait_for(p.event.wait(), timeout=step)
                return list(p.selected), dict(p.authz)
            except asyncio.TimeoutError:
                remaining -= step
        return [], {}
    finally:
        _PENDING.pop(selection_id, None)


def resolve(selection_id: str, selected, authz=None) -> bool:
    """Resolve a pending selection with the operator's picks.

    ``selected`` is normalized and filtered to the request's allowed candidate set.
    ``authz`` is the operator's reviewed per-host authorization ({host: profile}),
    also filtered to discovered hosts and known profiles.  Returns True if a request
    was actually waiting.
    """
    p = _PENDING.get(selection_id)
    if p is None:
        return False
    p.selected = normalize_selection(selected, allowed=p.allowed)
    p.authz = normalize_authz(authz, allowed=p.allowed)
    p.event.set()
    return True


def pending_ids() -> list:
    """Currently-waiting selection ids (for diagnostics / UI reconciliation)."""
    return list(_PENDING.keys())


__all__ = [
    "normalize_selection", "normalize_authz", "create_request",
    "await_selection", "await_decision", "resolve", "pending_ids",
]
