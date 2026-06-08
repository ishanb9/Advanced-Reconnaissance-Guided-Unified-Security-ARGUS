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


class _PendingSelection:
    __slots__ = ("event", "selected", "allowed", "created_at")

    def __init__(self, allowed: Optional[List[str]] = None) -> None:
        self.event = asyncio.Event()
        self.selected: List[str] = []          # fail-closed default: nothing
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
    """
    p = _PENDING.get(selection_id) or create_request(selection_id)
    try:
        await asyncio.wait_for(p.event.wait(), timeout=timeout)
        return list(p.selected)
    except asyncio.TimeoutError:
        return []
    finally:
        _PENDING.pop(selection_id, None)


def resolve(selection_id: str, selected) -> bool:
    """Resolve a pending selection with the operator's picks.

    ``selected`` is normalized and filtered to the request's allowed candidate
    set.  Returns True if a request was actually waiting.
    """
    p = _PENDING.get(selection_id)
    if p is None:
        return False
    p.selected = normalize_selection(selected, allowed=p.allowed)
    p.event.set()
    return True


def pending_ids() -> list:
    """Currently-waiting selection ids (for diagnostics / UI reconciliation)."""
    return list(_PENDING.keys())


__all__ = [
    "normalize_selection", "create_request", "await_selection",
    "resolve", "pending_ids",
]
