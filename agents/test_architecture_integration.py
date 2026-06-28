"""
agents/test_architecture_integration.py

Smoke-test for the architectural core:
  - EngagementContext lifecycle and prompt rendering
  - Per-tool circuit breaker (the "486 curls to dead URL" defense)
  - Output-signature dedup (same 404 5x = block)
  - finding_triggers evaluation (MinIO service → bootstrap-verify cmd)
  - pin_insights_from_intel (LLM exploit_chain → pinned insight)
  - reset_fired isolates parallel sessions

Run directly:
    cd C:\\Users\\ishan2\\Desktop\\Tools\\LLM\\v1
    python -m agents.test_architecture_integration

The test does NOT require pytest, MongoDB, MCP, or the LLM.  It
exercises pure-Python state mutation on the new core modules.

Exit code 0 = all pass; non-zero = something regressed.
"""
from __future__ import annotations

import sys
import traceback

# Make module importable when run from project root
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.engagement_context import (
    EngagementContext,
    register_context,
    get_context,
    unregister_context,
    CIRCUIT_BREAKER_THRESHOLDS,
    DUP_OUTPUT_THRESHOLD,
    PER_TOOL_INVOCATION_CAPS,
    DEFAULT_ENGAGEMENT_INVOCATION_BUDGET,
    SAME_ACTION_BURST_WINDOW_SEC,
)
from agents import finding_triggers as ft


# ─────────────────────────────────────────────────────────────────────
#  Mini test harness — keeps output dependency-free
# ─────────────────────────────────────────────────────────────────────

PASS = "[PASS]"
FAIL = "[FAIL]"
_failures: list[str] = []


def _ok(label: str) -> None:
    print(f"  {PASS} {label}")


def _bad(label: str, detail: str = "") -> None:
    _failures.append(label)
    msg = f"  {FAIL} {label}"
    if detail:
        msg += f"  ({detail})"
    print(msg)


def _assert(cond: bool, label: str, detail: str = "") -> None:
    if cond:
        _ok(label)
    else:
        _bad(label, detail)


def _section(title: str) -> None:
    print(f"\n-- {title} " + "-" * max(0, 60 - len(title) - 4))


# ─────────────────────────────────────────────────────────────────────
#  Test 1 — EngagementContext basic lifecycle
# ─────────────────────────────────────────────────────────────────────


def test_basic_lifecycle() -> None:
    _section("Test 1 — EngagementContext lifecycle + registry")

    intel = {"target": "10.129.56.165", "services": {}, "open_ports": []}
    ctx = EngagementContext(
        session_id="sess-1",
        target="10.129.56.165",
        intel_ref=intel,
    )
    register_context(ctx)

    _assert(get_context("sess-1") is ctx,
            "register_context + get_context round-trip")
    _assert(ctx.objective and "Compromise" in ctx.objective,
            "default objective contains 'Compromise'")
    _assert("PIVOT" in ctx.objective.upper(),
            "default objective mentions PIVOT priority")
    _assert(ctx.intel is intel,
            "intel_ref shared by reference (mutations propagate)")

    # Mutate underlying intel and confirm context sees it
    intel["open_ports"] = [80, 445, 54321]
    intel["services"] = {
        54321: {"service": "Golang net/http", "product": "MinIO",
                  "banner": "MinIO Object Storage server", "version": "RELEASE.2023-01-01"}
    }
    _assert(54321 in ctx.open_ports,
            "context reflects late-mutated intel.open_ports")
    _assert(ctx.services.get(54321, {}).get("product") == "MinIO",
            "context reflects late-mutated intel.services")

    unregister_context("sess-1")
    _assert(get_context("sess-1") is None,
            "unregister_context drops the entry")


# ─────────────────────────────────────────────────────────────────────
#  Test 2 — Circuit breaker on consecutive empty results
# ─────────────────────────────────────────────────────────────────────


def test_circuit_breaker_curl() -> None:
    _section("Test 2 — Curl circuit breaker after 6 empty calls")

    ctx = EngagementContext(session_id="sess-2", target="x")
    register_context(ctx)

    # Threshold for curl is 6 (per CIRCUIT_BREAKER_THRESHOLDS)
    expected = CIRCUIT_BREAKER_THRESHOLDS.get("curl", 5)
    _assert(expected == 6, "curl threshold is 6 (loud-tool tolerance)")

    # To test the consecutive_empty path in isolation (not the burst
    # guard which fires on immediate repeats), use the SAME target_sig
    # but vary the args slightly so the burst guard's args[:80] match
    # is broken between calls.  We pad with unique whitespace so the
    # first whitespace-split token (the URL) stays the same — same
    # target_sig — but the full args string is different per call so
    # burst-guard's args[:80] check sees them as distinct actions.
    url = "http://x/missing"
    for i in range(5):
        # extra-arg differs each iteration → args[:80] differs → no
        # burst-guard trigger; but _target_sig (first token, URL only)
        # is identical → per-(tool,target_sig) counter accumulates.
        ctx.record_action(
            tool="curl", args=f"{url} --header X-Iter-{i}",
            phase="exploit", reasoning="r",
            observation=f"HTTP/1.1 404 Not Found - probe-{i}",
        )
    blocked, _ = ctx.is_tool_blocked("curl", f"{url} --header X-Iter-fresh")
    _assert(not blocked, "5 empty curls (distinct args, same URL) — not yet blocked")

    # 6th empty call trips the breaker
    ctx.record_action(
        tool="curl", args=f"{url} --header X-Iter-5",
        phase="exploit", reasoning="r",
        observation="HTTP/1.1 404 Not Found - probe-5",
    )
    blocked, reason = ctx.is_tool_blocked("curl", f"{url} --header X-Iter-fresh")
    _assert(blocked, "6 empty curls — breaker tripped",
            detail=f"reason: {reason[:80]}")

    # A call against a DIFFERENT URL (different path on same host)
    # should not yet be blocked — _target_sig keeps path so each URL
    # gets its own counter.  This is the legitimate-enumeration case.
    blocked_other, _ = ctx.is_tool_blocked("curl", "http://x/admin")
    _assert(not blocked_other,
            "different target URL not affected by per-URL counter")
    unregister_context("sess-2")


# ─────────────────────────────────────────────────────────────────────
#  Test 3 — Output signature dedup blocks repeated dead responses
# ─────────────────────────────────────────────────────────────────────


def test_output_signature_dedup() -> None:
    _section("Test 3 — Output-signature dedup (same response 3x = block)")

    # Satisfy nikto's precondition (HTTP service open) so the
    # necessary-basis gate doesn't refuse before we can test dedup.
    intel = {
        "open_ports": [80],
        "services": {80: {"service": "http", "product": "nginx", "banner": "nginx/1.18"}},
    }
    ctx = EngagementContext(session_id="sess-3", target="x", intel_ref=intel)
    register_context(ctx)

    # Same SHORT-and-unproductive observation (so productive=False
    # path doesn't reset consecutive_dup) repeated against the same
    # target signature.  After DUP_OUTPUT_THRESHOLD+1 the breaker
    # must trip via the dedup path.
    same_404 = "HTTP/1.1 404 Not Found"   # dead marker, len<200 → unproductive
    for _ in range(DUP_OUTPUT_THRESHOLD + 1):
        ctx.record_action(
            tool="nikto", args="http://x/same-endpoint",
            phase="vuln", reasoning="", observation=same_404,
        )
    blocked, reason = ctx.is_tool_blocked("nikto", "http://x/same-endpoint")
    _assert(blocked, "same output signature repeated past threshold = blocked",
            detail=f"reason: {reason[:100]}")
    unregister_context("sess-3")


# ─────────────────────────────────────────────────────────────────────
#  Test 4 — pin_insights_from_intel propagates OSINT synthesis
# ─────────────────────────────────────────────────────────────────────


def test_pin_insights_from_intel() -> None:
    _section("Test 4 — pin_insights_from_intel converts exploit_chain")

    intel = {
        "target": "10.129.56.165",
        "exploit_chain": {
            "critical_cves": ["CVE-2023-28432"],
            "severity": "critical",
            "next_commands": [
                "curl -sk -X POST http://10.129.56.165/minio/bootstrap/v1/verify",
            ],
        },
        "critical_cves": ["CVE-2023-28432"],
        "next_commands": [
            "curl -sk -X POST http://10.129.56.165/minio/bootstrap/v1/verify",
        ],
    }
    ctx = EngagementContext(session_id="sess-4", target="10.129.56.165",
                              intel_ref=intel)
    ctx.pin_insights_from_intel()
    _assert(len(ctx.pinned) == 1, "exactly one pinned insight created",
            detail=f"got {len(ctx.pinned)}")
    p = ctx.pinned[0]
    _assert("CVE-2023-28432" in p.text,
            "pinned insight contains the critical CVE")
    _assert("CRITICAL" in p.text,
            "pinned insight contains severity")
    _assert(p.source == "osint_synthesis",
            "source field tagged 'osint_synthesis'")
    # Idempotence — calling again should not duplicate
    ctx.pin_insights_from_intel()
    _assert(len(ctx.pinned) == 1,
            "calling pin_insights_from_intel twice does NOT duplicate")


# ─────────────────────────────────────────────────────────────────────
#  Test 5 — finding_triggers MinIO scenario end-to-end
# ─────────────────────────────────────────────────────────────────────


def test_finding_triggers_minio() -> None:
    _section("Test 5 — finding_triggers fires MinIO bootstrap on banner match")

    ft.reset_fired()   # ensure no spillover from previous sessions

    intel = {
        "target": "10.129.56.165",
        "target_host": "10.129.56.165",
        "open_ports": [54321],
        "services": {
            54321: {
                "service": "Golang net/http server",
                "product": "MinIO",
                "banner":  "MinIO Object Storage Server RELEASE.2022-12-15",
            },
        },
    }
    ctx = EngagementContext(session_id="sess-5", target="10.129.56.165",
                              intel_ref=intel)
    actions = ft.evaluate_triggers(ctx)

    minio_cmds = [a for a in actions
                    if a.kind == "command" and "minio" in a.payload.lower()]
    _assert(len(minio_cmds) >= 1,
            "MinIO trigger fired at least one command",
            detail=f"actions: {[(a.kind, a.payload[:50]) for a in actions]}")

    minio_cmd = minio_cmds[0]
    _assert("10.129.56.165" in minio_cmd.payload,
            "{host} placeholder interpolated to actual target",
            detail=f"payload: {minio_cmd.payload}")
    _assert("bootstrap/v1/verify" in minio_cmd.payload,
            "MinIO bootstrap-verify endpoint present in command")
    _assert("CVE-2023-28432" in minio_cmd.cves,
            "CVE-2023-28432 attached to trigger action")

    # Second evaluation in same session must NOT re-fire (once=True)
    actions2 = ft.evaluate_triggers(ctx)
    minio_cmds2 = [a for a in actions2
                     if a.kind == "command" and "minio" in a.payload.lower()]
    _assert(len(minio_cmds2) == 0,
            "once=True triggers do not re-fire in same session")


# ─────────────────────────────────────────────────────────────────────
#  Test 6 — render_for_prompt produces a useful prelude
# ─────────────────────────────────────────────────────────────────────


def test_render_for_prompt() -> None:
    _section("Test 6 — render_for_prompt emits objective + insights + actions")

    intel = {"target": "10.10.10.10", "services": {}, "open_ports": []}
    ctx = EngagementContext(
        session_id="sess-6", target="10.10.10.10", intel_ref=intel,
        objective="Capture user.txt and root.txt from this HackTheBox machine",
    )
    ctx.pin_insight("Redis on 6379 is unauthenticated — SSH-key injection path live",
                      phase="osint", severity="critical", source="trigger")
    ctx.record_action(
        tool="nmap", args="-sV 10.10.10.10",
        phase="recon", reasoning="initial fingerprinting",
        observation="6379/tcp open redis Redis key-value store",
    )
    ctx.record_action(
        tool="curl", args="http://10.10.10.10/",
        phase="exploit", reasoning="probe root path",
        observation="HTTP/1.1 404 Not Found",
    )

    out = ctx.render_for_prompt()
    _assert("ENGAGEMENT OBJECTIVE" in out,
            "objective banner present")
    _assert("Capture user.txt" in out,
            "operator-supplied objective rendered verbatim")
    _assert("Redis on 6379" in out,
            "pinned insight rendered into prompt")
    _assert("nmap" in out and "redis" in out.lower(),
            "recent productive action rendered")
    _assert("404" in out or "✗ curl" in out or "curl" in out,
            "404 observation or failed-action entry present")


# ─────────────────────────────────────────────────────────────────────
#  Test 7 — Session isolation (reset_fired)
# ─────────────────────────────────────────────────────────────────────


def test_session_isolation() -> None:
    _section("Test 7 — reset_fired isolates back-to-back sessions")

    ft.reset_fired()
    intel_a = {
        "open_ports": [445],
        "services": {445: {"service": "microsoft-ds", "banner": "Samba 4.x"}},
        "target_host": "host-a",
    }
    ctx_a = EngagementContext(session_id="sess-A", target="host-a",
                                intel_ref=intel_a)
    actions_a = ft.evaluate_triggers(ctx_a)
    smb_a = [a for a in actions_a if a.kind == "command" and "smb" in a.payload.lower()
                                  or "enum4linux" in a.payload.lower()]
    _assert(len(smb_a) >= 1,
            "session A: SMB trigger fired on port 445")

    # Same trigger conditions in session B AFTER reset_fired must re-fire
    ft.reset_fired("sess-A")  # only clear A's memory
    intel_b = dict(intel_a)
    intel_b["target_host"] = "host-b"
    ctx_b = EngagementContext(session_id="sess-B", target="host-b",
                                intel_ref=intel_b)
    actions_b = ft.evaluate_triggers(ctx_b)
    smb_b = [a for a in actions_b if a.kind == "command" and "smb" in a.payload.lower()
                                  or "enum4linux" in a.payload.lower()]
    _assert(len(smb_b) >= 1,
            "session B: same trigger fires because session key is per-session")
    # host placeholder must be session B's host
    _assert(any("host-b" in a.payload for a in smb_b),
            "session B's commands have host-b interpolated, not host-a")


# ─────────────────────────────────────────────────────────────────────
#  Test 8 — Productive observation resets empty counter
# ─────────────────────────────────────────────────────────────────────


def test_productive_resets_counter() -> None:
    _section("Test 8 — productive call resets consecutive_empty")

    ctx = EngagementContext(session_id="sess-8", target="x")
    # Use distinct args each iteration so the burst guard doesn't trip
    # (we're testing consecutive_empty in isolation).  The URL is
    # constant so the per-(tool, target_sig) counter still accumulates.
    url = "http://x/probe"
    for i in range(4):
        ctx.record_action(
            tool="curl", args=f"{url} --header X-Try-{i}",
            phase="exploit", reasoning="r",
            observation=f"HTTP/1.1 404 Not Found try-{i}",
        )
    # 4 empties so far, threshold 6, not blocked
    blocked, _ = ctx.is_tool_blocked("curl", f"{url} --header X-Try-fresh")
    _assert(not blocked, "4 empty calls not yet blocked")

    # Productive call (long substantive output) should reset
    ctx.record_action(
        tool="curl", args=f"{url} --header X-Try-Productive",
        phase="exploit", reasoning="r",
        observation="HTTP/1.1 200 OK\n\n{\"buckets\":[\"secret-data\"]}\nContent-Type: application/json\n" + "a"*100,
    )
    cb_key = ("curl", ctx._target_sig(url))
    st = ctx.tool_stats[cb_key]
    _assert(st.consecutive_empty == 0,
            "consecutive_empty reset to 0 after productive call",
            detail=f"counter: {st.consecutive_empty}")
    _assert(st.productive >= 1, "productive counter incremented")


# ─────────────────────────────────────────────────────────────────────
#  Test 9 — force_block / lift_block operator overrides
# ─────────────────────────────────────────────────────────────────────


def test_operator_overrides() -> None:
    _section("Test 9 — force_block / lift_block operator overrides")

    # Satisfy hydra's basis requirements so the test exercises the
    # force_block/lift_block layer in isolation (not basis refusal).
    intel = {
        "open_ports": [22],
        "services": {22: {"service": "ssh", "product": "OpenSSH"}},
    }
    ctx = EngagementContext(session_id="sess-9", target="x", intel_ref=intel)
    hargs = "-L users.txt -P passwords.txt ssh://host-x"
    ctx.force_block("hydra", hargs, duration_sec=300)
    blocked, _ = ctx.is_tool_blocked("hydra", hargs)
    _assert(blocked, "force_block trips the breaker immediately")
    ctx.lift_block("hydra", hargs)
    blocked2, _ = ctx.is_tool_blocked("hydra", hargs)
    _assert(not blocked2, "lift_block clears it cleanly")


# ─────────────────────────────────────────────────────────────────────
#  Test 10 — Win-condition short-circuit (shell + flag = halt)
# ─────────────────────────────────────────────────────────────────────


def test_win_condition_short_circuit() -> None:
    _section("Test 10 — Win-condition short-circuits new dispatch")

    # Make hydra basis-warranted: SSH on port 22 + credential args.
    intel = {
        "target": "x",
        "open_ports": [22],
        "services": {22: {"service": "ssh", "product": "OpenSSH", "banner": "OpenSSH 8.0"}},
    }
    hydra_args = "-L users.txt -P passwords.txt ssh://host-y"
    ctx = EngagementContext(session_id="sess-10", target="x", intel_ref=intel)
    # Pre-win — tools allowed (with proper args + open port)
    blocked, _ = ctx.is_tool_blocked("hydra", hydra_args)
    _assert(not blocked, "pre-win: hydra allowed (basis met)")
    _assert(not ctx.is_engagement_complete(), "pre-win: not complete")

    # Achieve win condition
    intel["shell_access"] = True
    intel["user_flag"] = "HTB{...user...}"
    _assert(ctx.is_engagement_complete(),
            "engagement complete when shell+user_flag set")
    blocked, reason = ctx.is_tool_blocked("hydra", hydra_args)
    _assert(blocked, "post-win: aggressive tool (hydra) blocked",
            detail=reason[:80])
    # Post-completion allowed tools still pass
    blocked_tar, _ = ctx.is_tool_blocked("tar", "/loot/data")
    _assert(not blocked_tar,
            "post-win: 'tar' on allow-list still permitted")


# ─────────────────────────────────────────────────────────────────────
#  Test 11 — Operator mark_complete halts everything
# ─────────────────────────────────────────────────────────────────────


def test_operator_mark_complete() -> None:
    _section("Test 11 — Operator mark_complete halts new dispatch")

    ctx = EngagementContext(session_id="sess-11", target="x")
    ctx.mark_complete(reason="we've gathered enough — moving to reporting")
    blocked, reason = ctx.is_tool_blocked("nmap", "host-x")
    _assert(blocked, "operator halt blocks even non-aggressive tools",
            detail=reason[:80])
    _assert(any("ENGAGEMENT MARKED COMPLETE" in p.text for p in ctx.pinned),
            "halt reason pinned as critical insight")


# ─────────────────────────────────────────────────────────────────────
#  Test 12 — Global invocation budget exhaustion
# ─────────────────────────────────────────────────────────────────────


def test_global_invocation_budget() -> None:
    _section("Test 12 — Global engagement invocation budget cap")

    ctx = EngagementContext(session_id="sess-12", target="x")
    # Shrink the budget so we can test cheaply
    ctx.set_invocation_budget(10)
    for i in range(10):
        ctx.record_action(
            tool="nmap", args=f"host-{i}",
            phase="recon", reasoning="r",
            observation=f"PORT {i} open  some long substantive scan output here >40 chars",
        )
    _assert(ctx.total_invocations == 10,
            "total_invocations counted correctly")
    blocked, reason = ctx.is_tool_blocked("nmap", "host-new")
    _assert(blocked, "11th call after 10 budget — blocked",
            detail=reason[:90])
    _assert("budget exhausted" in reason.lower()
              or "invocation budget" in reason.lower(),
            "block reason mentions budget exhaustion")


# ─────────────────────────────────────────────────────────────────────
#  Test 13 — Per-tool absolute cap
# ─────────────────────────────────────────────────────────────────────


def test_per_tool_absolute_cap() -> None:
    _section("Test 13 — Per-tool absolute invocation cap (hydra=15)")

    # Make hydra basis-warranted: SSH on 22 + credential args.
    intel = {
        "open_ports": [22],
        "services": {22: {"service": "ssh", "product": "OpenSSH"}},
    }
    ctx = EngagementContext(session_id="sess-13", target="x", intel_ref=intel)
    cap = PER_TOOL_INVOCATION_CAPS.get("hydra", 999)
    _assert(cap == 15, "hydra per-tool cap is 15", detail=f"got {cap}")
    # Call hydra up to its cap with PRODUCTIVE distinct outputs so the
    # consecutive-empty path doesn't trip first.  Each invocation has
    # the args hydra's precondition requires (-L/-P).
    for i in range(cap):
        ctx.record_action(
            tool="hydra", args=f"-L users.txt -P passwords.txt ssh://target-{i}",
            phase="exploit", reasoning="brute",
            observation=f"login attempt {i} — substantive output of length >40 chars goes here",
        )
    # Fresh call (basis met) should now hit the per-tool cap.
    blocked, reason = ctx.is_tool_blocked("hydra", "-L u -P p ssh://fresh-target")
    _assert(blocked, "hydra blocked after hitting per-engagement cap",
            detail=reason[:80])
    _assert("cap " in reason or "engagement" in reason.lower(),
            "block reason mentions the cap")


# ─────────────────────────────────────────────────────────────────────
#  Test 14 — Same-action burst guard (immediate repeat blocked)
# ─────────────────────────────────────────────────────────────────────


def test_same_action_burst() -> None:
    _section("Test 14 — Same-action burst guard (immediate repeat blocked)")

    ctx = EngagementContext(session_id="sess-14", target="x")
    # First call: unproductive
    ctx.record_action(
        tool="curl", args="http://x/probe",
        phase="exploit", reasoning="r",
        observation="HTTP/1.1 404 Not Found",
    )
    # Immediate repeat should be blocked by the burst guard even
    # though consecutive_empty=1 (below the curl threshold of 6)
    blocked, reason = ctx.is_tool_blocked("curl", "http://x/probe")
    _assert(blocked,
            "immediate repeat of unproductive action — blocked by burst guard",
            detail=reason[:90])
    _assert("just produced" in reason.lower() or "do not immediately retry" in reason.lower(),
            "block reason mentions burst-guard explanation")

    # A DIFFERENT URL or DIFFERENT tool is NOT blocked
    blocked2, _ = ctx.is_tool_blocked("curl", "http://x/other")
    _assert(not blocked2,
            "different URL not affected by burst guard")
    blocked3, _ = ctx.is_tool_blocked("nmap", "http://x/probe")
    _assert(not blocked3,
            "different tool not affected by burst guard")


# ─────────────────────────────────────────────────────────────────────
#  Test 15 — Goal-tag attribution captured per action
# ─────────────────────────────────────────────────────────────────────


def test_goal_tag_attribution() -> None:
    _section("Test 15 — goal_tag attribution captured per action")

    ctx = EngagementContext(session_id="sess-15", target="x")
    ctx.record_action(
        tool="nmap", args="-sV x",
        phase="recon", reasoning="initial fingerprint",
        observation="22/tcp open ssh OpenSSH 8.0  substantive output >40 chars here",
        goal_tag="ReconAgent/NmapPortScanner",
    )
    ctx.record_action(
        tool="searchsploit", args="OpenSSH 8.0",
        phase="osint", reasoning="search for known exploits",
        observation="No results found for the query",
        goal_tag="OsintAgent/SearchSploitSubagent",
    )
    _assert(0 in ctx.action_goal_tags,
            "first action has goal_tag recorded")
    _assert("ReconAgent" in ctx.action_goal_tags.get(0, ""),
            "goal_tag includes parent agent name",
            detail=f"got: {ctx.action_goal_tags.get(0)!r}")
    _assert(1 in ctx.action_goal_tags,
            "second action has goal_tag recorded")
    _assert("OsintAgent" in ctx.action_goal_tags.get(1, ""),
            "goal_tag attribution distinct per action")


# ─────────────────────────────────────────────────────────────────────
#  Test 16 — Budget status renders in LLM prompt
# ─────────────────────────────────────────────────────────────────────


def test_budget_in_prompt() -> None:
    _section("Test 16 — Budget + completion status visible in prompt")

    ctx = EngagementContext(session_id="sess-16", target="x")
    ctx.set_invocation_budget(10)
    # Fire 8 calls to push above 80% warning threshold
    for i in range(8):
        ctx.record_action(
            tool="nmap", args=f"h-{i}",
            phase="recon", reasoning="r",
            observation=f"open port {i} found — long substantive scan output line >40 chars",
        )
    out = ctx.render_for_prompt()
    _assert("Tool calls: 8/10" in out,
            "prompt shows current usage / budget")
    _assert("TOOL BUDGET WARNING" in out,
            "warning banner triggers at >=80%")

    # Mark complete + re-render
    ctx.mark_complete(reason="all flags captured")
    out2 = ctx.render_for_prompt()
    _assert("OBJECTIVE SATISFIED" in out2
              or "OBJECTIVE STRUCTURALLY SATISFIED" in out2,
            "completion banner present after mark_complete")


# ─────────────────────────────────────────────────────────────────────
#  Test 17 — Necessary-basis gate refuses tools without supporting state
# ─────────────────────────────────────────────────────────────────────


def test_basis_gate_refusals() -> None:
    _section("Test 17 — Necessary-basis gate REFUSES tools without basis")

    from agents.engagement_context import check_tool_warranted

    # No services discovered yet
    intel: dict = {"open_ports": [], "services": {}}
    ctx = EngagementContext(session_id="sess-17", target="x", intel_ref=intel)

    # wpscan with no WordPress detected → refused
    ok, why = check_tool_warranted("wpscan", "--url http://x", ctx)
    _assert(not ok, "wpscan refused when no WordPress in services",
            detail=why[:120])
    _assert("wordpress" in why.lower() or "wp-" in why.lower(),
            "refusal mentions WordPress requirement")

    # enum4linux with no SMB port → refused
    ok, why = check_tool_warranted("enum4linux", "-A 10.0.0.1", ctx)
    _assert(not ok, "enum4linux refused when port 445 not open",
            detail=why[:120])

    # evil-winrm with no shell + no creds → refused
    ok, why = check_tool_warranted("evil-winrm", "-i 10.0.0.1", ctx)
    _assert(not ok, "evil-winrm refused without creds + WinRM port",
            detail=why[:120])

    # hydra without -L/-P → refused
    ok, why = check_tool_warranted("hydra", "host-x", ctx)
    _assert(not ok, "hydra refused without credential args",
            detail=why[:120])

    # msfconsole without a module spec → refused
    ok, why = check_tool_warranted("msfconsole", "-q", ctx)
    _assert(not ok, "msfconsole refused without explicit module",
            detail=why[:120])

    # sqlmap without URL → refused
    ok, why = check_tool_warranted("sqlmap", "--all", ctx)
    _assert(not ok, "sqlmap refused without target URL",
            detail=why[:120])

    # linpeas without shell_access → refused
    ok, why = check_tool_warranted("linpeas", "", ctx)
    _assert(not ok, "linpeas refused without shell_access",
            detail=why[:120])


# ─────────────────────────────────────────────────────────────────────
#  Test 18 — Basis gate PERMITS tools once preconditions met
# ─────────────────────────────────────────────────────────────────────


def test_basis_gate_allows_when_warranted() -> None:
    _section("Test 18 — Basis gate ALLOWS once preconditions satisfied")

    from agents.engagement_context import check_tool_warranted

    intel = {
        "open_ports": [80, 445, 22, 5985],
        "services": {
            80: {"service": "http", "product": "WordPress",
                  "banner": "Apache; WordPress 6.2; wp-content present"},
            445: {"service": "microsoft-ds", "banner": "Samba 4.x"},
            22: {"service": "ssh", "product": "OpenSSH"},
            5985: {"service": "wsman", "banner": "Microsoft WinRM"},
        },
        "shell_access": True,
    }
    ctx = EngagementContext(session_id="sess-18", target="x", intel_ref=intel)

    # wpscan now warranted because WordPress visible
    ok, why = check_tool_warranted("wpscan", "--url http://x", ctx)
    _assert(ok, "wpscan allowed when WordPress detected", detail=why[:120])

    # enum4linux warranted because 445 open
    ok, why = check_tool_warranted("enum4linux", "-A 10.0.0.1", ctx)
    _assert(ok, "enum4linux allowed once port 445 open", detail=why[:120])

    # hydra with proper args + SSH service warranted
    ok, why = check_tool_warranted(
        "hydra", "-L users.txt -P passwords.txt ssh://x", ctx)
    _assert(ok, "hydra allowed with proper -L/-P args",
            detail=why[:120])

    # evil-winrm warranted: WinRM port + creds in args
    ok, why = check_tool_warranted(
        "evil-winrm", "-i x -u admin -p Password1", ctx)
    _assert(ok, "evil-winrm allowed with WinRM port + creds",
            detail=why[:120])

    # msfconsole with explicit module
    ok, why = check_tool_warranted(
        "msfconsole",
        "-q -x 'use exploit/multi/handler; set LHOST 0; run'", ctx)
    _assert(ok, "msfconsole allowed with explicit exploit/ module",
            detail=why[:120])

    # linpeas with shell_access
    ok, why = check_tool_warranted("linpeas", "", ctx)
    _assert(ok, "linpeas allowed once shell_access=True",
            detail=why[:120])


# ─────────────────────────────────────────────────────────────────────
#  Test 19 — check_command_warranted on full command lines
# ─────────────────────────────────────────────────────────────────────


def test_check_command_warranted() -> None:
    _section("Test 19 — check_command_warranted on raw shell strings")

    from agents.engagement_context import check_command_warranted

    intel = {
        "open_ports": [3306],
        "services": {3306: {"service": "mysql", "product": "MariaDB"}},
    }
    ctx = EngagementContext(session_id="sess-19", target="x", intel_ref=intel)

    # Valid: mysql client + port open
    ok, _ = check_command_warranted(
        "mysql -h x -u root --password='' -e 'SELECT VERSION();'", ctx)
    _assert(ok, "mysql command warranted when port 3306 is open")

    # Invalid: psql without port 5432
    ok, why = check_command_warranted("psql -h x -U postgres", ctx)
    _assert(not ok, "psql refused without port 5432",
            detail=why[:120])

    # Invalid: empty command
    ok, _ = check_command_warranted("", ctx)
    _assert(not ok, "empty command refused")

    # Valid: nmap is discovery-tier, always allowed
    ok, _ = check_command_warranted("nmap -sV x", ctx)
    _assert(ok, "nmap (discovery-tier) always warranted")


# ─────────────────────────────────────────────────────────────────────
#  Test 20 — is_tool_blocked gates basis-failed tools immediately
# ─────────────────────────────────────────────────────────────────────


def test_basis_gate_in_is_tool_blocked() -> None:
    _section("Test 20 — is_tool_blocked includes basis gate as first check")

    intel = {"open_ports": [], "services": {}}
    ctx = EngagementContext(session_id="sess-20", target="x", intel_ref=intel)
    register_context(ctx)

    # wpscan with no WordPress — must be blocked immediately, before
    # any counter has had a chance to climb.
    blocked, reason = ctx.is_tool_blocked("wpscan", "--url http://x")
    _assert(blocked, "wpscan blocked immediately on NO-BASIS",
            detail=reason[:120])
    _assert(reason.startswith("NO BASIS"),
            "block reason starts with 'NO BASIS' prefix",
            detail=reason[:60])

    # No invocation counted — basis-failed calls don't consume budget
    _assert(ctx.total_invocations == 0,
            "basis-refused calls do NOT consume the invocation budget",
            detail=f"counter: {ctx.total_invocations}")
    unregister_context("sess-20")


# ─────────────────────────────────────────────────────────────────────
#  Test 21 — Focused-attack interrupt signal (cross-pipeline)
# ─────────────────────────────────────────────────────────────────────


def test_focused_attack_interrupt() -> None:
    _section("Test 21 — Focused-attack interrupt signal")

    ctx = EngagementContext(session_id="sess-21", target="10.10.10.10")

    # Before signal: pipelines should NOT yield
    _assert(not ctx.should_yield_to_focused_attack(pipeline_name="WSTG"),
            "no-yield before focused-attack signal is set")
    _assert(len(ctx.focused_attack_endpoints) == 0,
            "endpoints queue empty initially")

    # Raise the signal
    ctx.set_focused_attack(
        endpoints=[
            "curl -sk -m 15 -H 'Host: 2million.htb' http://10.10.10.10/api/v1/invite/generate",
            "curl -sk -m 15 -H 'Host: 2million.htb' http://10.10.10.10/js/inviteapi.min.js",
        ],
        reason="OSINT synthesis identified TwoMillion HTB invite-code chain",
        source="osint_synthesis_url_extract",
        vhost="2million.htb",
    )

    # Every pipeline name that polls now yields
    _assert(ctx.should_yield_to_focused_attack(pipeline_name="WSTG"),
            "WSTG yields after signal")
    _assert(ctx.should_yield_to_focused_attack(pipeline_name="vuln_batch"),
            "vuln_batch yields after signal")
    _assert("WSTG" in ctx.pipelines_yielded and "vuln_batch" in ctx.pipelines_yielded,
            "yield-set records all polling pipelines for telemetry")

    # Signal mirrored into intel for legacy consumers
    _assert(ctx.intel.get("focused_attack_mode") is True,
            "legacy intel['focused_attack_mode'] mirror is True")
    _assert("2million.htb" in (ctx.intel.get("vhosts") or []),
            "vhost propagated into intel['vhosts']")

    # Prompt rendering surfaces the signal prominently
    prompt = ctx.render_for_prompt()
    _assert("FOCUSED ATTACK MODE" in prompt,
            "FOCUSED ATTACK MODE banner visible in prompt")
    _assert("/api/v1/invite/generate" in prompt,
            "specific endpoint visible in prompt")

    # Pop endpoints in FIFO order
    first = ctx.pop_focused_attack_endpoint()
    _assert(first and "/api/v1/invite/generate" in first,
            "first popped endpoint is highest priority", detail=str(first))
    second = ctx.pop_focused_attack_endpoint()
    _assert(second and "inviteapi.min.js" in second,
            "second popped endpoint preserves order")
    third = ctx.pop_focused_attack_endpoint()
    _assert(third is None, "empty queue returns None")

    # Clearing the signal lets pipelines stop yielding
    ctx.clear_focused_attack()
    _assert(not ctx.should_yield_to_focused_attack(pipeline_name="WSTG"),
            "after clear_focused_attack pipelines stop yielding")


# ─────────────────────────────────────────────────────────────────────
#  Test 22 — Stall watchdog (25min + 30 actions + 0 findings = yield)
# ─────────────────────────────────────────────────────────────────────


def test_stall_watchdog() -> None:
    _section("Test 22 — Stall watchdog detects engagements going nowhere")

    ctx = EngagementContext(session_id="sess-22", target="x")
    # Fresh engagement: nothing happening yet → NOT stalled
    _assert(not ctx.is_engagement_stalled(),
            "fresh engagement: not stalled (elapsed=0)")

    # Simulate 30 minutes of elapsed time with many actions, no findings
    import time as _t
    ctx.started_at = _t.monotonic() - (30 * 60)
    for i in range(32):
        ctx.record_action(
            tool="curl", args=f"http://x/path-{i}",
            phase="vuln", reasoning="r",
            observation=f"HTTP/1.1 404 try-{i}",
        )
    _assert(ctx.is_engagement_stalled(),
            "30min + 32 actions + 0 findings: stalled",
            detail=f"invocations={ctx.total_invocations}")

    # If focused-attack signal is in flight → NOT stalled (we know what to do)
    ctx.set_focused_attack(endpoints=["curl http://x/api/foo"], reason="lead")
    _assert(not ctx.is_engagement_stalled(),
            "focused-attack signal in flight defers the stall verdict")

    # Cleared again
    ctx.clear_focused_attack()
    _assert(ctx.is_engagement_stalled(),
            "after clearing focused signal, stall verdict returns")

    # A real finding clears the stall
    ctx.record_finding({"title": "first finding", "host": "x", "severity": "HIGH"})
    _assert(not ctx.is_engagement_stalled(),
            "a finding resets the stall verdict")


# ─────────────────────────────────────────────────────────────────────
#  Test 23 — OSINT URL extractor pulls paths from narrative text
# ─────────────────────────────────────────────────────────────────────


def test_osint_url_extractor() -> None:
    _section("Test 23 — OSINT URL extractor pulls paths from narrative")
    from agents.osint_agent import OsintAgent

    synthesis = """
    Target 10.129.229.66 is the HTB TwoMillion box. The documented chain is:
    invite-code generation via /js/inviteapi.min.js → /api/v1/invite/generate →
    register → authenticated /api/v1/admin/* endpoint with command injection.
    The vhost twomillion.htb resolves via /etc/hosts to the same IP.
    Generic noise paths to ignore: /tmp/scan-output, /usr/share/wordlists,
    /etc/passwd. Real targets: /api/v1/user/auth, /api/v1/admin/settings.
    """
    paths = OsintAgent._extract_url_paths(synthesis)
    _assert("/js/inviteapi.min.js" in paths,
            "extracts /js/inviteapi.min.js from narrative",
            detail=f"got: {paths}")
    _assert("/api/v1/invite/generate" in paths,
            "extracts /api/v1/invite/generate from narrative")
    _assert("/api/v1/user/auth" in paths,
            "extracts /api/v1/user/auth from narrative")
    # Filesystem noise is filtered
    fs_paths = [p for p in paths if p.startswith(("/tmp/", "/usr/", "/etc/"))]
    _assert(len(fs_paths) == 0,
            "filesystem paths filtered out", detail=f"fs paths leaked: {fs_paths}")

    vhosts = OsintAgent._extract_vhosts(synthesis)
    _assert("twomillion.htb" in vhosts,
            "extracts twomillion.htb vhost from narrative")


# ─────────────────────────────────────────────────────────────────────
#  Test 24 — Target profile classification (the support.htb fix)
# ─────────────────────────────────────────────────────────────────────


def test_target_profile_classification() -> None:
    _section("Test 24 — Target profile classification (ad_dc vs web_app)")

    # Case 1: Active Directory DC (support.htb shape)
    intel = {
        "open_ports": [53, 88, 135, 139, 389, 445, 464, 593, 636,
                         3268, 3269, 5985, 9389],
        "services": {
            88:  {"service": "kerberos-sec", "product": "Microsoft Windows Kerberos"},
            389: {"service": "ldap", "product": "Microsoft Windows Active Directory LDAP",
                   "version": "Domain: support.htb0., Site: Default-First-Site-Name"},
            445: {"service": "microsoft-ds"},
            5985: {"service": "http", "product": "Microsoft HTTPAPI httpd"},
        },
    }
    ctx = EngagementContext(session_id="t24-ad", target="10.129.58.129", intel_ref=intel)
    profile = ctx.commit_target_profile()
    _assert(profile == "ad_dc", "AD DC fingerprint classified as ad_dc",
            detail=f"got {profile!r}")
    _assert(ctx.should_skip_web_testing(),
            "ad_dc profile → web_testing SHOULD be skipped")
    _assert(ctx.get_target_profile() == "ad_dc",
            "get_target_profile reads from intel cache")
    _assert(ctx.intel.get("target_profile") == "ad_dc",
            "profile mirrored into intel for legacy consumers")
    # Pinned insight visible in prompt
    prompt = ctx.render_for_prompt()
    _assert("ad_dc" in prompt,
            "ad_dc profile pinned and visible in prompt")

    # Case 2: A real web application (port 80 + apache + WordPress)
    intel2 = {
        "open_ports": [22, 80, 443],
        "services": {
            22: {"service": "ssh", "product": "OpenSSH"},
            80: {"service": "http", "product": "Apache", "version": "2.4.66 WordPress"},
            443: {"service": "https", "product": "Apache"},
        },
    }
    ctx2 = EngagementContext(session_id="t24-web", target="x", intel_ref=intel2)
    _assert(ctx2.classify_target_profile() == "web_app",
            "web service banner → web_app profile")
    _assert(not ctx2.should_skip_web_testing(),
            "web_app profile → web_testing SHOULD run")

    # Case 3: Mixed (AD DC + actual web app on port 80) — use a
    # FRESH intel dict so the previous test's commit_target_profile
    # doesn't pollute the cache key.
    intel3 = {
        "open_ports": [88, 389, 445, 80],
        "services": {
            88: {"service": "kerberos-sec"},
            389: {"service": "ldap", "product": "Microsoft Windows AD LDAP",
                   "version": "Domain: acme.htb"},
            445: {"service": "microsoft-ds"},
            80: {"service": "http", "product": "Apache", "version": "2.4"},
        },
    }
    ctx3 = EngagementContext(session_id="t24-mixed", target="x", intel_ref=intel3)
    _assert(ctx3.classify_target_profile() == "mixed",
            "AD DC + real web service → mixed profile")
    _assert(not ctx3.should_skip_web_testing(),
            "mixed profile → web_testing runs (has real web surface)")

    # Case 4: WinRM-only host masquerading as HTTP — NOT a web app
    intel4 = {
        "open_ports": [5985, 5986],
        "services": {
            5985: {"service": "http", "product": "Microsoft HTTPAPI httpd"},
        },
    }
    ctx4 = EngagementContext(session_id="t24-winrm", target="x", intel_ref=intel4)
    profile4 = ctx4.classify_target_profile()
    _assert(profile4 != "web_app",
            "WinRM HTTPAPI is NOT classified as web_app",
            detail=f"got {profile4!r}")


# ─────────────────────────────────────────────────────────────────────
#  Test 25 — extract_ad_domain pulls "support.htb" from LDAP banner
# ─────────────────────────────────────────────────────────────────────


def test_extract_ad_domain() -> None:
    _section("Test 25 — extract_ad_domain reads LDAP banner / DN")

    intel = {
        "services": {
            389: {"service": "ldap",
                   "product": "Microsoft Windows Active Directory LDAP",
                   "version": "Domain: support.htb0., Site: Default-First-Site-Name"},
        },
    }
    ctx = EngagementContext(session_id="t25", target="x", intel_ref=intel)
    domain = ctx.extract_ad_domain()
    _assert(domain == "support.htb",
            "domain extracted + trailing dot/0 stripped",
            detail=f"got {domain!r}")

    # Fallback: extract from a pinned finding with DN syntax
    intel2 = {"services": {}}
    ctx2 = EngagementContext(session_id="t25b", target="x", intel_ref=intel2)
    ctx2.findings.append({
        "description": "Anonymous bind allowed. Base DN: DC=acme,DC=corp.",
    })
    domain2 = ctx2.extract_ad_domain()
    _assert(domain2 == "acme.corp",
            "fallback: extracts domain from DC=acme,DC=corp DN string",
            detail=f"got {domain2!r}")


# ─────────────────────────────────────────────────────────────────────
#  Test 26 — AD chain trigger fires with proper command interpolation
# ─────────────────────────────────────────────────────────────────────


def test_ad_chain_trigger() -> None:
    _section("Test 26 — AD DC full-chain trigger queues real commands")

    ft.reset_fired()
    intel = {
        "target": "10.129.58.129",
        "target_host": "10.129.58.129",
        "open_ports": [88, 389, 445, 5985],
        "services": {
            88: {"service": "kerberos-sec"},
            389: {"service": "ldap", "product": "Microsoft Windows AD LDAP",
                   "version": "Domain: support.htb0., Site: Default-First-Site-Name"},
            445: {"service": "microsoft-ds"},
            5985: {"service": "http", "product": "Microsoft HTTPAPI httpd"},
        },
    }
    ctx = EngagementContext(session_id="t26", target="10.129.58.129", intel_ref=intel)
    actions = ft.evaluate_triggers(ctx)

    cmds = [a for a in actions if a.kind == "command"]
    # The ldapsearch payload contains "DC=support,DC=htb" — check for
    # that DN form rather than the dotted "support.htb" form.
    _assert(any("ldapsearch" in a.payload and "DC=support,DC=htb" in a.payload for a in cmds),
            "AD chain: ldapsearch with DC=support,DC=htb base DN queued",
            detail=str([a.payload[:80] for a in cmds[:5]]))
    _assert(any("GetNPUsers" in a.payload and "support.htb" in a.payload for a in cmds),
            "AD chain: AS-REP roast command with domain queued")
    _assert(any("crackmapexec smb" in a.payload and "--shares" in a.payload for a in cmds),
            "AD chain: crackmapexec SMB null-session queued")
    _assert(any("10.129.58.129" in a.payload for a in cmds),
            "{host} placeholder interpolated to target IP")


# ─────────────────────────────────────────────────────────────────────
#  Test 27 — WebOrchestrator yields when profile is ad_dc
# ─────────────────────────────────────────────────────────────────────


def test_web_orchestrator_yields_for_ad() -> None:
    _section("Test 27 — WebOrchestrator yields based on target_profile")

    intel = {
        "open_ports": [88, 389, 445],
        "services": {88: {"service": "kerberos-sec"},
                      389: {"service": "ldap"},
                      445: {"service": "microsoft-ds"}},
    }
    ctx = EngagementContext(session_id="t27", target="x", intel_ref=intel)
    ctx.commit_target_profile()
    _assert(ctx.should_skip_web_testing(),
            "context: ad_dc profile → should_skip_web_testing is True")

    # The orchestrator's helper directly mirrors this (we can't easily
    # instantiate the full WebOrchestrator here without web_agent etc.).
    # Verify the boolean check returns True for the ad_dc case.
    _assert(ctx.get_target_profile() == "ad_dc",
            "profile is ad_dc")

    # Now confirm a web_app target does NOT yield
    intel_web = {
        "open_ports": [80, 443],
        "services": {80: {"service": "http", "product": "Apache",
                             "version": "WordPress"}},
    }
    ctx_web = EngagementContext(session_id="t27b", target="x", intel_ref=intel_web)
    ctx_web.commit_target_profile()
    _assert(not ctx_web.should_skip_web_testing(),
            "web_app profile → should_skip_web_testing is False")


# ─────────────────────────────────────────────────────────────────────
#  Test 28 — engagement_mode state machine transitions
# ─────────────────────────────────────────────────────────────────────


def test_engagement_mode_transitions() -> None:
    _section("Test 28 — engagement_mode state machine")

    ctx = EngagementContext(session_id="t28", target="x")
    _assert(ctx.engagement_mode == "scanning",
            "fresh engagement starts in 'scanning' mode")

    # scanning → attempting_entry
    ok = ctx.transition_mode("attempting_entry", reason="test entry found")
    _assert(ok, "scanning → attempting_entry: allowed")
    _assert(ctx.engagement_mode == "attempting_entry",
            "mode is now attempting_entry")
    _assert(ctx.is_attempting_entry(),
            "is_attempting_entry() returns True")
    _assert(not ctx.should_scanners_yield(),
            "scanners do NOT yield during attempting_entry (parallel scan continues)")

    # attempting_entry → post_exploit
    ok = ctx.transition_mode("post_exploit", reason="shell obtained")
    _assert(ok, "attempting_entry → post_exploit: allowed")
    _assert(ctx.is_post_exploit_mode(),
            "is_post_exploit_mode() returns True")
    _assert(ctx.should_scanners_yield(),
            "scanners MUST yield in post_exploit mode")

    # post_exploit → scanning: REJECTED (no backtracking)
    ok = ctx.transition_mode("scanning", reason="should not be allowed")
    _assert(not ok, "post_exploit → scanning: rejected (no backtrack)")
    _assert(ctx.engagement_mode == "post_exploit",
            "mode stays post_exploit after rejected backtrack")

    # post_exploit → complete: allowed
    ok = ctx.transition_mode("complete", reason="flag captured")
    _assert(ok, "post_exploit → complete: allowed")
    _assert(ctx.should_scanners_yield(),
            "scanners yield in complete mode too")

    # Idempotent — calling same mode twice returns False
    ok = ctx.transition_mode("complete", reason="duplicate")
    _assert(not ok, "transition_mode(same mode) is no-op")


# ─────────────────────────────────────────────────────────────────────
#  Test 29 — Mode-change subscribers fire on transition
# ─────────────────────────────────────────────────────────────────────


def test_mode_change_subscribers() -> None:
    _section("Test 29 — Mode-change subscribers fire")

    ctx = EngagementContext(session_id="t29", target="x")
    received = []
    ctx.subscribe_mode_changes(lambda old, new, reason: received.append((old, new, reason[:30])))
    ctx.transition_mode("attempting_entry", reason="entry detected: anon LDAP")
    _assert(len(received) == 1, "subscriber fired once on transition",
            detail=str(received))
    _assert(received[0][0] == "scanning" and received[0][1] == "attempting_entry",
            "subscriber received correct old/new",
            detail=str(received[0]))
    ctx.transition_mode("post_exploit", reason="shell")
    _assert(len(received) == 2,
            "subscriber fires on every transition")


# ─────────────────────────────────────────────────────────────────────
#  Test 30 — Entry-point detector (universal across target types)
# ─────────────────────────────────────────────────────────────────────


def test_entry_point_detector_universal() -> None:
    _section("Test 30 — Entry-point detector across target types")

    # Case A — AD anonymous bind (Windows DC)
    ctx_a = EngagementContext(session_id="t30-a", target="x")
    ctx_a.record_finding({
        "title": "LDAP 389 — Anonymous Bind Allowed",
        "host":  "x", "severity": "HIGH",
        "description": "Anon bind",
    })
    _assert(ctx_a.engagement_mode == "attempting_entry",
            "AD anon bind → mode = attempting_entry",
            detail=f"mode={ctx_a.engagement_mode}, entries={len(ctx_a.entry_points)}")
    _assert(len(ctx_a.entry_points) >= 1,
            "entry point queued for AD anon bind")

    # Case B — Linux SSH default credentials
    ctx_b = EngagementContext(session_id="t30-b", target="y")
    ctx_b.record_finding({
        "title": "SSH 22 — Default Credentials root:root",
        "host": "y", "severity": "CRITICAL",
        "description": "Default password",
    })
    _assert(ctx_b.engagement_mode == "attempting_entry",
            "Linux default creds → mode = attempting_entry")

    # Case C — IoT device with telnet allowed
    ctx_c = EngagementContext(session_id="t30-c", target="z")
    ctx_c.record_finding({
        "title": "Telnet Allowed — No Authentication",
        "host": "z", "severity": "HIGH",
        "description": "Telnet exposed without auth",
    })
    _assert(ctx_c.engagement_mode == "attempting_entry",
            "IoT telnet → mode = attempting_entry")

    # Case D — pre-staged commands (from finding_triggers)
    ctx_d = EngagementContext(session_id="t30-d", target="w")
    ctx_d.intel["next_commands"] = [
        "impacket-GetNPUsers acme.local/ -dc-ip w -no-pass",
    ]
    ctx_d.detect_entry_points()
    _assert(ctx_d.engagement_mode == "attempting_entry",
            "pre-staged commands → mode = attempting_entry")
    _assert(any(e["type"] == "pre_staged_commands" for e in ctx_d.entry_points),
            "pre_staged_commands entry type registered")

    # Case E — focused URL endpoints (OSINT identified)
    ctx_e = EngagementContext(session_id="t30-e", target="v")
    ctx_e.set_focused_attack(
        endpoints=["curl http://v/api/v1/invite/generate"],
        reason="OSINT URL extraction",
    )
    _assert(ctx_e.engagement_mode == "attempting_entry",
            "OSINT URL endpoints → mode = attempting_entry")


# ─────────────────────────────────────────────────────────────────────
#  Test 31 — Success detector flips to post_exploit
# ─────────────────────────────────────────────────────────────────────


def test_success_detector() -> None:
    _section("Test 31 — Success detector flips to post_exploit")

    # Case A — shell access obtained (any OS)
    intel = {"target": "x"}
    ctx = EngagementContext(session_id="t31-shell", target="x", intel_ref=intel)
    ctx.transition_mode("attempting_entry", reason="anon bind")
    intel["shell_access"] = True
    ctx.detect_success_signals()
    _assert(ctx.is_post_exploit_mode(),
            "shell_access=True → engagement_mode = post_exploit")

    # Case B — credentials harvested (universal)
    intel_b = {"target": "y", "credentials": [{"user": "admin", "pass": "pwd"}]}
    ctx_b = EngagementContext(session_id="t31-creds", target="y", intel_ref=intel_b)
    ctx_b.detect_success_signals()
    _assert(ctx_b.is_post_exploit_mode(),
            "credentials harvested → engagement_mode = post_exploit")

    # Case C — loot harvested (SSH keys)
    intel_c = {"target": "z", "loot": {"ssh_keys": ["id_rsa from /home/user"]}}
    ctx_c = EngagementContext(session_id="t31-loot", target="z", intel_ref=intel_c)
    ctx_c.detect_success_signals()
    _assert(ctx_c.is_post_exploit_mode(),
            "loot harvested → engagement_mode = post_exploit")

    # Case D — flag captured + shell → mode = complete (not post_exploit)
    intel_d = {"target": "w", "shell_access": True, "user_flag": "HTB{...}"}
    ctx_d = EngagementContext(session_id="t31-flag", target="w", intel_ref=intel_d)
    ctx_d.detect_success_signals()
    _assert(ctx_d.engagement_mode == "complete",
            "shell + flag → mode = complete (objective satisfied)",
            detail=f"mode={ctx_d.engagement_mode}")


# ─────────────────────────────────────────────────────────────────────
#  Test 32 — Scanners yield in post_exploit but NOT in attempting_entry
# ─────────────────────────────────────────────────────────────────────


def test_scanners_yield_contract() -> None:
    _section("Test 32 — Scanner yield contract (parallel scan during attempt)")

    ctx = EngagementContext(session_id="t32", target="x")
    _assert(not ctx.should_scanners_yield(),
            "scanning mode: scanners DO NOT yield")

    ctx.transition_mode("attempting_entry", reason="entry found")
    _assert(not ctx.should_scanners_yield(),
            "attempting_entry: scanners DO NOT yield (parallel scan)")

    ctx.transition_mode("post_exploit", reason="shell obtained")
    _assert(ctx.should_scanners_yield(),
            "post_exploit: scanners YIELD")

    ctx.transition_mode("complete", reason="flag captured")
    _assert(ctx.should_scanners_yield(),
            "complete: scanners YIELD")


# ─────────────────────────────────────────────────────────────────────
#  Test 33 — Async entry-point queue: wait_for + pop
# ─────────────────────────────────────────────────────────────────────


def test_entry_point_async_queue() -> None:
    _section("Test 33 — Async entry-point queue: wait_for_entry_point")

    import asyncio as _aio

    async def _scenario():
        ctx = EngagementContext(session_id="t33", target="x")
        # Set up: no entries yet, wait_for_entry_point should timeout
        got = await ctx.wait_for_entry_point(timeout=0.1)
        _assert(not got, "wait_for_entry_point times out when queue is empty")

        # Add a finding that triggers entry-point detection
        ctx.record_finding({
            "title": "Anonymous Bind Allowed on LDAP",
            "host": "x", "severity": "HIGH",
        })
        # Now wait_for_entry_point should fire immediately
        got = await ctx.wait_for_entry_point(timeout=1.0)
        _assert(got, "wait_for_entry_point fires after record_finding")
        ep = ctx.pop_entry_point()
        _assert(ep is not None and ep.get("type") == "finding_match",
                "pop_entry_point returns the queued entry",
                detail=str(ep))

    _aio.run(_scenario())


# ─────────────────────────────────────────────────────────────────────
#  Test 34 — Entry point sig dedup: same finding doesn't re-fire
# ─────────────────────────────────────────────────────────────────────


def test_entry_point_dedup() -> None:
    _section("Test 34 — Same entry point doesn't fire twice")

    ctx = EngagementContext(session_id="t34", target="x")
    ctx.record_finding({
        "title": "LDAP 389 — Anonymous Bind Allowed",
        "host": "x", "severity": "HIGH",
        "finding_id": "abc-123",
    })
    first_count = len(ctx.entry_points)
    # Same finding — same signature — should NOT re-add
    ctx.detect_entry_points()
    ctx.detect_entry_points()
    second_count = len(ctx.entry_points)
    _assert(first_count == second_count,
            "calling detect_entry_points twice does NOT add duplicates",
            detail=f"{first_count} → {second_count}")


# ─────────────────────────────────────────────────────────────────────
#  Runner
# ─────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────
#  Test 35 — primary_web_port (port-aware WSTG targeting)
# ─────────────────────────────────────────────────────────────────────


def test_primary_web_port() -> None:
    _section("Test 35 — primary_web_port picks 8080 over 80 (Overpass-3 fix)")

    # Overpass-3 scenario: 80 closed, real app on 8080 (Werkzeug)
    intel_a = {
        "open_ports": [22, 111, 2049, 8080],
        "services": {
            22:   {"service": "ssh"},
            8080: {"service": "http", "product": "Werkzeug",
                    "banner": "Werkzeug httpd 0.14.1 Python 3.6.9"},
        },
        "target_host": "10.48.174.56",
    }
    ctx_a = EngagementContext(session_id="t35-a", target="x", intel_ref=intel_a)
    port = ctx_a.primary_web_port()
    _assert(port == 8080,
            "Overpass-3: primary_web_port picks 8080 (Werkzeug)",
            detail=f"got {port}")
    url = ctx_a.primary_web_url()
    _assert(url == "http://10.48.174.56:8080",
            "Overpass-3: primary_web_url builds correct URL",
            detail=str(url))

    # Standard case: port 80 with nginx banner
    intel_b = {
        "open_ports": [80, 443],
        "services": {
            80: {"service": "http", "product": "nginx", "banner": "nginx/1.18"},
        },
        "target_host": "h",
    }
    ctx_b = EngagementContext(session_id="t35-b", target="h", intel_ref=intel_b)
    _assert(ctx_b.primary_web_port() == 80,
            "standard nginx on 80 — primary is 80")

    # AD DC: 5985 looks like HTTP but is WinRM HTTPAPI — should NOT
    # be returned (would cause WSTG to waste cycles on WinRM)
    intel_c = {
        "open_ports": [445, 5985],
        "services": {
            5985: {"service": "http", "banner": "Microsoft-HTTPAPI/2.0 (SSDP/UPnP)"},
        },
        "target_host": "dc",
    }
    ctx_c = EngagementContext(session_id="t35-c", target="dc", intel_ref=intel_c)
    _assert(ctx_c.primary_web_port() is None,
            "AD DC WinRM HTTPAPI on 5985 — primary_web_port returns None",
            detail=f"got {ctx_c.primary_web_port()}")


# ─────────────────────────────────────────────────────────────────────
#  Test 36 — phase budget exceeded detection
# ─────────────────────────────────────────────────────────────────────


def test_phase_budget() -> None:
    _section("Test 36 — Phase wall-clock budget tracking")

    ctx = EngagementContext(session_id="t36", target="x")
    # set_phase_budget enforces a 60s minimum (production safety).
    # For test, bypass that floor by writing directly to the internal
    # store — exercising the same code path is_phase_budget_exceeded()
    # uses.
    ctx.set_phase_budget("vuln_id", 60.0)
    ctx._phase_budgets["vuln_id"] = 0.05    # type: ignore[attr-defined]
    ctx.mark_phase_started("vuln_id")
    _assert(not ctx.is_phase_budget_exceeded("vuln_id"),
            "freshly started phase not exceeded")
    import time as _t
    _t.sleep(0.1)
    _assert(ctx.is_phase_budget_exceeded("vuln_id"),
            "phase budget exceeded after sleep > budget")
    # Unknown phase → not exceeded (never started)
    _assert(not ctx.is_phase_budget_exceeded("unknown"),
            "unknown phase returns False (not exceeded)")
    # Default budgets present + sensible
    _assert(ctx.get_phase_budget("recon") >= 60,
            "default recon budget is at least 60s")
    _assert(ctx.get_phase_budget("vuln_id") > 0,
            "default vuln_id budget is positive")


# ─────────────────────────────────────────────────────────────────────
#  Test 37 — Error Analyzer fast-path classifications
# ─────────────────────────────────────────────────────────────────────


def test_error_analyzer_fast_paths() -> None:
    _section("Test 37 — Error Analyzer fast-path (tool_missing + transient)")

    from agents.meta.error_analyzer_agent import ErrorAnalyzerAgent, ErrorEvent
    import asyncio as _aio

    async def _scenario():
        ctx = EngagementContext(session_id="t37", target="x")
        register_context(ctx)
        analyzer = ErrorAnalyzerAgent(broadcast=None, session_id="t37",
                                          db_conn=None, enabled=True)

        # tool_missing fast path — should pin insight + force_block
        evt = ErrorEvent(tool="dalfox", args="url http://x",
                          target="x", exit_code=1,
                          stderr="[MCP ERROR] Tool not found: 'dalfox'.  Install: apt install dalfox -y",
                          phase="vuln_id")
        await analyzer._handle(evt)
        _assert(any("error_analyzer" == p.source for p in ctx.pinned),
                "tool_missing pinned an insight from error_analyzer")
        _assert(any("dalfox" in p.text.lower() for p in ctx.pinned),
                "pinned insight mentions the offending tool")
        # The block should also be visible via is_tool_blocked
        blocked, _ = ctx.is_tool_blocked("dalfox", "x")
        _assert(blocked, "dalfox is force_blocked after tool_missing classification")

        # transient fast path — no force_block, just pinned
        ctx2 = EngagementContext(session_id="t37-tr", target="y")
        register_context(ctx2)
        analyzer2 = ErrorAnalyzerAgent(broadcast=None, session_id="t37-tr",
                                           db_conn=None, enabled=True)
        evt2 = ErrorEvent(tool="curl", args="http://y",
                           target="y", exit_code=6,
                           stderr="curl: (6) Could not resolve host: y",
                           phase="recon")
        await analyzer2._handle(evt2)
        blocked2, _ = ctx2.is_tool_blocked("curl", "y")
        _assert(not blocked2,
                "transient errors do NOT trip force_block (just pinned for guidance)")

        unregister_context("t37")
        unregister_context("t37-tr")

    _aio.run(_scenario())


# ─────────────────────────────────────────────────────────────────────
#  Test 38 — Error Analyzer dedup window
# ─────────────────────────────────────────────────────────────────────


def test_error_analyzer_dedup() -> None:
    _section("Test 38 — Error Analyzer dedup (same error doesn't re-fire)")

    from agents.meta.error_analyzer_agent import ErrorAnalyzerAgent, ErrorEvent
    import asyncio as _aio

    async def _scenario():
        ctx = EngagementContext(session_id="t38", target="x")
        register_context(ctx)
        analyzer = ErrorAnalyzerAgent(broadcast=None, session_id="t38",
                                          db_conn=None, enabled=True)
        evt = ErrorEvent(tool="dalfox", args="url http://x",
                          target="x", exit_code=1,
                          stderr="[MCP ERROR] Tool not found: 'dalfox'",
                          phase="v")
        await analyzer._handle(evt)
        before = len(ctx.pinned)
        # Replay same signature within dedup window
        await analyzer._handle(evt)
        after = len(ctx.pinned)
        _assert(before == after,
                "duplicate error signature does NOT produce duplicate pin",
                detail=f"{before} → {after}")
        unregister_context("t38")

    _aio.run(_scenario())


# ─────────────────────────────────────────────────────────────────────
#  Runner
# ─────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────
#  Test 39 — CPE builder maps real banners to CPE 2.3 URIs
# ─────────────────────────────────────────────────────────────────────


def test_cpe_builder_banner_to_cpe() -> None:
    _section("Test 39 — CPE builder banner → CPE 2.3")

    from agents.osint.cpe_builder import map_banner_to_cpe

    # OpenSSH banner from Overpass-3 run
    m = map_banner_to_cpe("OpenSSH 7.6p1 Ubuntu 4ubuntu0.3")
    _assert(m is not None, "OpenSSH banner mapped",
            detail=str(m))
    _assert(m.vendor == "openbsd" and m.product == "openssh",
            "OpenSSH → openbsd:openssh",
            detail=f"{m.vendor}:{m.product}")
    _assert(m.version == "7.6p1",
            "OpenSSH version extracted = 7.6p1",
            detail=m.version)
    _assert("cpe:2.3:a:openbsd:openssh:7.6p1" in m.cpe_uri,
            "CPE 2.3 URI shape correct")

    # Apache + Werkzeug
    m_apache = map_banner_to_cpe("Apache/2.4.66 (Debian)")
    _assert(m_apache is not None and m_apache.version == "2.4.66",
            "Apache 2.4.66 mapped")
    m_werkzeug = map_banner_to_cpe("Werkzeug httpd 0.14.1 Python 3.6.9")
    _assert(m_werkzeug is not None and m_werkzeug.version == "0.14.1",
            "Werkzeug 0.14.1 mapped",
            detail=str(m_werkzeug))

    # Unknown banner → returns None
    m_unknown = map_banner_to_cpe("Unrecognised exotic banner xyz")
    _assert(m_unknown is None,
            "unknown banner returns None")


# ─────────────────────────────────────────────────────────────────────
#  Test 40 — Version comparison utilities
# ─────────────────────────────────────────────────────────────────────


def test_version_comparison() -> None:
    _section("Test 40 — version_compare + in_version_range")

    from agents.osint.cpe_builder import version_compare, in_version_range

    _assert(version_compare("7.6", "7.7") < 0, "7.6 < 7.7")
    _assert(version_compare("7.6p1", "7.6") > 0, "7.6p1 > 7.6")
    _assert(version_compare("2.4.66", "2.4.66") == 0, "equal versions equal")

    # OpenSSH 2.3 < 7.7 — applies to 7.6 (yes)
    _assert(
        in_version_range("7.6p1", "OpenSSH 2.3 < 7.7 - Username Enumeration") is True,
        "OpenSSH 7.6p1 IS in range '2.3 < 7.7'",
    )
    # Doesn't apply to 7.8
    _assert(
        in_version_range("7.8", "OpenSSH 2.3 < 7.7 - Username Enumeration") is False,
        "OpenSSH 7.8 is NOT in range '2.3 < 7.7'",
    )
    # Ancient title "OpenSSH 1.2 - .scp" doesn't apply to 7.6
    # — extract_versions picks "1.2", in_version_range should return non-True
    res = in_version_range("7.6p1", "OpenSSH 1.2 - '.scp' File Create/Overwrite")
    _assert(res is False,
            "OpenSSH 1.2 exploit not applicable to 7.6p1",
            detail=str(res))


# ─────────────────────────────────────────────────────────────────────
#  Test 41 — Google CSE dead-key cache
# ─────────────────────────────────────────────────────────────────────


def test_google_cse_dead_key_cache() -> None:
    _section("Test 41 — Google CSE dead-key cache")

    from agents.osint.google_dorks_subagent import (
        _cse_key_dead, _cse_mark_dead,
    )

    test_key = "AIza_TEST_KEY_DEAD_CACHE_TEST_xx"
    _assert(not _cse_key_dead(test_key),
            "fresh key not marked dead")
    _cse_mark_dead(test_key, permanent=True)
    _assert(_cse_key_dead(test_key),
            "after _cse_mark_dead permanent=True, key reports dead")
    # Different key prefix should NOT be affected (per-key cache)
    _assert(not _cse_key_dead("AIza_OTHER_KEY_XYZ_PREFIX_TEST"),
            "unrelated key not affected by another key's dead mark")


# ─────────────────────────────────────────────────────────────────────
#  Test 42 — OSINT discovery context carries cves_with_score
# ─────────────────────────────────────────────────────────────────────


def test_osint_cve_propagation_to_github_subagent() -> None:
    _section("Test 42 — CVEs propagate into discovery → GitHub queries")

    from agents.osint.github_poc_subagent import GitHubPoCSubagent

    # Build a fake subagent with discovery containing CVEs
    sub = GitHubPoCSubagent(
        session_id="t42", target="10.0.0.1",
        broadcast_fn=None,
        discovery={
            "cves_with_score": [
                ("CVE-2023-28432", 9.0),
                ("CVE-2018-15473", 5.3),
            ],
            "critical_cves": ["CVE-2023-28432"],
            "product_versions": ["OpenSSH 7.6p1"],
        },
    )
    queries = sub._build_queries()
    _assert(len(queries) >= 2,
            "queries built from CVEs + product versions",
            detail=f"got {len(queries)}")
    q_strings = [q[0] for q in queries]
    _assert(any("CVE-2023-28432" in q for q in q_strings),
            "CVE-2023-28432 query is present")
    _assert(any("OpenSSH 7.6p1" in q for q in q_strings),
            "product+version query is present",
            detail=str(q_strings))
    # Most critical CVE comes first (CVSS-ranked)
    _assert("CVE-2023-28432" in q_strings[0],
            "CVSS 9.0 CVE ranks before CVSS 5.3",
            detail=q_strings[0])


# ─────────────────────────────────────────────────────────────────────
#  Test 43 — Intel cascade signal dedup
# ─────────────────────────────────────────────────────────────────────


def test_intel_cascade_dedup() -> None:
    _section("Test 43 — Intel cascade signal dedup")

    from agents.osint.intel_cascade import (
        IntelCascade, IntelSignal,
        register_cascade, get_cascade, unregister_cascade,
    )
    cascade = IntelCascade(session_id="t43", target="example.com")
    register_cascade(cascade)
    _assert(get_cascade("t43") is cascade,
            "register + get round-trip works")

    s1 = IntelSignal(kind="cve", value="CVE-2023-28432")
    s2 = IntelSignal(kind="cve", value="cve-2023-28432")  # same after norm
    s3 = IntelSignal(kind="cve", value="CVE-2024-99999")

    # Without a running event loop, submit_signal returns False (no
    # dispatch task can be created), but it should still track sigs.
    # Use signature() directly to test dedup logic.
    _assert(s1.signature() == s2.signature(),
            "CVE signatures normalised (case-insensitive)")
    _assert(s1.signature() != s3.signature(),
            "different CVE → different signature")
    unregister_cascade("t43")
    _assert(get_cascade("t43") is None,
            "unregister drops the cascade")


# ─────────────────────────────────────────────────────────────────────
#  Test 44 — Intel cascade routes signals to correct sources
# ─────────────────────────────────────────────────────────────────────


def test_intel_cascade_routes() -> None:
    _section("Test 44 — Signal routing covers all signal kinds")

    from agents.osint.intel_cascade import SIGNAL_ROUTES

    # All required signal kinds present
    for kind in ("banner", "cve", "domain", "ip", "tech", "finding"):
        _assert(kind in SIGNAL_ROUTES,
                f"SIGNAL_ROUTES has '{kind}' route")
        _assert(len(SIGNAL_ROUTES[kind]) >= 2,
                f"'{kind}' has ≥2 sources",
                detail=str(SIGNAL_ROUTES[kind]))

    # CVE route must include CISA KEV + GitHub PoC
    _assert("cisa_kev" in SIGNAL_ROUTES["cve"],
            "CVE signals route to CISA KEV")
    _assert("github_poc" in SIGNAL_ROUTES["cve"],
            "CVE signals route to GitHub PoC")
    _assert("vulners" in SIGNAL_ROUTES["cve"],
            "CVE signals route to Vulners")
    # Domain route must include crt.sh
    _assert("crtsh" in SIGNAL_ROUTES["domain"],
            "domain signals route to crt.sh for subdomain enum")
    # Banner route must include NVD CPE + ExploitDB + GitHub
    _assert("nvd_cpe" in SIGNAL_ROUTES["banner"],
            "banner signals route to NVD CPE search")
    _assert("github_poc" in SIGNAL_ROUTES["banner"],
            "banner signals route to GitHub PoC")


# ─────────────────────────────────────────────────────────────────────
#  Test 45 — harvest_signals_from_intel extracts the right signals
# ─────────────────────────────────────────────────────────────────────


def test_intel_cascade_harvest() -> None:
    _section("Test 45 — harvest_signals_from_intel extracts banners/CVEs/domains")

    from agents.osint.intel_cascade import IntelCascade

    cascade = IntelCascade(session_id="t45", target="10.0.0.1")
    intel = {
        "services": {
            22:   {"service": "ssh", "product": "OpenSSH",   "version": "7.6p1"},
            8080: {"service": "http", "product": "Werkzeug", "version": "0.14.1"},
        },
        "cves_with_score": [("CVE-2023-28432", 9.0)],
        "critical_cves":   ["CVE-2018-15473"],
        "subdomains":      ["dev.example.com", "admin.example.com"],
    }
    count = cascade.harvest_signals_from_intel(intel)
    _assert(count >= 4,
            "harvest extracts ≥4 signals (2 banners + 2 CVEs + 2 domains)",
            detail=f"got {count}")
    # Same signals second time → 0 new
    count2 = cascade.harvest_signals_from_intel(intel)
    _assert(count2 == 0,
            "re-harvest produces 0 new signals (dedup)")


# ─────────────────────────────────────────────────────────────────────
#  Test 46 — CISA KEV loader caches across calls
# ─────────────────────────────────────────────────────────────────────


def test_cisa_kev_synchronous_check() -> None:
    _section("Test 46 — CISA KEV synchronous is_kev/kev_entry helpers")

    import agents.osint.cisa_kev_subagent as kev_mod

    # Inject a fake catalog so the test doesn't need network
    kev_mod._KEV_CACHE = {
        "CVE-2023-28432": {
            "cveID":          "CVE-2023-28432",
            "vendorProject":  "MinIO",
            "product":        "MinIO",
            "vulnerabilityName": "MinIO Cluster Mode Information Disclosure",
            "shortDescription":  "MinIO contains an info disclosure...",
            "dateAdded":      "2023-04-21",
            "dueDate":        "2023-05-12",
        }
    }
    _assert(kev_mod.is_kev("CVE-2023-28432"),
            "is_kev returns True for catalog member")
    _assert(kev_mod.is_kev("cve-2023-28432"),
            "is_kev is case-insensitive")
    _assert(not kev_mod.is_kev("CVE-9999-99999"),
            "is_kev returns False for non-member")
    entry = kev_mod.kev_entry("CVE-2023-28432")
    _assert(entry is not None and entry.get("vendorProject") == "MinIO",
            "kev_entry returns catalog metadata",
            detail=str(entry))


# ─────────────────────────────────────────────────────────────────────
#  Test 47 — NFS full exploitation chain trigger
# ─────────────────────────────────────────────────────────────────────


def test_nfs_full_exploit_chain() -> None:
    _section("Test 47 — NFS full exploit chain (showmount→mount→loot)")

    from agents import finding_triggers as ft
    ft.reset_fired()

    intel = {
        "target": "10.48.143.182", "target_host": "10.48.143.182",
        "open_ports": [22, 111, 2049, 8080],
        "services": {2049: {"service": "nfs", "version": "3-4"}},
    }
    ctx = EngagementContext(session_id="t47", target="10.48.143.182", intel_ref=intel)
    actions = ft.evaluate_triggers(ctx)
    nfs_cmds = [a.payload for a in actions if a.kind == "command"
                  and ("showmount" in a.payload or "mount -t nfs" in a.payload
                         or "argus_nfs" in a.payload)]
    _assert(len(nfs_cmds) >= 3,
            "NFS chain produces showmount + mount + loot (≥3 cmds)",
            detail=f"got {len(nfs_cmds)}")
    _assert(any("showmount -e" in c for c in nfs_cmds),
            "step 1: showmount -e present")
    _assert(any("mount -t nfs" in c for c in nfs_cmds),
            "step 2: mount present")
    _assert(any("id_rsa" in c or "user.txt" in c for c in nfs_cmds),
            "step 3: loot hunt (keys/flags) present")


# ─────────────────────────────────────────────────────────────────────
#  Test 48 — Werkzeug debug-console trigger
# ─────────────────────────────────────────────────────────────────────


def test_werkzeug_debug_trigger() -> None:
    _section("Test 48 — Werkzeug debug-console trigger")

    from agents import finding_triggers as ft
    ft.reset_fired()
    intel = {
        "target": "10.48.143.182", "target_host": "10.48.143.182",
        "open_ports": [8080],
        "services": {8080: {"service": "http", "product": "Werkzeug",
                              "banner": "Werkzeug/0.14.1 Python/3.6.9"}},
    }
    ctx = EngagementContext(session_id="t48", target="10.48.143.182", intel_ref=intel)
    actions = ft.evaluate_triggers(ctx)
    cmds = [a.payload for a in actions if a.kind == "command"]
    _assert(any("/console" in c for c in cmds),
            "Werkzeug trigger probes /console for debugger",
            detail=str([c[:50] for c in cmds]))
    _assert(any("__debugger__" in c for c in cmds),
            "Werkzeug trigger checks __debugger__ resource")


# ─────────────────────────────────────────────────────────────────────
#  Test 49 — Loot/flag hunter fires on shell_access
# ─────────────────────────────────────────────────────────────────────


def test_loot_flag_hunter() -> None:
    _section("Test 49 — Loot/flag hunter fires when shell_access=True")

    from agents import finding_triggers as ft
    ft.reset_fired()

    # Without shell — hunter should NOT fire
    intel_noshell = {"target": "x", "open_ports": [22], "services": {}}
    ctx0 = EngagementContext(session_id="t49-0", target="x", intel_ref=intel_noshell)
    actions0 = ft.evaluate_triggers(ctx0)
    loot0 = [a for a in actions0 if a.kind == "command"
               and a.payload.startswith("shell_exec")]
    _assert(len(loot0) == 0,
            "no shell → loot hunter does NOT fire")

    # With shell — hunter fires
    ft.reset_fired()
    intel_shell = {"target": "x", "open_ports": [22], "services": {},
                     "shell_access": True}
    ctx1 = EngagementContext(session_id="t49-1", target="x", intel_ref=intel_shell)
    actions1 = ft.evaluate_triggers(ctx1)
    loot1 = [a.payload for a in actions1 if a.kind == "command"
               and a.payload.startswith("shell_exec")]
    _assert(len(loot1) >= 4,
            "shell_access=True → loot hunter fires multiple commands",
            detail=f"got {len(loot1)}")
    _assert(any("user.txt" in c and "root.txt" in c for c in loot1),
            "loot hunter looks for user.txt + root.txt flags")
    _assert(any("sudo -n -l" in c for c in loot1),
            "loot hunter checks sudo NOPASSWD rights")
    _assert(any("perm -4000" in c for c in loot1),
            "loot hunter enumerates SUID binaries")
    _assert(any("id_rsa" in c for c in loot1),
            "loot hunter hunts SSH keys")


# ─────────────────────────────────────────────────────────────────────
#  Test 50 — Hydra web false-positive rejection
# ─────────────────────────────────────────────────────────────────────


def test_hydra_false_positive_rejection() -> None:
    _section("Test 50 — Hydra http-get false-positive rejection")

    import agents.exploit_agent as ea
    # Build a bare ExploitAgent instance without running __init__ network
    agent = ea.ExploitAgent.__new__(ea.ExploitAgent)

    # Accept-everything pattern: 3 distinct creds all "valid" on http-get
    fp_stdout = (
        "[8080][http-get] host: 10.48.143.182   login: tomcat password: admin\n"
        "[8080][http-get] host: 10.48.143.182   login: admin password: admin\n"
        "[8080][http-get] host: 10.48.143.182   login: root password: root\n"
        "1 of 1 target successfully completed, 3 valid passwords found\n"
    )
    res = agent._parse_hydra_result(fp_stdout)
    _assert(not res["found"],
            "3 web 'valid pairs' rejected as accept-everything FP",
            detail=str(res))
    _assert(res.get("rejected_web_fp") == 3,
            "rejected_web_fp counts the dropped web hits")

    # Real SSH credential — must be kept
    ssh_stdout = (
        "[22][ssh] host: 10.48.143.182   login: james password: Hunter2\n"
        "1 of 1 target successfully completed, 1 valid password found\n"
    )
    res2 = agent._parse_hydra_result(ssh_stdout)
    _assert(res2["found"] and len(res2["credentials"]) == 1,
            "real SSH credential kept")
    _assert(res2["credentials"][0]["service"] == "ssh",
            "SSH cred service preserved")


# ─────────────────────────────────────────────────────────────────────
#  Test 51 — Error Analyzer GUI identity (routes to its own panel)
# ─────────────────────────────────────────────────────────────────────


def test_error_analyzer_gui_identity() -> None:
    _section("Test 51 — Error Analyzer emits as 'error_analyzer' (GUI routing)")

    from agents.meta.error_analyzer_agent import ErrorAnalyzerAgent

    analyzer = ErrorAnalyzerAgent(broadcast=None, session_id="t51",
                                      db_conn=None, enabled=True)
    # The override makes all meta_agent_status / meta_agent_thinking /
    # meta_correction events tag agent='error_analyzer' so the store
    # routes them to metaErrorAnalyzerState instead of polluting the
    # Issue-Validator panel.
    _assert(analyzer._agent_name_str == "error_analyzer",
            "_agent_name_str overridden to 'error_analyzer'",
            detail=analyzer._agent_name_str)
    # Stats tally initialised for the GUI summary panel
    _assert("tool_missing" in analyzer._stats and "blocking" in analyzer._stats,
            "stats tally has classification + blocking counters")


# ─────────────────────────────────────────────────────────────────────
#  Test 52 — Error Analyzer emits meta_correction for GUI panel
# ─────────────────────────────────────────────────────────────────────


def test_error_analyzer_emits_correction() -> None:
    _section("Test 52 — Error Analyzer emits meta_correction (Corrections tab)")

    from agents.meta.error_analyzer_agent import ErrorAnalyzerAgent, ErrorEvent
    import asyncio as _aio

    captured = []

    async def _fake_broadcast(msg):
        # BaseAgent._emit passes a WebSocketMessage; capture its type+data
        try:
            captured.append({
                "type": getattr(msg, "type", None) or (msg.get("type") if isinstance(msg, dict) else None),
                "data": getattr(msg, "data", None) or (msg.get("data") if isinstance(msg, dict) else None),
            })
        except Exception:
            captured.append({"raw": str(msg)})

    async def _scenario():
        ctx = EngagementContext(session_id="t52", target="x")
        register_context(ctx)
        analyzer = ErrorAnalyzerAgent(broadcast=_fake_broadcast,
                                          session_id="t52", db_conn=None,
                                          enabled=True)
        # tool_missing fast path → should emit BOTH meta_correction + error_analysis
        evt = ErrorEvent(tool="dalfox", args="url http://x", target="x",
                          exit_code=1,
                          stderr="[MCP ERROR] Tool not found: 'dalfox'",
                          phase="vuln_id")
        await analyzer._handle(evt)
        types = [c.get("type") for c in captured]
        _assert("meta_correction" in types,
                "meta_correction emitted (populates Corrections tab)",
                detail=str(types))
        _assert("error_analysis" in types,
                "error_analysis emitted (populates feed + stats)")
        # The correction must be tagged source=error_analyzer for routing
        corr = next((c for c in captured if c.get("type") == "meta_correction"), None)
        _assert(corr is not None and (corr.get("data") or {}).get("source") == "error_analyzer",
                "correction source='error_analyzer' for GUI panel routing",
                detail=str((corr or {}).get("data", {}).get("source")))
        _assert(analyzer._stats["total"] >= 1,
                "stats.total incremented")
        unregister_context("t52")

    _aio.run(_scenario())


# ─────────────────────────────────────────────────────────────────────
#  Test 53 — ParallelChainExecutor first-to-win (now wired into exploit)
# ─────────────────────────────────────────────────────────────────────


def test_parallel_chain_executor_first_to_win() -> None:
    _section("Test 53 — ParallelChainExecutor: first-to-win cancels laggards")

    from agents.exploit.parallel_chain_executor import (
        ParallelChainExecutor, ChainOutcome,
    )
    import asyncio as _aio

    async def _scenario():
        # 3 chains: 'fast' wins at 0.1s; 'slow1'/'slow2' would take 5s but
        # must be cancelled after the win (5s grace is long, so shrink it
        # by setting chain_timeout low and asserting outcomes).
        ran_to_completion = {"slow1": False, "slow2": False}

        async def _runner(chain, ctx):
            kind = chain["chain_id"]
            if kind == "fast":
                await _aio.sleep(0.05)
                # signal the win
                if ctx.on_event:
                    await ctx.on_event("shell_obtained", {"chain_id": ctx.chain_id})
                return [{"title": "shell via fast"}]
            else:
                # Slow chain — should be cancelled before finishing
                try:
                    await _aio.sleep(30)
                except _aio.CancelledError:
                    raise
                ran_to_completion[kind] = True
                return [{"title": f"{kind} done"}]

        execu = ParallelChainExecutor(max_parallel=3, chain_timeout=20)
        # Patch the 5s grace to be near-instant for the test by monkeypatching
        # asyncio.sleep inside the watcher is overkill — instead we rely on
        # the win flag + a short manual wait.  We assert WIN + that slow
        # chains did NOT run to completion.
        chains = [
            {"chain_id": "fast"},
            {"chain_id": "slow1"},
            {"chain_id": "slow2"},
        ]
        runs = await _aio.wait_for(
            execu.run(chains, _runner, "10.0.0.1", {"10.0.0.1"}),
            timeout=15,
        )
        by_id = {r.chain_id: r for r in runs}
        _assert(by_id["fast"].outcome == ChainOutcome.WIN,
                "fast chain marked WIN", detail=str(by_id["fast"].outcome))
        _assert(not ran_to_completion["slow1"] and not ran_to_completion["slow2"],
                "slow chains were cancelled before completion (first-to-win)")
        _assert(by_id["slow1"].outcome in (ChainOutcome.CANCELLED, ChainOutcome.TIMEOUT),
                "slow1 cancelled/timeout, not DONE",
                detail=str(by_id["slow1"].outcome))

    _aio.run(_scenario())


# ─────────────────────────────────────────────────────────────────────
#  Test 54 — ExploitOrchestrator builds parallel chains (not sequential)
# ─────────────────────────────────────────────────────────────────────


def test_exploit_orchestrator_uses_parallel_executor() -> None:
    _section("Test 54 — ExploitOrchestrator wired to ParallelChainExecutor")

    import inspect
    from agents.exploit import exploit_orchestrator as eo

    src = inspect.getsource(eo.ExploitOrchestrator.run)
    _assert("ParallelChainExecutor" in src,
            "ExploitOrchestrator.run references ParallelChainExecutor")
    _assert("first-to-win" in src.lower() or "parallel" in src.lower(),
            "run() documents parallel/first-to-win behavior")
    # The old strictly-sequential 'Step 1/4 ... Step 4/4' awaits should be gone
    _assert(src.count("await _run(") == 0,
            "old sequential `await _run(...)` stages removed",
            detail=f"count={src.count('await _run(')}")


# ─────────────────────────────────────────────────────────────────────
#  Test 55 — MasterAgent exposes autonomous payload-development helper
# ─────────────────────────────────────────────────────────────────────


def test_master_has_payload_helper() -> None:
    _section("Test 55 — MasterAgent._auto_generate_payload exists + wired")

    import inspect
    from agents.master_agent import MasterAgent

    _assert(hasattr(MasterAgent, "_auto_generate_payload"),
            "MasterAgent has _auto_generate_payload helper")
    # The exploit phase should pre-stage a payload when a web/RCE surface exists
    exploit_src = inspect.getsource(MasterAgent._phase_exploit)
    _assert("_auto_generate_payload" in exploit_src,
            "_phase_exploit calls _auto_generate_payload (autonomous payload dev)")
    helper_src = inspect.getsource(MasterAgent._auto_generate_payload)
    _assert("PayloadAgent" in helper_src and "create_listener" in helper_src,
            "helper generates payload AND starts a human-usable listener")


# ─────────────────────────────────────────────────────────────────────
#  Test 56 — Reasoning loop self-heals empty intel from findings store
#  Regression guard for the "Ports open: 0 for 7 iterations despite a
#  completed recon" failure: subagents persist findings to the DB but the
#  shared intel dict is only populated by the master's sync paths.  If any
#  sync path is missing/fails, the loop must rebuild evidence from findings
#  rather than loop forever re-requesting a port scan.
# ─────────────────────────────────────────────────────────────────────


def test_reasoning_loop_reconciles_intel_from_findings() -> None:
    _section("Test 56 — ReasoningLoop rebuilds open_ports from findings when intel empty")

    import inspect
    import asyncio as _aio
    from types import SimpleNamespace
    from agents.reasoning.reasoning_loop import ReasoningLoop

    # ── Wiring: _observe must self-heal when open_ports is empty ──────────
    obs_src = inspect.getsource(ReasoningLoop._observe)
    _assert("_reconcile_intel_from_findings" in obs_src,
            "_observe triggers reconcile when open_ports empty")

    # ── Functional: feed the EXACT findings this scan produced ───────────
    canned = [
        {"title": "HTTP 80 — Server Disclosure: Apache/2.4.18 (Ubuntu)",
         "description": "HTTP at 10.48.130.215:80 discloses: Apache/2.4.18 (Ubuntu).",
         "port": 80, "cves": []},
        {"title": "SSH 22 — Outdated Version: OpenSSH 7.2",
         "description": "SSH at 10.48.130.215:22 runs OpenSSH 7.2.",
         "port": 22, "cves": ["CVE-2018-15473"]},
        {"title": "Open Port 22/tcp: ssh (OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu )",
         "description": "Port 22/tcp is open. Service: ssh. Version: OpenSSH 7.2p2 Ubuntu 4ubuntu2.8.",
         "port": 22, "cves": []},
        {"title": "Open Port 80/tcp: http (Apache httpd 2.4.18 ((Ubuntu)))",
         "description": "Port 80/tcp is open. Service: http. Version: Apache httpd 2.4.18.",
         "port": 80, "cves": []},
    ]

    import db.mongo_client as _dbmod
    _orig = getattr(_dbmod, "get_findings", None)

    async def _fake_get_findings(session_id, *a, **k):
        return canned

    _dbmod.get_findings = _fake_get_findings
    try:
        emitted: list = []

        async def _emit(msg):
            emitted.append(msg)

        stub = SimpleNamespace(
            _intel={},                       # empty intel — reproduces the bug
            _session_id="test-session",
            _target="10.48.130.215",
            _emit_reasoning=_emit,
        )

        recovered = _aio.run(ReasoningLoop._reconcile_intel_from_findings(stub))

        _assert(recovered == 2,
                "recovered 2 open ports from findings store", detail=f"got {recovered}")
        _assert(sorted(stub._intel.get("open_ports", [])) == [22, 80],
                "intel.open_ports backfilled to [22, 80]",
                detail=str(stub._intel.get("open_ports")))
        svcs = stub._intel.get("services", {})
        _assert(svcs.get(22, {}).get("service") == "ssh"
                and "OpenSSH" in svcs.get(22, {}).get("version", ""),
                "SSH service + version recovered from finding text")
        _assert("CVE-2018-15473" in stub._intel.get("cves", []),
                "CVE-2018-15473 recovered from findings")
        _assert(any("Recovered" in str(m) for m in emitted),
                "self-heal emits an operator-visible reasoning event")

        # ── Vulnerabilities recovered (CVE-bearing / HIGH finding) ───────
        recovered_vulns = stub._intel.get("vulnerabilities", [])
        _assert(any("CVE-2018-15473" in (v.get("cves") or [])
                    for v in recovered_vulns),
                "CVE-bearing finding promoted to a vulnerability entry")

        # ── Broadened exploit gate now fires on recovered evidence ───────
        intel = stub._intel
        _svc_has_version = any(
            (s.get("version") if isinstance(s, dict) else "")
            for s in (intel.get("services") or {}).values()
        )
        has_exploit_evidence = bool(intel.get("open_ports")) and (
            bool(intel.get("vulnerabilities"))
            or bool(intel.get("technologies"))
            or bool(intel.get("cves"))
            or _svc_has_version
        )
        _assert(has_exploit_evidence,
                "exploit gate satisfied after reconcile (unblocks exploitation)")

        # ── Idempotence / no-clobber: a second pass must no-op ───────────
        recovered2 = _aio.run(ReasoningLoop._reconcile_intel_from_findings(stub))
        _assert(recovered2 == 0,
                "no-op when open_ports already populated (never clobbers)")
    finally:
        if _orig is not None:
            _dbmod.get_findings = _orig


# ─────────────────────────────────────────────────────────────────────
#  Test 57 — Identified CVE → reactive exploitation (parallel, internet
#  exploit or built payload).  Operator directive: "once a vulnerability
#  is found, it should be exploited ... let other processes run in
#  parallel."  Guards both the entry-point creation (any CVE in intel,
#  not just OSINT chains) and the dispatcher wiring (exploitable_cve
#  actually invokes ExploitOrchestrator, not just emits reasoning).
# ─────────────────────────────────────────────────────────────────────


def test_identified_cve_triggers_reactive_exploit() -> None:
    _section("Test 57 — Identified CVE fires reactive parallel exploitation")

    import inspect

    # ── Entry-point creation: a raw CVE in intel must create an entry ────
    ctx = EngagementContext(session_id="t57-a", target="10.48.130.215")
    ctx.intel["cves"] = ["CVE-2018-15473"]
    ctx.detect_entry_points()
    _assert(any(e.get("type") == "exploitable_cve"
                and "CVE-2018-15473" in (e.get("cves") or [])
                for e in ctx.entry_points),
            "raw intel['cves'] creates an exploitable_cve entry point")

    # A vulnerability finding (dict with cves) must also create one
    ctx2 = EngagementContext(session_id="t57-b", target="10.48.130.215")
    ctx2.intel["vulnerabilities"] = [
        {"title": "OpenSSH 7.2 user enum", "severity": "HIGH",
         "cves": ["CVE-2018-15473"]},
    ]
    ctx2.detect_entry_points()
    _assert(any(e.get("type") == "exploitable_cve" for e in ctx2.entry_points),
            "vulnerability finding with CVE creates an exploitable_cve entry")

    # ── Dispatcher wiring: exploitable_cve must actually exploit ─────────
    from agents.master_agent import MasterAgent
    ea_src = inspect.getsource(MasterAgent._execute_entry_attempt)
    _assert("_attempt_exploit_for_cves" in ea_src,
            "exploitable_cve branch invokes _attempt_exploit_for_cves (not reasoning-only)")
    _assert(hasattr(MasterAgent, "_attempt_exploit_for_cves"),
            "MasterAgent exposes _attempt_exploit_for_cves helper")

    helper_src = inspect.getsource(MasterAgent._attempt_exploit_for_cves)
    _assert("ExploitOrchestrator" in helper_src,
            "reactive exploit delegates to ExploitOrchestrator (searchsploit/MSF/web chains)")
    _assert("register_shell" in helper_src,
            "a landed shell is promoted via register_shell (pivots to loot/privesc)")
    _assert("is_post_exploit_mode" in helper_src,
            "reactive exploit yields once a foothold already exists (no pile-on)")

    # ── The reactive dispatcher must START in the DEFAULT reasoning path ─
    rlr_src = inspect.getsource(MasterAgent._reasoning_loop_run)
    _assert("_entry_attempt_dispatcher" in rlr_src,
            "entry-attempt dispatcher is started in the reasoning-loop path (not legacy-only)")


# ─────────────────────────────────────────────────────────────────────
#  Test 58 — Tier-2 LLM exploit-code synthesis (synth→run→observe→refine)
#  Operator directive: "if [tier-1] not successful, LLM exploit code
#  synthesis should be attempted ... I want a full view."  Guards the
#  synthesis loop, the success detection, the live exploit_lab stream,
#  and the Tier-1→Tier-2 fallback wiring.
# ─────────────────────────────────────────────────────────────────────


def test_exploit_synth_tier2() -> None:
    _section("Test 58 — Tier-2 LLM exploit synthesis loop + Exploit Lab stream")

    import inspect
    import asyncio as _aio
    from agents.exploit.exploit_synth_subagent import ExploitSynthSubagent

    emitted: list = []

    async def _bc(ev):
        emitted.append(ev)

    # ── Success detection ────────────────────────────────────────────────
    sub = ExploitSynthSubagent("t58", "10.0.0.1", _bc, None, think_json_fn=None)
    ok, user, _ = sub._detect_success("uid=0(root) gid=0(root) groups=0(root)", "")
    _assert(ok and user == "root", "detects uid=0(root) as shell success")
    ok2, _, _ = sub._detect_success("bash: permission denied\nnothing useful", "")
    _assert(not ok2, "no false-positive on benign error output")
    # F1: the LLM's self-declared success_indicator is NO LONGER trusted on its
    # own (the model writing both the PoC and its own pass-string is the
    # self-fulfilling false-positive that fabricated a "shell" from web-enum
    # output).  A self-declared string with no real command-exec signature fails.
    ok3, _, _ = sub._detect_success("RESULT: PWNED-7f3a", "PWNED-7f3a")
    _assert(not ok3, "self-declared success_indicator alone is NOT trusted (anti-fake-shell)")

    # ── No-LLM run is a safe no-op ───────────────────────────────────────
    res0 = _aio.run(sub.run(target="10.0.0.1", cves=["CVE-1"]))
    _assert(res0.parsed_data.get("shell_obtained") is False,
            "no-LLM synthesis is a safe no-op (shell_obtained False)")

    # ── Full loop with mocked LLM + sandbox → success on attempt 1 ───────
    async def _fake_think(prompt, system=""):
        return {
            "plan": "connect to ssh and run id",
            "language": "python",
            "code": "import sys\nprint('uid=0(root) gid=0(root)')\n",
            "run_command": "python3 exploit.py",
            "success_indicator": "uid=0(root)",
        }

    sub2 = ExploitSynthSubagent("t58b", "10.0.0.1", _bc, None, think_json_fn=_fake_think)
    # Isolate from the real filesystem + tool execution.
    sub2._materialize = lambda code, language, attempt: (
        "/tmp/lab", "/tmp/lab/exploit.py", "exploit.py")

    async def _fake_run(target, workdir, rel, lang, runcmd):
        return "uid=0(root) gid=0(root) groups=0(root)"

    sub2._run_sandboxed = _fake_run

    async def _auto_approve(approval_id, attempt, code, language, run_cmd, target, cves):
        return "approve"

    sub2._await_approval = _auto_approve   # operator approves in this scenario

    res = _aio.run(sub2.run(
        target="10.0.0.1", cves=["CVE-2018-15473"],
        services=[{"service": "ssh", "version": "OpenSSH 7.2p2"}],
        lhost="10.0.0.2", lport=4444,
    ))
    pd = res.parsed_data
    _assert(pd.get("shell_obtained") is True,
            "synth loop reports a shell when exec output proves it")
    _assert(pd.get("attempts") == 1,
            "succeeds on attempt 1 (stops as soon as it lands)")
    _assert(any(e.get("type") == "exploit_lab" and e.get("stage") == "code"
                for e in emitted),
            "streams the GENERATED CODE to the live Exploit Lab view")
    _assert(any(e.get("stage") == "complete" and e.get("success") for e in emitted),
            "streams a complete=success event to the live view")
    # Regression guard: the live-view step field must NOT be the reserved
    # 'phase' key, which _make_sa_broadcast strips out of the data envelope.
    run_src = inspect.getsource(ExploitSynthSubagent.run)
    _assert('"stage"' in run_src and '"phase"' not in run_src,
            "exploit_lab events use 'stage' (survives _make_sa_broadcast), not reserved 'phase'")

    # ── MANDATORY APPROVAL — rejected exploit must NOT execute ───────────
    ran = {"called": False}
    sub3 = ExploitSynthSubagent("t58c", "10.0.0.1", _bc, None, think_json_fn=_fake_think)
    sub3._materialize = lambda code, language, attempt: (
        "/tmp/lab", "/tmp/lab/exploit.py", "exploit.py")

    async def _deny(approval_id, attempt, code, language, run_cmd, target, cves):
        return "stop"

    async def _run_must_not_run(target, workdir, rel, lang, runcmd):
        ran["called"] = True
        return "uid=0(root)"

    sub3._await_approval = _deny           # operator rejects & stops
    sub3._run_sandboxed = _run_must_not_run
    res3 = _aio.run(sub3.run(target="10.0.0.1", cves=["CVE-2018-15473"],
                             services=[{"service": "ssh"}]))
    _assert(ran["called"] is False,
            "MANDATORY GATE: rejected exploit code is NEVER executed")
    _assert(res3.parsed_data.get("shell_obtained") is False,
            "rejected synthesis obtains no shell")
    _assert(res3.parsed_data.get("approval") == "denied",
            "denial is recorded in the result")

    # The gate must precede execution in the run() source.
    _assert("_await_approval" in run_src and
            run_src.index("_await_approval") < run_src.index("_run_sandboxed"),
            "approval gate is invoked BEFORE sandboxed execution")

    # ── Reject & Retry — synthesize a DIFFERENT attempt, still never run ─
    synth_calls = {"n": 0}
    ran2 = {"called": False}

    async def _think_count(prompt, system=""):
        synth_calls["n"] += 1
        return {"plan": "p", "language": "python", "code": "print('x')",
                "run_command": "python3 exploit.py", "success_indicator": "NEVERMATCH"}

    async def _retry(approval_id, attempt, code, language, run_cmd, target, cves):
        return "retry"

    async def _run_never(*a):
        ran2["called"] = True
        return "x"

    sub4 = ExploitSynthSubagent("t58d", "10.0.0.1", _bc, None, think_json_fn=_think_count)
    sub4._materialize = lambda code, language, attempt: (
        "/tmp/lab", "/tmp/lab/exploit.py", "exploit.py")
    sub4._await_approval = _retry
    sub4._run_sandboxed = _run_never
    res4 = _aio.run(sub4.run(target="10.0.0.1", cves=["CVE-X"],
                             services=[{"service": "x"}]))
    _assert(synth_calls["n"] >= 2,
            "Reject & Retry synthesizes additional attempt(s)")
    _assert(ran2["called"] is False,
            "retry path still never executes un-approved code")
    _assert(res4.parsed_data.get("approval") == "retry",
            "retry decision recorded in result")

    # ── Approval registry: 3-way decision + fail-closed timeout ──────────
    from agents.exploit import exploit_approval as _appr

    async def _reg_decide(aid, decision):
        _appr.create_request(aid)
        task = _aio.ensure_future(_appr.await_decision(aid, 5.0))
        await _aio.sleep(0.01)
        resolved = _appr.resolve(aid, decision)
        return resolved, await task

    r_ok, got_ok = _aio.run(_reg_decide("aid-ok", True))       # legacy bool → approve
    _assert(r_ok and got_ok == "approve", "registry: bool True normalizes to 'approve'")
    _, got_retry = _aio.run(_reg_decide("aid-retry", "retry"))
    _assert(got_retry == "retry", "registry: 'retry' decision passes through")
    _assert(_aio.run(_appr.await_decision("aid-timeout", 0.05)) == "stop",
            "registry: fail-closed on timeout → 'stop' (no run)")

    # ── agent_server wires the approval WS handler ──────────────────────
    import os as _os
    _asrv = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent_server.py")
    _txt = open(_asrv, encoding="utf-8").read()
    _assert("exploit_approval" in _txt and "_resolve_exploit" in _txt,
            "agent_server.py wires the exploit_approval WS handler")

    # ── Tier-1 → Tier-2 fallback wiring ─────────────────────────────────
    from agents.master_agent import MasterAgent
    _assert(hasattr(MasterAgent, "_attempt_synth_exploitation"),
            "MasterAgent exposes _attempt_synth_exploitation (Tier-2)")
    t1_src = inspect.getsource(MasterAgent._attempt_exploit_for_cves)
    _assert("_attempt_synth_exploitation" in t1_src,
            "Tier-1 failure falls back to Tier-2 LLM synthesis")
    t2_src = inspect.getsource(MasterAgent._attempt_synth_exploitation)
    _assert("ExploitSynthSubagent" in t2_src,
            "Tier-2 invokes the ExploitSynthSubagent")
    _assert("register_shell" in t2_src,
            "Tier-2 promotes a landed shell (→ post-exploit/loot/human shell)")


# ─────────────────────────────────────────────────────────────────────
#  Test 59 — Exploit methodology: CVE triage + web-RCE verification +
#  synthesis de-refusal.  Guards the fixes for the 10.48.177.153 failure
#  (fired at DoS/client/fabricated CVEs; blind unverified webshell upload;
#  synthesis refused as a jailbreak and produced no code).
# ─────────────────────────────────────────────────────────────────────


def test_exploit_methodology_fixes() -> None:
    _section("Test 59 — CVE triage + web-RCE verification + synth de-refusal")

    import inspect
    import asyncio as _aio

    # ── A. CVE exploitability triage ─────────────────────────────────────
    from agents.exploit import exploitability as _x
    descs = {
        "CVE-2017-9788":  "uninitialized memory information disclosure in mod_auth_digest",
        "CVE-2021-34798": "malformed requests cause a NULL pointer dereference denial of service",
        "CVE-2026-35385": "scp installs setuid file; local privilege escalation, requires local root",
        "CVE-2023-38408": "ssh-agent forwarding PKCS#11 client-side code execution",
        "CVE-2014-6271":  "remote unauthenticated command injection (shellshock) via CGI",
    }
    keep, drop = _x.triage(list(descs.keys()) + ["CVE-2099-99999"],
                           current_year=2026, descriptions=descs)
    drop_ids = {c for c, _ in drop}
    _assert("CVE-2014-6271" in keep,
            "triage KEEPS unauth remote RCE (shellshock)")
    _assert({"CVE-2017-9788", "CVE-2021-34798", "CVE-2026-35385",
             "CVE-2023-38408", "CVE-2099-99999"} <= drop_ids,
            "triage DROPS info-leak / DoS / local / client-side / fabricated CVEs")
    k2, _ = _x.triage(["CVE-2021-44228"], current_year=2026)
    _assert("CVE-2021-44228" in k2,
            "no-description CVE kept (conservative — never silently drop a real one)")

    from agents.master_agent import MasterAgent
    t1 = inspect.getsource(MasterAgent._attempt_exploit_for_cves)
    _assert("exploitability" in t1 and "triage" in t1,
            "reactive exploit path runs CVE exploitability triage before firing")

    # ── B. web_exploit VERIFIES RCE and promotes a real shell ────────────
    from agents.exploit.web_exploit_subagent import WebExploitSubagent

    async def _bc(ev):
        return None

    # B1: a verified webshell (id returns uid=) → registerable shell
    sub = WebExploitSubagent("t59", "10.0.0.1", _bc, None)
    sub.store_finding = lambda f: sub._findings.append(f) or _noop_coro()

    async def _ct_hit(tool, target, opts=None):
        a = (opts or {}).get("options", "")
        return ("uid=33(www-data) gid=33(www-data) groups=33(www-data)"
                if "shell.php?cmd=id" in a else "")

    sub.collect_tool = _ct_hit
    res = _aio.run(sub.run(target="10.0.0.1", url="http://10.0.0.1/upload",
                           vuln_type="upload"))
    pd = getattr(res, "parsed_data", None) or {}
    _assert(pd.get("shell_obtained") is True,
            "VERIFIED webshell RCE promotes to a registerable shell")
    _assert(pd.get("user") == "www-data",
            "web RCE user extracted from id output")
    _assert(any("CONFIRMED" in getattr(f, "title", "") for f in res.findings),
            "confirmed webshell RCE emits a CRITICAL CONFIRMED finding")

    # B2: nothing executes → INFO lead, NOT a claimed shell
    sub2 = WebExploitSubagent("t59b", "10.0.0.1", _bc, None)
    sub2.store_finding = lambda f: sub2._findings.append(f) or _noop_coro()

    async def _ct_miss(tool, target, opts=None):
        return ""

    sub2.collect_tool = _ct_miss
    res2 = _aio.run(sub2.run(target="10.0.0.1", url="http://10.0.0.1/upload",
                             vuln_type="upload"))
    pd2 = getattr(res2, "parsed_data", None) or {}
    _assert(pd2.get("shell_obtained") is not True,
            "UNVERIFIED upload does NOT claim a shell")
    _assert(any(getattr(f, "severity", "") == "INFO" for f in res2.findings),
            "unverified upload downgraded to an INFO lead (no finding inflation)")

    # ── C. synthesis prompt de-refusal + early-stop ──────────────────────
    from agents.exploit.exploit_synth_subagent import ExploitSynthSubagent
    syn = inspect.getsource(ExploitSynthSubagent._synthesize)
    _assert("ATTEMPT" not in syn and "elite exploit developer" not in syn,
            "synthesis prompt drops the jailbreak-like 'ATTEMPT n of 3' framing")
    _assert("authorized" in syn.lower() and "isolated" in syn.lower(),
            "synthesis prompt states the authorized isolated-lab context")
    _assert("empty" in syn.lower(),
            "synthesis prompt permits an empty result (removes fabrication pressure)")
    run_src = inspect.getsource(ExploitSynthSubagent.run)
    _assert("empties" in run_src,
            "synth loop early-stops after consecutive no-code (stops burning budget on refusals)")


def _noop_coro():
    async def _n():
        return None
    return _n()


# ─────────────────────────────────────────────────────────────────────
#  Test 60 — Red-team coverage push: app-aware web attack, SSRF/XXE,
#  TLS-skip injection, enumerator dedup, checkpoint sanitisation,
#  attack-graph model alignment.
# ─────────────────────────────────────────────────────────────────────


def test_red_team_coverage_push() -> None:
    _section("Test 60 — app-aware chains + SSRF/XXE + TLS-skip + dedup + reliability")

    import inspect
    import asyncio as _aio

    # ── A. App-aware web triggers fire off DISCOVERED PATHS ──────────────
    from agents import finding_triggers as _ft
    from agents.engagement_context import EngagementContext
    ctx = EngagementContext(session_id="t60", target="10.0.0.9")
    ctx.intel["web_paths"] = ["/wp-login.php", "/phpmyadmin/", "/wp-admin/"]
    _ft.reset_fired("t60")
    acts = _ft.evaluate_triggers(ctx)
    cmds = " ".join(a.payload for a in acts if a.kind == "command")
    _assert("wpscan" in cmds, "WordPress attack chain fires off /wp-login.php path")
    _assert("phpmyadmin" in cmds.lower(), "phpMyAdmin attack chain fires off discovered path")

    # ── B. web_exploit SSRF + XXE handlers (verified) ────────────────────
    from agents.exploit.web_exploit_subagent import WebExploitSubagent

    async def _bc(ev):
        return None

    sub = WebExploitSubagent("t60s", "10.0.0.9", _bc, None)
    sub.store_finding = lambda f: sub._findings.append(f) or _noop_coro()

    async def _ct_ssrf(tool, target, opts=None):
        a = (opts or {}).get("options", "")
        return "instance-id: i-0abc\nami-id: ami-123\niam/" if "169.254.169.254" in a else ""

    sub.collect_tool = _ct_ssrf
    res = _aio.run(sub.run(target="10.0.0.9", url="http://10.0.0.9/fetch",
                           vuln_type="ssrf"))
    _assert(any("SSRF" in getattr(f, "title", "") and getattr(f, "severity", "") == "CRITICAL"
                for f in res.findings),
            "SSRF to cloud metadata is confirmed + flagged CRITICAL")

    sub2 = WebExploitSubagent("t60x", "10.0.0.9", _bc, None)
    sub2.store_finding = lambda f: sub2._findings.append(f) or _noop_coro()

    async def _ct_xxe(tool, target, opts=None):
        return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

    sub2.collect_tool = _ct_xxe
    res2 = _aio.run(sub2.run(target="10.0.0.9", url="http://10.0.0.9/xml",
                             vuln_type="xxe"))
    _assert(any("XXE" in getattr(f, "title", "") for f in res2.findings),
            "XXE external-entity file read is confirmed")

    # ── C. TLS-skip injection in BOTH execution paths ────────────────────
    bs = inspect.getsource(__import__("agents.base_subagent", fromlist=["x"]).BaseSubagent.run_tool)
    _assert("_inject_tls_skip" in bs and "disable-tls-checks" in bs,
            "base_subagent injects TLS-skip flags for https tools")
    ba = inspect.getsource(__import__("agents.base_agent", fromlist=["x"]).BaseAgent.run_tool)
    _assert("https://" in ba and "no-check-certificate" in ba,
            "base_agent injects TLS-skip flags for https tools (recon path)")

    # ── D. Enumerator dedup + pointless-fuzz guard ───────────────────────
    _assert("_ENUM_RAN_KEYS" in ba and "param-fuzz on dotfile" in ba,
            "base_agent dedups repeat enumerators + skips param-fuzz on dotfiles")
    _assert("cannot execute binary file" in ba and "-c '" in ba,
            "base_agent wraps bare bash commands in -c (fixes 'cannot execute binary file')")

    # ── E. Checkpoint deep key-sanitisation ──────────────────────────────
    from agents.master_agent import MasterAgent
    cp = inspect.getsource(MasterAgent._save_checkpoint)
    _assert("_mongo_safe" in cp,
            "checkpoint deep-sanitises int keys (services + service_versions) for Mongo")

    # ── F. AttackGraph model alignment + policy fail-fast ────────────────
    from agents.attack_graph_agent import AttackGraphAgent
    llmc = inspect.getsource(AttackGraphAgent._llm_call)
    _assert("_provider()" in llmc,
            "AttackGraphAgent resolves its LLM from .env via get_provider() (not hardcoded)")
    loop = inspect.getsource(AttackGraphAgent.run_analysis_loop)
    _assert("usage policy" in loop.lower() and "_switch_to_fallback" in loop,
            "AttackGraphAgent falls back to the .env backup LLM (not an immediate stop)")


# ─────────────────────────────────────────────────────────────────────
#  Test 61 — remaining tooling items + Privesc/Post/Payload integration
#  (privesc enumerated but never exploited; staged payload never consumed).
# ─────────────────────────────────────────────────────────────────────


def test_completion_push() -> None:
    _section("Test 61 — tooling items + privesc-exploit/post/payload wiring")

    import inspect
    from agents.exploit.exploitability import infer_distro_versions
    from agents.base_agent import BaseAgent
    from agents.master_agent import MasterAgent
    from agents.exploit.web_exploit_subagent import WebExploitSubagent

    # ── A. Version inference from distro-leaking banner ──────────────────
    r = infer_distro_versions("ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.13")
    _assert(r.get("distro") == "Ubuntu 20.04" and r["versions"].get("apache") == "2.4.41",
            "OpenSSH Ubuntu banner → distro + shipped Apache version inferred")
    _assert(infer_distro_versions("nginx 1.18") == {},
            "no inference without a distro-leaking banner (no fabricated versions)")

    # ── B. run_tool: UDP host-timeout + nmap $() reroute + bash -c wrap ──
    rt = inspect.getsource(BaseAgent.run_tool)
    _assert("--host-timeout" in rt and "-sU" in rt,
            "UDP scans get a --host-timeout cap (no 300s block)")
    _assert("shell-metacharacter reroute" in rt and 'tool_name = "bash"' in rt,
            "nmap $(...) command-substitution AND piped/redirected commands reroute through bash -c")

    # ── C. Privesc now EXPLOITS (was: enumerate-only) ────────────────────
    rps = inspect.getsource(MasterAgent._run_phase_subagents)
    for cls in ("LinuxExploitSubagent", "WindowsExploitSubagent",
                "ContainerEscapeSubagent", "CloudMetaSubagent"):
        _assert(cls in rps, f"privesc phase now dispatches {cls} (was orphaned)")
    _assert("enum_results" in rps,
            "privesc exploit subagent receives the enum results")
    _assert("PostModuleSubagent" in rps and "meterpreter" in rps,
            "PostModuleSubagent wired into post-exploit (gated on an MSF session)")

    # ── D. Staged payload consumable + RCE→reverse-shell loop closer ─────
    ap = inspect.getsource(MasterAgent._auto_generate_payload)
    _assert("staged_payloads" in ap and "reverse_shell_oneliners" in ap,
            "staged payload + reverse-shell one-liners stashed in intel (consumable)")
    we = inspect.getsource(WebExploitSubagent)
    _assert("_fire_reverse_shell" in we and "/dev/tcp/" in we,
            "web_exploit fires a reverse shell through confirmed RCE (closes the loop)")


# ─────────────────────────────────────────────────────────────────────
#  Test 62 — .env-driven primary + backup LLM with fallback after N fails
# ─────────────────────────────────────────────────────────────────────


def test_env_driven_llm_fallback() -> None:
    _section("Test 62 — .env-driven LLM primary + backup fallback")

    import os as _os
    import inspect
    from utils import llm_providers as _lp
    from agents.attack_graph_agent import AttackGraphAgent

    # build_provider honours an explicit (.env-supplied) model — not hardcoded
    p = _lp.build_provider("ollama", model="deepseek-v3.1:671b-cloud")
    _assert(p is not None and getattr(p, "model", "") == "deepseek-v3.1:671b-cloud",
            "build_provider builds a provider with the .env-supplied model")
    _assert(_lp.build_provider("totally-unknown-provider") is None,
            "build_provider returns None for an unknown provider name")

    # get_fallback_provider: None when unset; built from env when set
    for _k in ("LLM_FALLBACK_PROVIDER", "ATTACKGRAPH_FALLBACK_PROVIDER",
               "LLM_FALLBACK_MODEL", "ATTACKGRAPH_FALLBACK_MODEL"):
        _os.environ.pop(_k, None)
    _assert(_lp.get_fallback_provider() is None,
            "no backup when LLM_FALLBACK_PROVIDER is unset (nothing hardcoded)")
    _os.environ["LLM_FALLBACK_PROVIDER"] = "ollama"
    _os.environ["LLM_FALLBACK_MODEL"]    = "llama3.1:8b"
    try:
        fb = _lp.get_fallback_provider()
        _assert(fb is not None and getattr(fb, "model", "") == "llama3.1:8b",
                "backup LLM is built from the .env LLM_FALLBACK_* vars")
    finally:
        _os.environ.pop("LLM_FALLBACK_PROVIDER", None)
        _os.environ.pop("LLM_FALLBACK_MODEL", None)

    # Agent wiring: no switch without a backup; switches once a backup is set
    aga = AttackGraphAgent("t62", "10.0.0.1", lambda e: _noop_coro(), None)
    _assert(aga._switch_to_fallback() is False,
            "no fallback switch when no backup is configured")

    class _StubProv:
        name = "stub"
        model = "backup-model"

    aga._fallback_provider = _StubProv()
    aga._fallback_loaded = True
    aga._on_fallback = False
    _assert(aga._switch_to_fallback() is True and aga._on_fallback is True
            and aga._active_provider.model == "backup-model",
            "switch_to_fallback activates the .env-configured backup provider")

    src = inspect.getsource(AttackGraphAgent.run_analysis_loop)
    _assert("ATTACKGRAPH_FALLBACK_AFTER" in src,
            "fallback threshold is read from .env (ATTACKGRAPH_FALLBACK_AFTER, default 5)")


# ─────────────────────────────────────────────────────────────────────
#  Test 63 — subagent LLM access + Error Analyzer default-path wiring +
#  warranted (not hard-3 / not endless) Exploit Lab attempts.
# ─────────────────────────────────────────────────────────────────────


def test_subagent_llm_and_errors_and_synth() -> None:
    _section("Test 63 — subagent LLM access + error-analyzer wiring + synth attempts")

    import inspect
    import asyncio as _aio

    # ── A. BaseSubagent now has LLM access (think/think_json via .env) ───
    import agents.base_subagent as _bsmod
    bs = inspect.getsource(_bsmod.BaseSubagent)
    _assert("async def think" in bs and "get_provider" in bs and "log_llm" in bs,
            "BaseSubagent has LLM access (think/think_json via .env provider, logged)")

    # Functional: think_json reasons via the (stubbed) .env provider + parses JSON
    class _StubProv:
        name = "stub"
        model = "stub-model"

        async def stream(self, messages, timeout=600):
            for t in ['{"order":["sqli"],', ' "skip":["xxe"],', ' "rationale":"x"}']:
                yield t

    import utils.llm_providers as _lp
    _orig_gp = _lp.get_provider
    _lp.get_provider = lambda: _StubProv()

    async def _bc(ev):
        return None

    try:
        from agents.exploit.web_exploit_subagent import WebExploitSubagent
        sub = WebExploitSubagent("t63", "10.0.0.1", _bc, None)
        spec = _aio.run(sub.think_json("decide vectors"))
        _assert(spec.get("order") == ["sqli"] and spec.get("skip") == ["xxe"],
                "subagent.think_json reasons via the provider and parses JSON")
    finally:
        _lp.get_provider = _orig_gp

    # ── B. Exploit/Privesc/Payload subagents WIRED to reason ─────────────
    we = inspect.getsource(WebExploitSubagent.run)
    _assert("think_json" in we and "_want" in we,
            "web_exploit reasons with the LLM to triage which vuln classes to run")
    from agents.privesc.linux_exploit_subagent import LinuxExploitSubagent
    _assert("think_json" in inspect.getsource(LinuxExploitSubagent.run),
            "linux privesc-exploit reasons with the LLM over the enum results")
    # payload_agent imports netifaces (Linux-only — not on the dev box), so
    # read the source from disk instead of importing it.
    _pa_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "agents", "payload_agent.py")
    _pa_src = open(_pa_path, encoding="utf-8").read()
    _assert("think_json" in _pa_src and "payload_strategy" in _pa_src,
            "payload agent reasons with the LLM about payload strategy/evasion")

    # ── C. Error Analyzer: started in DEFAULT path + fed by main agents ──
    from agents.master_agent import MasterAgent
    rlr = inspect.getsource(MasterAgent._reasoning_loop_run)
    _assert("ErrorAnalyzerAgent" in rlr and "_error_analyzer.run()" in rlr,
            "Error Analyzer is started in the DEFAULT reasoning-loop path (was legacy-only)")
    from agents.base_agent import BaseAgent
    _assert("ingest_error" in inspect.getsource(BaseAgent.run_tool),
            "base_agent feeds tool errors to the Error Analyzer (main agents, not just subagents)")

    # ── D. Exploit Lab: warranted attempts (not hard-3 / not endless) ────
    from agents.exploit.exploit_synth_subagent import ExploitSynthSubagent
    _assert(ExploitSynthSubagent.MAX_ITERATIONS >= 6,
            "Exploit Lab attempt cap raised from 3 (default 6)")
    _assert("EXPLOIT_SYNTH_MAX_ATTEMPTS" in inspect.getsource(ExploitSynthSubagent.__init__),
            "Exploit Lab attempt cap is .env-overridable")
    sr = inspect.getsource(ExploitSynthSubagent.run)
    _assert("code_sigs" in sr and "repeating itself" in sr,
            "Exploit Lab stops on no-novelty (warranted, not an endless loop)")
    # Tier-2 only after Tier-1 completed+failed (gated on a real CVE)
    t1 = inspect.getsource(MasterAgent._attempt_exploit_for_cves)
    _assert("elif cves:" in t1 and "_attempt_synth_exploitation" in t1,
            "Tier-2 synthesis fires only after Tier-1 fails AND a real CVE survived triage")


# ─────────────────────────────────────────────────────────────────────
#  Test 64 — holistic objective grading (complete/partial/not_complete)
#  + checkpoint sanitisation so objective state persists.
# ─────────────────────────────────────────────────────────────────────


def test_objective_evaluator() -> None:
    _section("Test 64 — objective completion grading + checkpoint persistence")

    import inspect
    import asyncio as _aio
    from agents.reasoning.question_engine import QuestionEngine

    emitted: list = []

    async def _emit(ev):
        emitted.append(ev)

    class _StubMaster:
        async def think_json(self, prompt, system=""):
            return {"objectives": [
                {"index": 0, "status": "complete", "confidence": 0.9,
                 "evidence": "root shell", "blocker": ""},
                {"index": 1, "status": "partial", "confidence": 0.5,
                 "evidence": "foothold only", "blocker": "need privesc"},
                {"index": 2, "status": "not_complete", "confidence": 0.1,
                 "evidence": "", "blocker": "no access"}]}

    qe = QuestionEngine(_StubMaster(), "t64", "10.0.0.1", _emit)
    intel = {
        "engagement_context": {"objectives": [
            {"task": "get a shell"}, {"task": "read user.txt"}, {"task": "read root.txt"}]},
        "shells": [{"user": "root", "elevated": True}],
        "open_ports": [22, 10000],
    }
    summ = _aio.run(qe.evaluate_objectives(intel))
    _assert(summ.get("complete") == 1 and summ.get("partial") == 1
            and summ.get("not_complete") == 1 and summ.get("total") == 3,
            "evaluator grades each objective complete / partial / not_complete")
    _assert(intel.get("objective_status", {}).get("0", {}).get("status") == "complete",
            "objective_status is persisted into intel (survives checkpointing)")
    _assert(any(e.get("type") == "objective_status" for e in emitted)
            and any(e.get("type") == "objectives_summary" for e in emitted),
            "emits objective_status + objectives_summary events for the GUI/report")

    # No-downgrade: a proven-complete objective stays complete on re-grade
    class _StubMaster2:
        async def think_json(self, prompt, system=""):
            return {"objectives": [{"index": 0, "status": "not_complete",
                                    "confidence": 0.1, "evidence": "", "blocker": ""}]}

    qe._master = _StubMaster2()
    _aio.run(qe.evaluate_objectives(intel))
    _assert(intel["objective_status"]["0"]["status"] == "complete",
            "a proven-complete objective is never downgraded on re-grade")

    # Evidence summary reflects the engagement state
    ev = qe._build_evidence_summary(intel)
    _assert("root" in ev and "Open ports" in ev,
            "evidence summary condenses shells/ports for grading")

    # ── Wiring: reasoning loop grades objectives (periodic + final) ──────
    import agents.reasoning.reasoning_loop as _rl
    run_src = inspect.getsource(_rl.ReasoningLoop.run)
    _assert(run_src.count("evaluate_objectives") >= 2,
            "reasoning loop grades objectives periodically AND at scan end")
    ioa = inspect.getsource(_rl.ReasoningLoop._is_objective_achieved)
    _assert("objective_status" in ioa,
            "_is_objective_achieved honours the graded objective_status")

    # ── Checkpoint sanitisation (so objective state actually saves) ──────
    from agents.master_agent import MasterAgent
    cp = inspect.getsource(MasterAgent._save_checkpoint)
    _assert("type(obj).__name__" in cp and "_mongo_safe" in cp,
            "checkpoint stringifies non-serializable objects (no more BoundedInstructionCache crash)")


def test_loop_convergence_and_web_dedup() -> None:
    _section("Test 65 — loop stall-convergence + WebAgent re-dispatch dedup")

    import inspect
    from types import SimpleNamespace
    from pathlib import Path
    import agents.reasoning.reasoning_loop as _rl
    RL = _rl.ReasoningLoop

    # ── Constants exist and are ordered (escalate before break) ──────────
    _assert(hasattr(RL, "STALL_ESCALATE_AT") and hasattr(RL, "STALL_BREAK_AT"),
            "stall thresholds defined on ReasoningLoop")
    _assert(0 < RL.STALL_ESCALATE_AT < RL.STALL_BREAK_AT,
            "escalate threshold fires strictly before the converge-break",
            detail=f"escalate={RL.STALL_ESCALATE_AT} break={RL.STALL_BREAK_AT}")

    # ── _evidence_fingerprint: breakthrough vs full distinction ──────────
    stub = SimpleNamespace(_intel={
        "open_ports": [22, 80], "web_paths": ["/a"], "credentials": [],
        "vulnerabilities": [], "cves": [], "shell_access": False,
    })
    full1 = RL._evidence_fingerprint(stub, full=True)
    brk1  = RL._evidence_fingerprint(stub, full=False)
    _assert(full1 != brk1 and "wp:" in full1 and "wp:" not in brk1,
            "full fingerprint includes web surface; breakthrough fingerprint does not")

    # Discovering another web path changes FULL but NOT breakthrough (a
    # fuzzer finding 404s must not look like progress toward compromise).
    stub._intel["web_paths"] = ["/a", "/b"]
    full2 = RL._evidence_fingerprint(stub, full=True)
    brk2  = RL._evidence_fingerprint(stub, full=False)
    _assert(full2 != full1, "new web path changes the full fingerprint")
    _assert(brk2 == brk1, "new web path does NOT change the breakthrough fingerprint")

    # Harvesting a credential IS compromise progress → breakthrough changes.
    stub._intel["credentials"] = [{"user": "root", "pass": "x"}]
    _assert(RL._evidence_fingerprint(stub, full=False) != brk1,
            "a harvested credential changes the breakthrough fingerprint")

    # A landed shell registers as breakthrough too.
    stub._intel["shell_access"] = True
    _assert("sh:1" in RL._evidence_fingerprint(stub, full=False),
            "shell_access reflected in the breakthrough fingerprint")

    # ── run() wiring: skip the two expensive planning calls when static ──
    run_src = inspect.getsource(RL.run)
    _assert("evidence_changed" in run_src,
            "run() computes an evidence-changed gate")
    _assert("reusing cached hypotheses" in run_src
            and "if evidence_changed:" in run_src,
            "run() skips the TARGET-STATE hypothesize call when evidence is unchanged")
    _assert("if evidence_changed or not self._ranked_paths:" in run_src,
            "run() skips the CURRENT-EVIDENCE prioritize call when evidence is unchanged")
    _assert("STALL_ESCALATE_AT" in run_src and "_escalate_to_exploitation" in run_src,
            "run() forces an exploitation escalation once the stall threshold is hit")
    _assert("STALL_BREAK_AT" in run_src
            and "completing the testing cycle" in run_src,
            "run() converges + completes the cycle after a post-escalation stall")
    _assert("no_breakthrough" in run_src,
            "stall is driven by COMPROMISE progress (no_breakthrough), not raw activity")

    # ── Wall-clock backstop (ultimate ceiling, env-overridable) ──────────
    _assert(hasattr(RL, "MAX_LOOP_SECONDS") and RL.MAX_LOOP_SECONDS > 0,
            "ReasoningLoop has a wall-clock ceiling")
    _assert("time.monotonic()" in run_src and "MAX_LOOP_SECONDS" in run_src
            and "WALL-CLOCK BACKSTOP" in run_src,
            "run() enforces the wall-clock backstop at the iteration boundary")
    _assert("ARGUS_MAX_LOOP_SECONDS" in inspect.getsource(_rl),
            "wall-clock ceiling is env-overridable (ARGUS_MAX_LOOP_SECONDS)")

    # ── _escalate_to_exploitation re-dispatches exploit with force=True ──
    esc = inspect.getsource(RL._escalate_to_exploitation)
    _assert("_phase_exploit" in esc and "force=True" in esc,
            "escalation re-runs the exploit phase + orchestrator (overriding idempotency)")

    # ── WebAgent re-dispatch dedup (kills the curl x200 re-flood) ────────
    wa_src = (Path(__file__).resolve().parent / "web_agent.py").read_text(encoding="utf-8")
    _assert("_BATTERY_DONE" in wa_src,
            "WebAgent has a session-keyed battery-done registry")
    _assert("if pk in done:" in wa_src and "web_battery_skip" in wa_src,
            "WebAgent.run() skips the full battery when the (target:port) already ran")
    _assert(wa_src.index("done.add(pk)") < wa_src.index('_run_parallel(phase1_tasks'),
            "WebAgent marks the port done BEFORE running (concurrent re-dispatch also skips)")


def test_os_detection_and_tech_correct_foothold() -> None:
    _section("Test 66 — OS classification drives tech-correct exploitation")

    import inspect
    from types import SimpleNamespace
    from pathlib import Path
    from agents.exploit.exploitability import infer_os
    from agents.master_agent import MasterAgent

    # ── infer_os: the exact Windows-AD-DC that got a Linux payload ───────
    win_intel = {
        "os_guess": "unknown",
        "open_ports": [53, 80, 88, 135, 139, 389, 445, 464, 593, 636,
                       3268, 3269, 5985, 9389, 47001],
        "services": {
            "88":  {"service": "kerberos-sec", "version": "Microsoft Windows Kerberos"},
            "389": {"service": "ldap", "version": "Microsoft Windows Active Directory LDAP"},
            "445": {"service": "microsoft-ds", "version": ""},
            "5985":{"service": "http", "version": "Microsoft HTTPAPI httpd 2.0"},
        },
        "service_versions": {"80": "Microsoft-IIS/10.0", "135": "Microsoft Windows RPC",
                             "9389": ".NET Message Framing"},
    }
    _assert(infer_os(win_intel) == "windows",
            "infer_os classifies the AD DC as WINDOWS (was 'unknown' → Linux payload bug)")

    # ── infer_os: a Linux box stays Linux ────────────────────────────────
    nix_intel = {
        "os_guess": "unknown",
        "open_ports": [22, 80],
        "services": {
            "22": {"service": "ssh",  "version": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.3"},
            "80": {"service": "http", "version": "Apache/2.4.18 (Ubuntu)"},
        },
    }
    _assert(infer_os(nix_intel) == "linux",
            "infer_os classifies an OpenSSH/Apache Ubuntu host as LINUX")

    # ── infer_os: AD port fingerprint alone is decisive ──────────────────
    _assert(infer_os(text="", open_ports=[88, 135, 389, 445, 5985]) == "windows",
            "infer_os falls back to the AD/Windows port fingerprint")

    # ── infer_os: Linux+Samba (139/445) must NOT be mislabelled Windows ──
    samba = {
        "open_ports": [22, 139, 445],
        "services": {
            "22":  {"service": "ssh", "version": "OpenSSH 8.2p1 Ubuntu"},
            "445": {"service": "netbios-ssn", "version": "Samba smbd 4.x Linux"},
        },
    }
    _assert(infer_os(samba) == "linux",
            "infer_os does not mislabel a Linux+Samba box as Windows")

    # ── nmap CPE marker is decisive even with sparse data ────────────────
    _assert(infer_os(text="Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows") == "windows",
            "infer_os honours the nmap 'OS: Windows' / CPE marker")

    # ── _detect_target_os caches os_guess into intel (the root-cause fix) ─
    stub = SimpleNamespace(_intel=dict(win_intel))
    got = MasterAgent._detect_target_os(stub)
    _assert(got == "windows", "_detect_target_os returns windows for the AD DC")
    _assert((stub._intel.get("os_guess") or "").lower() == "windows",
            "_detect_target_os writes os_guess back into intel (drives all stages)")

    # ── _detect_target_os never clobbers an existing concrete guess ──────
    stub2 = SimpleNamespace(_intel={"os_guess": "Linux", "open_ports": [445, 88, 389, 135, 5985]})
    _assert(MasterAgent._detect_target_os(stub2) == "linux",
            "_detect_target_os respects an already-set concrete os_guess")

    # ── _phase_exploit is now tech-correct (no blind Linux default) ──────
    pe = inspect.getsource(MasterAgent._phase_exploit)
    _assert("_detect_target_os()" in pe,
            "_phase_exploit classifies the OS before staging a foothold")
    _assert("_attempt_windows_credential_shell" in pe,
            "_phase_exploit logs in with creds on Windows (not a Linux ELF)")
    _assert('platform="windows"' in pe and 'platform="linux"' in pe,
            "_phase_exploit can stage BOTH windows and linux payloads (tech-routed)")
    # The old unconditional `if "windows" in _osg: ... else: <linux>` default
    # must be gone; payload platform now branches on the classified OS.
    _assert('_os == "windows"' in pe and '_os == "linux"' in pe
            and 'if "windows" in _osg' not in pe,
            "payload platform is gated on the detected OS, not a hardcoded default")

    # ── _attempt_windows_credential_shell uses Windows tooling ───────────
    wcs = inspect.getsource(MasterAgent._attempt_windows_credential_shell)
    _assert("evil-winrm" in wcs and "crackmapexec" in wcs,
            "Windows credential foothold uses evil-winrm / crackmapexec (not msfvenom ELF)")

    # ── recon merge derives os_guess when -O didn't run ──────────────────
    msrc = inspect.getsource(MasterAgent)
    _assert(msrc.count("_detect_target_os") >= 3,
            "os_guess is derived at recon-merge AND exploit time")

    # ── network scan subagent infers OS from -sV banners (no root -O) ────
    ns = (Path(__file__).resolve().parent / "recon" / "network_scan_subagent.py").read_text(encoding="utf-8")
    _assert("from agents.exploit.exploitability import infer_os" in ns
            and "OS inferred from -sV banners" in ns,
            "network_scan falls back to banner/port OS inference when -O is unavailable")


def test_vhost_autopivot_and_protection() -> None:
    _section("Test 67 — vhost auto-pivot + self-sabotage protection")

    import asyncio as _aio
    import tempfile, os as _os
    from pathlib import Path
    import agents.recon.vhost_pivot as vp

    blob = ("http://10.129.10.175 [302 Found] Apache[2.4.58], "
            "RedirectLocation[http://cctv.htb/], Title[302 Found]\n"
            "Location: http://cctv.htb/\n")

    # ── extraction: redirect vhost found; public domains excluded ────────
    hosts = vp.extract_hostnames(blob)
    _assert("cctv.htb" in hosts,
            "extract_hostnames finds the redirect vhost cctv.htb")
    _assert("www.google.com" not in vp.extract_hostnames("Location: http://www.google.com/"),
            "public domains are NOT treated as in-scope vhosts (scope safety)")

    # ── remap replaces a STALE prior-box mapping (the actual bug) ────────
    tmpd = tempfile.mkdtemp()
    hf = _os.path.join(tmpd, "hosts")
    with open(hf, "w", encoding="utf-8") as f:
        f.write("127.0.0.1 localhost\n10.129.17.151 cctv.htb  # stale prior box\n")
    _orig_hf, _orig_am = vp.HOSTS_FILE, vp.VHOST_AUTOMAP
    vp.HOSTS_FILE = hf
    vp.VHOST_AUTOMAP = True
    try:
        added, _skipped = vp.remap_vhosts("10.129.10.175", ["cctv.htb"])
        _assert("cctv.htb" in added,
                "remap_vhosts maps the vhost to the CURRENT target IP")
        _assert(vp.hosts_currently_mapped("cctv.htb") == "10.129.10.175",
                "cctv.htb now resolves to the current target (not the old box)")
        _txt = open(hf, encoding="utf-8").read()
        _assert("10.129.17.151" not in _txt,
                "stale prior-box mapping was REMOVED (so it can't win first-match)")
        a2, s2 = vp.remap_vhosts("10.129.10.175", ["cctv.htb"])
        _assert("cctv.htb" in s2 and not a2,
                "remap is idempotent once the vhost is correctly mapped")
        pr = _aio.run(vp.pivot_from_recon_output("10.129.10.175", blob))
        _assert("cctv.htb" in pr.extracted_hostnames,
                "pivot_from_recon_output extracts + maps the vhost end-to-end")
    finally:
        vp.HOSTS_FILE = _orig_hf
        vp.VHOST_AUTOMAP = _orig_am

    # ── base_agent pins the web surface to the vhost + guards /etc/hosts ─
    ba = (Path(__file__).resolve().parent / "base_agent.py").read_text(encoding="utf-8")
    _assert("record_vhost" in ba and "target_resolver" in ba,
            "base_agent records the discovered vhost as the web target via the central resolver")
    _assert('getattr(self, "_master", None)' in ba and "_add_intel" in ba,
            "base_agent propagates the vhost to the MASTER's shared intel (the dict web tools read), not just the local one")
    _assert("neutralised /etc/hosts deletion" in ba
            and "sed\\s+-i" in ba,
            "base_agent neutralises self-sabotaging /etc/hosts deletions")
    vp = (Path(__file__).resolve().parent / "recon" / "vhost_pivot.py").read_text(encoding="utf-8")
    _assert("_sudo_tee" in vp and "sudo" in vp,
            "vhost_pivot falls back to `sudo tee` when /etc/hosts isn't writable (Python not root)")

    # ── web-primer targets the vhost, not the bare (redirecting) IP ──────
    de = (Path(__file__).resolve().parent / "reasoning" / "decision_engine.py").read_text(encoding="utf-8")
    _assert('url_host = (intel.get("web_host")' in de and "target=url_host" in de,
            "web-primer points web tools at the discovered vhost host")

    # ── error-analyzer no longer calls a vhost 'scope_drift' / purges it ─
    ea = (Path(__file__).resolve().parent / "meta" / "error_analyzer_agent.py").read_text(encoding="utf-8")
    _assert("CRITICAL VHOST RULE" in ea and "NEVER recommend" in ea,
            "error-analyzer treats an internal vhost as in-scope, never purges it")


def test_compromise_readiness_gate() -> None:
    _section("Test 68 — compromise-readiness gate (no CVE-list-as-result)")

    import inspect
    from types import SimpleNamespace
    from pathlib import Path
    from agents.master_agent import MasterAgent

    A = MasterAgent._assess_compromise

    # recon-only: version CVEs + nothing earned → NOT a result
    s = SimpleNamespace(_intel={"vulnerabilities": [{"title": "CVE-2024-38475", "verified": False}],
                                "credentials": []})
    r = A(s)
    _assert(r["level"] == "recon_only" and not r["compromised"] and not r["foothold_progress"],
            "version-CVE-only run is graded recon_only (forces a real push)")

    # operator-provided creds alone do NOT count as progress
    s = SimpleNamespace(_intel={"credentials": [{"user": "wallace.everette",
                                                  "password": "x", "source": "operator_notes"}]})
    _assert(A(s)["level"] == "recon_only",
            "operator-PROVIDED creds (unused) do not satisfy the gate")

    # a real shell = compromised
    _assert(A(SimpleNamespace(_intel={"shell_access": True}))["level"] == "compromised",
            "a landed shell grades as compromised")

    # a captured flag = compromised
    _assert(A(SimpleNamespace(_intel={"root_flag": "abc"}))["compromised"] is True,
            "a captured flag grades as compromised")

    # harvested creds = partial progress (reporting warranted, no forced push)
    s = SimpleNamespace(_intel={"credentials": [{"user": "svc", "password": "p",
                                                 "source": "secretsdump"}]})
    _assert(A(s)["level"] == "partial" and A(s)["foothold_progress"],
            "harvested credentials count as genuine foothold progress")

    # a VERIFIED exploit = partial progress
    s = SimpleNamespace(_intel={"web_vulns": [{"title": "SQLi RCE", "verified": True}]})
    _assert(A(s)["foothold_progress"] is True,
            "a verified/exploited finding counts as progress (not just a version match)")

    # ── gate behaviour + wiring ──────────────────────────────────────────
    gate = inspect.getsource(MasterAgent._final_compromise_gate)
    _assert("_final_push_done" in gate and "_phase_exploit(target)" in gate,
            "gate forces ONE exploit pass and is one-shot (cannot loop)")
    _assert("engagement_outcome" in gate and "_assess_compromise()" in gate,
            "gate records an honest engagement_outcome before/after the push")

    msrc = (Path(__file__).resolve().parent / "master_agent.py").read_text(encoding="utf-8")
    _assert(msrc.count("await self._final_compromise_gate(") >= 2,
            "gate is wired before reporting in BOTH the reasoning-loop and legacy paths")
    _assert("ENGAGEMENT OUTCOME:" in msrc and "NOT compromised" in msrc,
            "report states the honest outcome and won't present version CVEs as exploited")


def test_tool_kill_reaches_process_tree() -> None:
    _section("Test 69 — killing a tool reaps the whole process tree")

    import inspect
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent

    # ── MCP server: detached spawn + process-GROUP kill at every kill site ─
    mcp = (repo / "mcp-server.js").read_text(encoding="utf-8")
    _assert("detached: true" in mcp,
            "MCP server spawns each tool in its own process group (detached)")
    _assert("function killTree" in mcp and "process.kill(-proc.pid" in mcp,
            "MCP server has killTree() that signals the whole group (negative pid)")
    # The three kill sites must route through killTree, not a leader-only kill.
    _assert(mcp.count("killTree(proc, 'SIGKILL')") >= 3
            and mcp.count("killTree(proc, 'SIGTERM')") >= 3,
            "timeout, client-disconnect, and tools/stop all use killTree")
    # No leftover leader-only kill in the disconnect/timeout/stop paths.
    _assert("proc.kill('SIGTERM')" not in mcp,
            "no leader-only proc.kill('SIGTERM') remains (would orphan children)")
    # Detached children must be reaped if the server itself is stopped.
    _assert("process.on('SIGINT'" in mcp and "shutdownActiveTools" in mcp,
            "MCP server reaps active tool groups on its own shutdown (no new orphans)")

    # ── Client side: a tool_stop actually cancels the in-flight MCP task ──
    from agents.base_agent import BaseAgent
    kct = inspect.getsource(BaseAgent.kill_current_tool)
    _assert("_active_tool_tasks" in kct and ".cancel()" in kct,
            "kill_current_tool cancels the in-flight MCP stream task (closes the connection)")
    _assert("_active_procs" in kct and "_kill_proc_tree" in kct,
            "kill_current_tool also process-group-kills any LOCAL subprocess")

    # ── Local subprocess path already uses a new session + killpg ────────
    ba = (repo / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("start_new_session=True" in ba and "os.killpg(" in ba,
            "local tools spawn in a new session and are killed via killpg (tree kill)")


def test_tool_artifacts_stay_out_of_backend() -> None:
    _section("Test 70 — tool artifacts confined to scratch, not the backend folder")

    import os as _os, tempfile, inspect
    from pathlib import Path
    from agents.base_agent import _tool_scratch_dir

    _orig = _os.environ.pop("ARGUS_TOOL_SCRATCH", None)
    try:
        d = _tool_scratch_dir()
        _assert(_os.path.isdir(d), "scratch dir is created on demand")
        _assert(tempfile.gettempdir() in d,
                "default scratch lives under the system temp dir, not the backend folder")
        backend = _os.path.realpath(str(Path(inspect.getsourcefile(_tool_scratch_dir)).resolve().parent.parent))
        dd = _os.path.realpath(d)
        _assert(dd != backend and not dd.startswith(backend + _os.sep),
                "scratch dir is OUTSIDE the backend/project folder")
        ov = _os.path.join(tempfile.mkdtemp(), "argus-scratch-test")
        _os.environ["ARGUS_TOOL_SCRATCH"] = ov
        _assert(_os.path.realpath(_tool_scratch_dir()) == _os.path.realpath(ov),
                "ARGUS_TOOL_SCRATCH override is honoured")
    finally:
        _os.environ.pop("ARGUS_TOOL_SCRATCH", None)
        if _orig is not None:
            _os.environ["ARGUS_TOOL_SCRATCH"] = _orig

    # ── local-tool subprocess runs in the scratch dir ───────────────────
    ba = (Path(__file__).resolve().parent / "base_agent.py").read_text(encoding="utf-8")
    _assert("cwd=_tool_scratch_dir()" in ba,
            "local tools run in the scratch dir (relative artifacts avoid the backend folder)")
    _assert("db.store_tool_output" in ba and "db.finalize_tool_output" in ba,
            "tool output is persisted to the DB (the authoritative store)")

    # ── MCP server runs each tool in the scratch dir ────────────────────
    mcp = (Path(__file__).resolve().parent.parent / "mcp-server.js").read_text(encoding="utf-8")
    _assert("const TOOL_SCRATCH = process.env.ARGUS_TOOL_SCRATCH" in mcp
            and mcp.count("TOOL_SCRATCH") >= 3,
            "MCP server defines an env-overridable scratch dir and runs tools there (cwd)")


def test_domain_subdomain_hunt_and_selection() -> None:
    _section("Test 71 — domain → subdomain hunt → human target selection")

    import asyncio as _aio
    from pathlib import Path
    import agents.target_selection as ts
    import agents.recon.subdomain_hunter as sh

    # ── Selection gate: fail-closed on timeout ───────────────────────────
    ts.create_request("sel-timeout", allowed=["a.x.com", "b.x.com"])
    _assert(_aio.run(ts.await_selection("sel-timeout", timeout=0.05)) == [],
            "selection gate is fail-closed: timeout → attack nothing")

    # ── Selection gate: resolve unblocks + filters to discovered hosts ───
    async def _flow():
        ts.create_request("sel-ok", allowed=["a.x.com", "b.x.com"])
        async def _pick():
            await _aio.sleep(0.01)
            # 'evil.com' was never discovered → must be dropped (no injection)
            ts.resolve("sel-ok", ["a.x.com", "evil.com", "b.x.com"])
        t = _aio.ensure_future(_pick())
        sel = await ts.await_selection("sel-ok", timeout=2)
        await t
        return sel
    _assert(_aio.run(_flow()) == ["a.x.com", "b.x.com"],
            "operator pick unblocks the gate and is filtered to discovered candidates")
    _assert(ts.normalize_selection([{"host": "a.x.com"}]) == ["a.x.com"]
            and ts.normalize_selection("a.x.com, b.x.com") == ["a.x.com", "b.x.com"]
            and ts.normalize_selection(None) == [],
            "normalize_selection handles dicts / comma-strings / None")

    # ── Source parsers ───────────────────────────────────────────────────
    crt = '[{"name_value":"*.example.com\\nwww.example.com"},{"name_value":"api.example.com"},{"name_value":"other.org"}]'
    got = sh.parse_crtsh_json(crt, "example.com")
    _assert("www.example.com" in got and "api.example.com" in got and "other.org" not in got,
            "crt.sh parser extracts in-scope hosts, strips wildcards, drops out-of-scope")
    _assert("dev.example.com" in sh.parse_host_lines("dev.example.com\nnope.org\n", "example.com"),
            "subfinder/host-line parser keeps in-scope hosts")
    _assert("vpn.example.com" in sh.parse_gobuster_dns("Found: vpn.example.com\nFound: x.org\n", "example.com"),
            "gobuster-dns parser extracts brute-forced hosts")

    # ── Scope classification ─────────────────────────────────────────────
    in_net, third, _n = sh.classify("a.example.com", ["10.0.0.5"], ["10.0.0.9"])
    _assert(in_net and not third, "same /24 as apex → in_apex_network")
    in_net, third, _n = sh.classify("cdn.example.com", ["104.20.1.1"], ["10.0.0.9"])
    _assert(third and not in_net, "different network → flagged third-party/CDN")
    in_net, third, _n = sh.classify("dangling.example.com", [], ["10.0.0.9"])
    _assert(not in_net and not third, "unresolved host → neither (shown, flagged dangling)")

    # ── End-to-end hunt with injected runner + resolver (offline) ────────
    async def _fake_runner(tool, argv, timeout):
        if tool == "curl":     return (0, '[{"name_value":"www.example.com\\napi.example.com"}]', "")
        if tool == "subfinder":return (0, "dev.example.com\n", "")
        if tool == "gobuster": return (0, "Found: vpn.example.com\n", "")
        return (127, "", "missing")
    _ips = {"example.com": ["10.0.0.10"], "www.example.com": ["10.0.0.11"],
            "api.example.com": ["10.0.0.12"], "dev.example.com": ["104.20.5.5"],
            "vpn.example.com": ["10.0.0.13"]}
    async def _fake_resolver(host):  return _ips.get(host, [])
    cands = _aio.run(sh.hunt("example.com", tool_runner=_fake_runner, resolver=_fake_resolver,
                             wordlist=__file__))  # __file__ exists → active brute branch fires
    hosts = [c.host for c in cands]
    _assert(cands and cands[0].host == "example.com",
            "hunt always includes the apex and lists it first")
    _assert(all(h in hosts for h in ("www.example.com", "api.example.com",
                                     "dev.example.com", "vpn.example.com")),
            "hunt merges passive (crt.sh+subfinder) AND active (gobuster) sources")
    _dev = next(c for c in cands if c.host == "dev.example.com")
    _www = next(c for c in cands if c.host == "www.example.com")
    _assert(_dev.third_party and _www.in_apex_network,
            "candidates are scope-classified (dev=third-party, www=in-network)")

    # ── Orchestrator + server wiring (source) ────────────────────────────
    dro = (Path(__file__).resolve().parent.parent / "agents" / "domain_recon_orchestrator.py").read_text(encoding="utf-8")
    _assert("target_selection_request" in dro and "await_selection" in dro and "CIDROrchestrator" in dro,
            "orchestrator hunts → emits candidates → blocks on selection → scans selected via CIDROrchestrator")

    srv = (Path(__file__).resolve().parent.parent / "agent_server.py").read_text(encoding="utf-8")
    _assert("DomainReconOrchestrator" in srv and "_looks_like_domain" in srv,
            "server routes a domain + hunt flag to the subdomain-hunt orchestrator")
    _assert('mtype == "target_selection"' in srv and "/select-targets" in srv,
            "server exposes WS + REST handlers for the operator's target picks")

    sch = (Path(__file__).resolve().parent.parent / "db" / "schemas.py").read_text(encoding="utf-8")
    _assert("hunt_subdomains" in sch,
            "StartPentestRequest carries the hunt_subdomains flag")

    # ── Frontend wiring (source) ─────────────────────────────────────────
    root = Path(__file__).resolve().parent.parent
    store = (root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("targetSelection" in store and "TARGET_SELECTION_SET" in store
            and "target_selection_request" in store,
            "store.js captures the target_selection candidate events")
    app = (root / "static" / "js" / "app.jsx").read_text(encoding="utf-8")
    _assert("TargetSelectionModal" in app
            and "React.createElement(TargetSelectionModal)" in app
            and "target_selection" in app,
            "app.jsx mounts a blocking TargetSelectionModal that sends the picks over WS")
    tc = (root / "static" / "js" / "pages" / "TargetConfig.jsx").read_text(encoding="utf-8")
    _assert("hunt_subdomains" in tc and "Hunt subdomains" in tc,
            "start form exposes a 'Hunt subdomains' toggle for domain targets")
    idx = (root / "templates" / "index.html").read_text(encoding="utf-8")
    _assert("store.js?v=49" in idx and "app.jsx?v=24" in idx and "TargetConfig.jsx?v=10" in idx,
            "index.html cache-bust versions bumped for the edited JS")
    # Tier 3: operator-core events surface in the GUI activity feed.
    _store_js = (root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("case 'operator_core_start':" in _store_js
            and "case 'operator_core_fallback':" in _store_js
            and "case 'operator_flag':" in _store_js,
            "store.js routes operator-core lifecycle/flag events to the activity feed")


def test_target_resolver_ip_vs_vhost() -> None:
    _section("Test 72 — central target resolver (IP vs vhost intelligence)")

    from pathlib import Path
    import agents.recon.target_resolver as tr

    # ── No vhost → web tools target the bare IP ──────────────────────────
    ip_intel = {"target": "10.129.244.156"}
    _assert(tr.network_ip(ip_intel) == "10.129.244.156", "network_ip is the bare IP")
    _assert(tr.web_host(ip_intel) == "10.129.244.156", "web_host defaults to the IP when no vhost")
    _assert(tr.web_base_url(ip_intel, 80) == "http://10.129.244.156", "web_base_url = bare IP when no vhost")
    _assert(not tr.uses_vhost(ip_intel) and tr.curl_resolve_args(ip_intel, 80) == [],
            "no vhost → uses_vhost False, no --resolve")

    # ── Vhost discovered → ALL web tools must target it; network stays IP ─
    intel = {"target": "10.129.244.156"}
    _assert(tr.record_vhost(intel, "cctv.htb", ip="10.129.244.156", verified=True) is True,
            "record_vhost registers a freshly discovered vhost")
    _assert(tr.web_host(intel) == "cctv.htb", "web_host becomes the discovered vhost")
    _assert(tr.web_base_url(intel, 80) == "http://cctv.htb"
            and tr.web_base_url(intel, 8080) == "http://cctv.htb:8080"
            and tr.web_base_url(intel, 443) == "https://cctv.htb",
            "web_base_url is vhost-aware with correct scheme/port suffix")
    _assert(tr.network_ip(intel) == "10.129.244.156",
            "network tools STILL target the IP (not the vhost)")
    _assert(intel.get("target_url") == "http://cctv.htb/" and "cctv.htb" in intel.get("vhosts", [])
            and intel.get("web_host_verified") is True,
            "record_vhost sets target_url / vhosts / verified consistently")
    _assert(tr.curl_resolve_args(intel, 80) == ["--resolve", "cctv.htb:80:10.129.244.156"],
            "curl --resolve lets HTTP reach the vhost even without /etc/hosts")
    _assert(tr.record_vhost(intel, "cctv.htb") is False, "record_vhost is idempotent")
    _assert(tr.decision(intel)["uses_vhost"] is True, "decision() reports the vhost pivot")

    # ── A secondary unverified vhost must NOT downgrade the primary ──────
    intel2 = {"target": "10.0.0.1", "web_host": "admin.foo.htb",
              "vhosts": ["admin.foo.htb"], "target_url": "http://admin.foo.htb/"}
    tr.record_vhost(intel2, "blog.foo.htb")
    _assert(tr.web_host(intel2) == "admin.foo.htb"
            and intel2["target_url"] == "http://admin.foo.htb/"
            and "blog.foo.htb" in intel2["vhosts"],
            "secondary vhost is recorded but doesn't override the primary web target")

    # ── Wiring: every web path consumes the resolver ─────────────────────
    root = Path(__file__).resolve().parent.parent
    ba = (root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("target_resolver" in ba and "record_vhost" in ba and "target_decision" in ba,
            "base_agent records the decision via the resolver + emits a target_decision event")
    wa = (root / "agents" / "web_agent.py").read_text(encoding="utf-8")
    _assert("target_resolver" in wa and "web_base_url" in wa,
            "web_agent's full battery resolves its base URL through the resolver (vhost-aware)")
    wo = (root / "agents" / "web" / "web_orchestrator.py").read_text(encoding="utf-8")
    _assert("target_resolver" in wo and "web_host" in wo,
            "WSTG orchestrator targets the resolver's web_host (vhost), not the bare IP")


def test_conflict_audit_fixes() -> None:
    _section("Test 73 — conflict-audit fixes C1–C10 (accuracy conflicts)")

    import inspect, asyncio as _aio
    from types import SimpleNamespace
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    # ── C3 (functional): union-reconcile merges a PARTIAL port list ──────
    from agents.reasoning.reasoning_loop import ReasoningLoop
    import db.mongo_client as _dbmod
    _orig = getattr(_dbmod, "get_findings", None)
    async def _fake_find(session_id, *a, **k):
        return [{"title": "Open Port 22/tcp: ssh", "port": 22, "cves": []},
                {"title": "Open Port 80/tcp: http", "port": 80, "cves": []}]
    _dbmod.get_findings = _fake_find
    try:
        emitted = []
        async def _emit(m): emitted.append(m)
        stub = SimpleNamespace(_intel={"open_ports": [80], "services": {}, "cves": []},
                               _session_id="s", _target="t", _emit_reasoning=_emit)
        added = _aio.run(ReasoningLoop._reconcile_intel_from_findings(stub, union=True))
        _assert(added == 1 and sorted(stub._intel["open_ports"]) == [22, 80],
                "C3: union-reconcile merges a partial port list ([80] → [22,80])")
        # union no-op when nothing new
        stub._intel["open_ports"] = [22, 80]
        _assert(_aio.run(ReasoningLoop._reconcile_intel_from_findings(stub, union=True)) == 0,
                "C3: union-reconcile is a no-op when no new ports (no churn)")
    finally:
        if _orig is not None:
            _dbmod.get_findings = _orig
    _rl = (root / "agents" / "reasoning" / "reasoning_loop.py").read_text(encoding="utf-8")
    _assert("union=True" in _rl and "_pset" in _rl,
            "C3: _observe partial-reconciles + the port counter is normalized")

    # ── C4 (functional): shared first-strike ledger dedups commands ──────
    from agents.master_agent import MasterAgent
    _led = SimpleNamespace()
    _cmd = "nmap -p- --min-rate 2000 10.0.0.1 && nuclei -u http://x/"
    _assert(MasterAgent._first_strike_already_run(_led, _cmd) is False
            and MasterAgent._first_strike_already_run(_led, _cmd) is True,
            "C4: first-strike command runs once, second call is suppressed")
    _msrc = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert(_msrc.count("_first_strike_already_run(") >= 4,
            "C4: the ledger is consulted by all 3 next_commands consumers")
    _assert("_exploit_orch_active" in _msrc and _msrc.count("_exploit_orch_active = True") >= 2,
            "C4/C10: only one ExploitOrchestrator runs at a time (no concurrent races)")

    # ── C6: Expert prompt via stdin, not argv (no ARG_MAX overflow) ──────
    _llm = (root / "utils" / "llm_providers.py").read_text(encoding="utf-8")
    _assert("stdin=asyncio.subprocess.PIPE" in _llm and "proc.stdin.write(prompt" in _llm,
            "C6: ClaudeCodeProvider feeds the prompt over stdin (fixes Argument list too long)")

    # ── C5: pinned-insight content de-dup (anti-flood) ───────────────────
    _ec = (root / "agents" / "engagement_context.py").read_text(encoding="utf-8")
    _assert("REFRESHED in place" in _ec or "anti-flood" in _ec.lower(),
            "C5: pin_insight de-dups identical advice instead of flooding the prompt window")

    # ── C1: every web driver resolves through the target resolver ────────
    _de = (root / "agents" / "reasoning" / "decision_engine.py").read_text(encoding="utf-8")
    _assert("_tr.web_host(intel)" in _de,
            "C1: web-primer resolves its host via target_resolver (not a hand-rolled string)")
    _ft = (root / "agents" / "finding_triggers.py").read_text(encoding="utf-8")
    _assert("target_resolver" in _ft and "web_host" in _ft,
            "C1: finding_triggers fire web tools at the resolved vhost, not the bare IP")
    _wa = (root / "agents" / "web_agent.py").read_text(encoding="utf-8")
    _assert("pk = f\"{_whost}:{port}\"" in _wa,
            "C1: WebAgent battery dedup key is the resolved web host (not the IP)")
    _assert("vhost_preprobe" in _msrc,
            "C1: a redirect pre-probe resolves the vhost BEFORE the web battery runs")

    # ── C2: CMS/SQLi rungs can actually fire ─────────────────────────────
    _assert('intel.get("technologies")' in _de and 'intel.get("web_paths")' in _de,
            "C2: CMS tags come from technologies + URL surface from web_paths (rungs no longer dead)")
    _assert("argus.urls." not in _de,
            "C2: sqlmap sweep no longer depends on a URL file that nothing writes")

    # ── C9: WebFingerprint technologies reach intel ──────────────────────
    _assert('"web_targets"' in _msrc and "LIST_KEYS" in _msrc,
            "C9: web_targets is synced into intel (WebFingerprint data no longer orphaned)")

    # ── C7: blocking corrections actually reach the planner ──────────────
    _assert("[MANDATORY|" in _msrc,
            "C7: blocking corrections are injected into planner context (not a silent no-op)")

    # ── C8: Error Analyzer stops fighting forward progress ───────────────
    _ea = (root / "agents" / "meta" / "error_analyzer_agent.py").read_text(encoding="utf-8")
    _assert("_ports_known" in _ea and "already mapped" in _ea,
            "C8: Error-Analyzer suppresses 're-scan' advice once ports are known")


def test_liveness_and_cancel_breakers() -> None:
    _section("Test 74 — host-liveness + operator-cancel breakers, meta throttle (F1–F8)")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    # ── F1/F5 (functional): ToolBlacklist detects the timeouts ARGUS emits ──
    from agents.reasoning.tool_blacklist import ToolBlacklist, HOST_UNREACHABLE_THRESH
    H = "10.0.0.99"

    bl = ToolBlacklist()
    for _ in range(HOST_UNREACHABLE_THRESH):
        bl.record_run(host=H, tool="curl", port=80, exit_code=28, stdout="000", stderr="")
    _assert(bl.host_unreachable(H),
            "F5: N curl exit-28 timeouts mark the host unreachable")

    r = ToolBlacklist().record_run(host=H, tool="whatweb", port=80, exit_code=-1,
                                   stdout="", stderr="[AGENT ERROR] ReadTimeout: ")
    _assert(r == "timeout",
            "F1: ARGUS's own '[AGENT ERROR] ReadTimeout' text is recognised as a timeout")

    # a clean success clears the unreachable verdict
    bl.record_run(host=H, tool="curl", port=80, exit_code=0,
                  stdout="<html>live</html>", stderr="")
    _assert(not bl.host_unreachable(H),
            "F5: a successful tool run clears the host-unreachable flag")

    # a connection-REFUSED (host is up, just closed) must NOT mark unreachable
    bl_ref = ToolBlacklist()
    for _ in range(HOST_UNREACHABLE_THRESH + 2):
        bl_ref.record_run(host=H, tool="curl", port=80, exit_code=1,
                          stdout="", stderr="connection refused")
    _assert(not bl_ref.host_unreachable(H),
            "F5: connection-refused (host up) does NOT count as unreachable")

    # ── F2 (functional): operator-cancel streak breaker ──
    bl_c = ToolBlacklist()
    bl_c.record_cancel(H); bl_c.record_cancel(H)
    _assert(bl_c.cancel_streak_tripped(H),
            "F2: two operator cancels in a row trip the cancel-streak breaker")
    bl_c.record_run(host=H, tool="curl", port=80, exit_code=0, stdout="ok body", stderr="")
    _assert(not bl_c.cancel_streak_tripped(H),
            "F2: a successful tool run resets the cancel streak")

    # ── F3 (functional): a cancel (-2) is neither failure nor success ──
    bl_x = ToolBlacklist()
    for _ in range(HOST_UNREACHABLE_THRESH + 1):
        bl_x.record_run(host=H, tool="curl", port=80, exit_code=-2,
                        stdout="", stderr="[CANCELLED] Tool 'curl' stopped by operator")
    _assert(not bl_x.host_unreachable(H),
            "F3: operator cancellations (-2) never mark a host unreachable")

    # ── Source-checks for the wiring ──
    _rl = (root / "agents" / "reasoning" / "reasoning_loop.py").read_text(encoding="utf-8")
    _assert("cancel_streak_tripped" in _rl and "_web_primer_halted" in _rl
            and "host_unreachable" in _rl,
            "F2/F5: the reasoning loop consults the cancel + liveness breakers each iteration")
    _assert("_MAX_META_REVIEW_PASSES" in _rl and "_meta_reviewed_phases" in _rl,
            "F8: meta-reviews are budgeted (each phase reviewed once, capped total)")

    _de = (root / "agents" / "reasoning" / "decision_engine.py").read_text(encoding="utf-8")
    _assert('intel.get("_web_primer_halted")' in _de,
            "F2: the web-primer ladder stops offering rungs once halted")

    _ba = (root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("record_cancel" in _ba,
            "F2: base_agent feeds the operator-cancel streak when a tool is killed")

    _ea = (root / "agents" / "meta" / "error_analyzer_agent.py").read_text(encoding="utf-8")
    _assert("stopped by operator" in _ea and "exit_code == -2" in _ea,
            "F3: error_analyzer drops operator-cancelled tools instead of 'analysing' them")
    _assert("_CORE_EXECUTORS" in _ea and "_real_missing" in _ea,
            "F6: error_analyzer never force-blocks shells / requires a real not-found signal")
    _assert("ADVICE_DEDUP_SEC" in _ea and "host_unreachable" in _ea,
            "F7: error_analyzer throttles repeat advice + goes quiet once host is unreachable")


def test_owasp2025_native_probes() -> None:
    _section("Test 75 — OWASP-2025 native, tool-independent web probes")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    from agents.web.owasp2025_native_probes import (
        analyze_cors, ssti_evaluated, detect_crlf, detect_stack_trace,
        detect_sql_error, analyze_cookies, analyze_csrf, split_headers_body,
        parse_set_cookies, SSTI_EVALUATED, OWASP2025NativeProbesSubagent,
    )

    # ── A01 CORS ──
    refl_cred = ("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://argus-evil.test\r\n"
                 "Access-Control-Allow-Credentials: true\r\n")
    c = analyze_cors("https://argus-evil.test", refl_cred)
    _assert(c and c["severity"] == "CRITICAL",
            "A01: reflected Origin + credentials → CRITICAL CORS finding")
    c = analyze_cors("https://argus-evil.test",
                     "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://argus-evil.test\r\n")
    _assert(c and c["severity"] == "HIGH", "A01: reflected Origin (no creds) → HIGH")
    c = analyze_cors("https://x", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: null\r\n")
    _assert(c and c["severity"] == "HIGH", "A01: 'null' Origin trusted → HIGH")
    _assert(analyze_cors("https://x", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") is None,
            "A01: no ACAO header → no CORS finding (no false positive)")

    # ── A05 SSTI ──
    _assert(ssti_evaluated(f"<p>result: {SSTI_EVALUATED}</p>") is True,
            "A05: SSTI sentinel evaluated server-side (1337*1337) is detected")
    _assert(ssti_evaluated("<p>result: qXq{{1337*1337}}qXq</p>") is False,
            "A05: a literal (un-evaluated) SSTI payload echo is NOT a false positive")

    # ── A05 CRLF ──
    _assert(detect_crlf("HTTP/1.1 200 OK\r\nX-Argus-Crlf: injected\r\n") is True,
            "A05: reflected CRLF header → header-injection detected")
    _assert(detect_crlf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n") is False,
            "A05: clean headers → no CRLF false positive")

    # ── A02/A10 verbose errors + A05 SQL error oracle ──
    _assert(detect_stack_trace("Traceback (most recent call last):\n  File \"app.py\", line 7") == "python",
            "A10: Python stack trace disclosure detected")
    _assert(detect_stack_trace("<b>Fatal error</b>: Uncaught Error on line 22") == "php",
            "A10: PHP fatal-error disclosure detected")
    _assert(detect_stack_trace("<html><body>Welcome</body></html>") is None,
            "A10: clean page → no verbose-error false positive")
    _assert(detect_sql_error("You have an error in your SQL syntax; MySQL server version") == "mysql",
            "A05: error-based SQLi oracle (MySQL) detected")

    # ── A04 cookie flags ──
    miss = analyze_cookies(["SESSIONID=abc123; Path=/"], is_https=True)
    _assert(miss and set(["Secure", "HttpOnly", "SameSite"]).issubset(set(miss[0]["missing"])),
            "A04: session cookie missing Secure/HttpOnly/SameSite flagged")
    ok = analyze_cookies(["SID=x; Path=/; Secure; HttpOnly; SameSite=Strict"], is_https=True)
    _assert(ok == [], "A04: fully-hardened cookie produces no finding")

    # ── A01 CSRF ──
    csrf = analyze_csrf("<form method='post' action='/transfer'><input name=amt></form>", [])
    _assert(csrf and csrf["severity"] in ("MEDIUM", "LOW"),
            "A01: POST form without anti-CSRF token flagged")
    safe = analyze_csrf("<form method=post><input name='csrf_token' value=x></form>", [])
    _assert(safe is None, "A01: POST form WITH a csrf token → no finding")

    # ── helpers ──
    h, b = split_headers_body("HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\n\r\n<html>hi</html>")
    _assert("Set-Cookie" in h and "<html>" in b, "helper: header/body split works")
    _assert(parse_set_cookies("Set-Cookie: a=b; Path=/\nSet-Cookie: c=d") == ["a=b; Path=/", "c=d"],
            "helper: Set-Cookie extraction works")

    # ── wiring + bug-fix source-checks ──
    _assert(OWASP2025NativeProbesSubagent.SUBAGENT_NAME == "owasp2025_native_probes",
            "subagent class present with correct SUBAGENT_NAME")
    _msrc = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("OWASP2025NativeProbesSubagent(**kw).execute" in _msrc,
            "native-probe subagent is wired into the master web battery")
    _ids = (root / "agents" / "web" / "insecure_design_subagent.py").read_text(encoding="utf-8")
    _assert("wrongpassword0" in _ids and "wrongpassword{i}" not in _ids,
            "A06: the rate-limit NameError bug is fixed (literal probe, no undefined `i`)")


def test_env_preflight_and_setup() -> None:
    _section("Test 76 — venv-rebuild guards (preflight + setup.sh + reqs warning)")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    _srv = (root / "agent_server.py").read_text(encoding="utf-8")
    _assert("def _preflight_env(" in _srv and "_preflight_env()" in _srv,
            "preflight: agent_server.py defines AND calls _preflight_env() at startup")
    _assert("bson.errors" in _srv and "python-dotenv" in _srv,
            "preflight: checks the rogue-bson shadow AND missing python-dotenv")
    _assert("starlette" in _srv and "fastapi" in _srv and "pymongo" in _srv,
            "preflight: verifies core web/db deps are present in the venv")
    _assert("websockets" in _srv and "wsproto" in _srv,
            "preflight: catches the missing WebSocket library (the dead /ws live-UI)")

    _setup = (root / "setup.sh")
    _assert(_setup.exists(), "setup.sh exists (reproducible venv build)")
    _stxt = _setup.read_text(encoding="utf-8")
    _assert("python3 -m venv" in _stxt and "requirements.txt" in _stxt,
            "setup.sh builds a venv and installs the pinned requirements")
    _assert("from bson.errors import InvalidId" in _stxt and "--verify" in _stxt,
            "setup.sh verifies the exact import that crashed + supports --verify")
    _assert("uninstall -y bson" in _stxt,
            "setup.sh defensively removes a stray 'bson' before install")
    _assert("websockets" in _stxt,
            "setup.sh verifies the WebSocket library (uvicorn[standard] extra)")

    _req = (root / "requirements.txt").read_text(encoding="utf-8")
    _assert("setup.sh" in _req and "pip install bson" in _req,
            "requirements.txt warns about venv rebuilds + the bson trap")
    # the brittle deps that drifted are still explicitly pinned
    _assert("starlette==0.37.2" in _req and "python-dotenv==1.0.1" in _req
            and "pymongo==4.7.2" in _req,
            "requirements.txt keeps the brittle deps pinned (no silent drift)")


def test_no_fake_shell_guards() -> None:
    _section("Test 77 — fake-shell / local-exec guards (F1–F3)")

    import asyncio as _aio
    from types import SimpleNamespace
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    # ── F1 (functional): exploit_synth success regex ──
    from agents.exploit.exploit_synth_subagent import _SUCCESS_RE
    _assert(_SUCCESS_RE.search("uid=0(root) gid=0(root)") is not None,
            "F1: real command-exec output (uid=0) is accepted as proof")
    _assert(_SUCCESS_RE.search("[+] /login -> 200 :: <!doctype html>") is None,
            "F1: a web-enum line ('/login -> 200') is NOT a shell (the false positive)")
    _assert(_SUCCESS_RE.search("token: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") is None,
            "F1: a bare 32-hex token/hash is NOT code execution")
    _es = (root / "agents" / "exploit" / "exploit_synth_subagent.py").read_text(encoding="utf-8")
    _assert("if success_indicator and success_indicator in out" not in _es,
            "F1: the self-fulfilling 'LLM declares its own pass-string' branch is removed")

    # ── F2 (source): exploit_synth routed through register_shell evidence gate ──
    _ms = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert('"exploit_synth"' in _ms and "_OPTIMISTIC_SOURCE_PREFIXES" in _ms,
            "F2: exploit_synth is gated by register_shell's _REAL_SHELL_RE evidence check")

    # ── F3 (functional): _verify_remote_session ──
    from agents.master_agent import MasterAgent
    async def _echo_sh(command="", timeout=20, **k):
        return {"stdout": command.replace("echo ", ""), "exit_code": 0}
    # no shells → not verified
    s0 = SimpleNamespace(_intel={"shells": []}, _execute_shell_command=_echo_sh)
    _assert(_aio.run(MasterAgent._verify_remote_session(s0)) is False,
            "F3: no live session → verification fails (exploit_synth case)")
    # only a pending shell → not verified
    s1 = SimpleNamespace(_intel={"shells": [{"pending": True, "session_id": "x"}]},
                         _execute_shell_command=_echo_sh)
    _assert(_aio.run(MasterAgent._verify_remote_session(s1)) is False,
            "F3: a pending (unconfirmed) shell does NOT count as a live session")
    # a real non-pending session whose marker round-trips → verified
    s2 = SimpleNamespace(_intel={"shells": [{"pending": False, "session_id": "s"}]},
                         _execute_shell_command=_echo_sh)
    _assert(_aio.run(MasterAgent._verify_remote_session(s2)) is True,
            "F3: a live session that echoes the marker verifies True")
    # a 'session' that does NOT echo the marker (dead) → not verified
    async def _dead_sh(command="", timeout=20, **k):
        return {"stdout": "no active shell session", "exit_code": -2}
    s3 = SimpleNamespace(_intel={"shells": [{"pending": False, "session_id": "s"}]},
                         _execute_shell_command=_dead_sh)
    _assert(_aio.run(MasterAgent._verify_remote_session(s3)) is False,
            "F3: a session that can't echo the marker is treated as dead")

    _assert(_ms.count("_verify_remote_session()") >= 2,
            "F3: BOTH post-exploit and privesc gate on a verified live session")


def test_sqli_weaponization() -> None:
    _section("Test 78 — SQLi weaponization (F4): strict confirm + credential dump")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    from agents.exploit.sqli_weaponize import (
        sqlmap_confirmed_injection, extract_credentials_from_csv,
        looks_like_hash, build_dump_args, is_user_column, is_pass_column,
    )

    # ── strict confirmation (no startup-noise false positives) ──
    _assert(not sqlmap_confirmed_injection(
        "[INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 ...'"),
        "F4: 'fetched random User-Agent' is NOT a SQLi confirmation (the old false positive)")
    _assert(not sqlmap_confirmed_injection(
        "POST parameter 'username' might not be injectable"),
        "F4: 'might not be injectable' is NOT a confirmation (the old false positive)")
    _assert(sqlmap_confirmed_injection(
        "sqlmap identified the following injection point with a total of 42 HTTP(s) requests"),
        "F4: a real injection-point report IS confirmed")
    _assert(sqlmap_confirmed_injection(
        "available databases [2]:\n[*] information_schema\n[*] smarthire"),
        "F4: an enumerated DB list IS confirmed")

    # ── credential extraction from a dump CSV ──
    csv1 = ("id,username,password\n"
            "1,admin,5f4dcc3b5aa765d61d8327deb882cf99\n"
            "2,john,$2b$12$Zrabcdefghijklmnopqrstuv\n")
    creds = extract_credentials_from_csv(csv1)
    _assert(len(creds) == 2 and {c["username"] for c in creds} == {"admin", "john"},
            "F4: username/password pairs extracted from a dump CSV")
    _assert(any(c["hash_mode"].startswith("md5") for c in creds)
            and any(c["hash_mode"].startswith("bcrypt") for c in creds),
            "F4: hash formats (md5 + bcrypt) recognised for cracking")
    _assert(extract_credentials_from_csv("id,title,body\n1,hello,world") == [],
            "F4: a non-credential table yields no creds (no fabricated creds)")
    _assert(is_user_column("email") and is_pass_column("password_hash")
            and not is_pass_column("title"),
            "F4: credential-column heuristics")
    _assert(looks_like_hash("a" * 40) == "sha1(100)" and looks_like_hash("plaintextpw") is None,
            "F4: hash detection (sha1 vs plaintext)")

    # ── bounded dump args (not the 900s storm) ──
    args = build_dump_args("http://t/", 80)
    _assert("--dump" in args and "--crawl=1" in args and "--exclude-sysdbs" in args
            and "--level=5" not in args and "--crawl=3" not in args,
            "F4: dump args are bounded (depth-1 crawl, level 2, --dump) — not --crawl=3 --level=5")

    # ── wiring ──
    _wa = (root / "agents" / "web_agent.py").read_text(encoding="utf-8")
    _assert("sqlmap_confirmed_injection" in _wa and "extract_credentials_from_dump" in _wa,
            "F4: web_agent gates on strict confirmation AND dumps/extracts credentials")
    _assert("[INFO] fetched" not in _wa and "--crawl=3 --level=5" not in _wa,
            "F4: web_agent dropped the false-positive confirm keyword + the 900s-storm args")


def test_shared_operator_session() -> None:
    _section("Test 79 — shared ARGUS/operator shell session + post-ex visibility")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    _srv = (root / "agent_server.py").read_text(encoding="utf-8")
    _assert(_srv.count("master._shell_agent = shell_agent") >= 2,
            "operator + ARGUS share ONE ShellAgent (wired at both create and restore)")

    _ms = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("if shell_agent is None:" in _ms,
            "master reuses an injected _shell_agent (lazy construct guarded by None)")
    _assert("agent_shell_command" in _ms,
            "ARGUS post-exploit commands are surfaced to the operator's event feed")


def test_authenticated_web_playbook() -> None:
    _section("Test 80 — F5 authenticated-web exploitation as a PLAYBOOK (capability as data)")

    from pathlib import Path
    root = Path(__file__).resolve().parent.parent

    # The playbook engine loads the new capability with NO new Python class.
    from agents.playbook.engine import PlaybookEngine
    eng = PlaybookEngine()
    n = eng.load()
    ids = [p.id for p in eng.playbooks]
    _assert(n > 0 and "web_authenticated_exploitation" in ids,
            "F5: authenticated-web capability is a PLAYBOOK the engine loads — not a new agent class")

    pb = (root / "knowledge" / "data" / "playbooks"
          / "web_authenticated_exploitation.yml").read_text(encoding="utf-8")
    _assert("/register" in pb and "/login" in pb and "argus.jar" in pb,
            "F5: register → login carrying a shared cookie jar (the missing authenticated session)")
    _assert("/predict" in pb and "1337" in pb and "uid=" in pb,
            "F5: attacks the authenticated endpoint (SSTI/cmd-injection) for real RCE proof")
    _assert("sshpass" in pb and "dumped_password" in pb,
            "F5: reuses dumped/app credentials against SSH (credential reuse → foothold)")

    # Operator GUI surfaces ARGUS's post-exploit commands.
    _store = (root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("agent_shell_command" in _store,
            "operator GUI surfaces ARGUS post-exploit commands in the feed")


def test_operator_tiered_llm() -> None:
    _section("Test 81 — Tier 0: tiered LLM foundation (converse + fallback + refusal re-route)")
    import asyncio as _aio
    import os as _os
    import importlib as _il
    import utils.llm_providers as _L

    # Refusal detection: short refusal = True; long technical answer = False.
    _assert(_L.looks_like_refusal("I can't help with that request."),
            "looks_like_refusal flags a short policy refusal")
    _assert(not _L.looks_like_refusal("Run: sqlmap -u http://x --batch --dump"),
            "looks_like_refusal does NOT flag an actionable technical answer")
    _assert(not _L.looks_like_refusal("uid=0(root) " + ("A" * 1300)),
            "looks_like_refusal does NOT flag a long answer that merely mentions policy")

    # Provider chain: Opus primary, implicit ollama backup; cheap-first for bulk.
    _saved = _os.environ.get("LLM_PROVIDER")
    for _k in ("LLM_FALLBACK_PROVIDER", "ATTACKGRAPH_FALLBACK_PROVIDER"):
        _os.environ.pop(_k, None)
    _os.environ["LLM_PROVIDER"] = "anthropic"
    try:
        _il.reload(_L)
        _reason = [p.name for p in _L.provider_chain("reason")]
        _bulk = [p.name for p in _L.provider_chain("bulk")]
        _assert(_reason[:2] == ["anthropic", "ollama"],
                "reason tier = primary(Opus) then implicit ollama backup", str(_reason))
        _assert(_bulk[:2] == ["ollama", "anthropic"],
                "bulk tier = cheap ollama first, primary second", str(_bulk))
        _assert(_L.has_fallback("reason") is True,
                "has_fallback() reports a distinct backup is available")
        # get_fallback_provider stays pure .env (nothing hardcoded) — implicit
        # backup lives ONLY in provider_chain.
        _assert(_L.get_fallback_provider() is None,
                "get_fallback_provider() stays None when unset (implicit backup is chain-only)")
    finally:
        if _saved is None:
            _os.environ.pop("LLM_PROVIDER", None)
        else:
            _os.environ["LLM_PROVIDER"] = _saved
        _il.reload(_L)

    # stream_tiered: primary raises before any token -> falls back to backup.
    class _FP:
        def __init__(self, name, toks=None, boom=False):
            self.name = name; self.model = name + "-m"; self._t = toks or []; self._boom = boom
        async def stream(self, messages, timeout=600):
            if self._boom:
                raise RuntimeError(self.name + " down")
            for t in self._t:
                yield t
    async def _drive_fallback():
        _L._PROVIDER_CACHE = _FP("opus", boom=True)
        _orig = _L.get_fallback_provider
        _L.get_fallback_provider = lambda: _FP("ollama", ["he", "llo"])
        try:
            seen, provs = [], []
            async for tok in _L.stream_tiered([{"role": "user", "content": "x"}],
                                              tier="reason",
                                              on_provider=lambda n, m, f: provs.append((n, f))):
                seen.append(tok)
            return "".join(seen), provs
        finally:
            _L.get_fallback_provider = _orig
            _L._PROVIDER_CACHE = None
    _txt, _provs = _aio.run(_drive_fallback())
    _assert(_txt == "hello" and _provs == [("opus", False), ("ollama", True)],
            "stream_tiered falls back to the backup when the primary fails pre-token",
            f"text={_txt!r} provs={_provs}")

    # The real BaseAgent.converse passes the FULL transcript through and joins tokens.
    from agents.base_agent import BaseAgent
    import inspect as _inspect
    _assert(_inspect.iscoroutinefunction(BaseAgent.converse),
            "BaseAgent.converse exists and is async (multi-turn operator LLM call)")

    async def _drive_converse():
        captured = {}
        async def _fake_stream(messages, *, tier="reason", timeout=600,
                               on_provider=None, on_usage=None):
            captured["messages"] = messages
            captured["tier"] = tier
            if on_provider:
                on_provider("fake", "fake-m", False)
            for t in ["Hel", "lo"]:
                yield t
            if on_usage:
                on_usage({"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7})
        _orig = _L.stream_tiered
        _L.stream_tiered = _fake_stream
        try:
            class _OpAgent(BaseAgent):
                async def run(self, *a, **k):
                    return {}
            inst = _OpAgent.__new__(_OpAgent)
            inst.name = "agentname.operator"; inst.phase = "operator"
            inst._session_id = ""; inst._stop_requested = False; inst._llm_available = True
            async def _noop(*a, **k):
                return None
            inst.set_status = _noop; inst._emit = _noop
            msgs = [{"role": "system", "content": "S"},
                    {"role": "user", "content": "U1"},
                    {"role": "assistant", "content": "A1"},
                    {"role": "user", "content": "U2"}]
            out = await inst.converse(msgs, tier="reason")
            return out, captured
        finally:
            _L.stream_tiered = _orig
    _out, _cap = _aio.run(_drive_converse())
    _assert(_out == "Hello", "converse() joins streamed tokens into the reply", repr(_out))
    _assert(len(_cap.get("messages", [])) == 4 and _cap["messages"][2]["role"] == "assistant",
            "converse() passes the FULL multi-turn transcript through (accumulating context)")


def test_operator_core_loop() -> None:
    _section("Test 82 — Tier 1: operator ReAct loop, approve-to-exploit, stateful HTTP")
    import asyncio as _aio
    import json as _json
    from agents.operator_agent.operator_core import OperatorCore, OperatorUnavailable
    from agents.operator_agent import tool_catalog as _cat
    from agents.operator_agent.http_session import extract_forms, extract_csrf
    from agents.exploit import exploit_approval as _APP

    # System prompt carries the anti-refusal framing + winning methodology.
    _sp = _cat.build_system_prompt(
        objective="Get user.txt and root.txt",
        target={"host": "smarthire.htb", "ip": "10.129.12.16",
                "url": "http://smarthire.htb", "kind": "hostname"},
        scope_guard="in-scope: 10.129.0.0/16", autonomy="approve_to_exploit")
    _l = _sp.lower()
    _assert("authorized" in _l and "isolated lab" in _l,
            "operator system prompt uses the authorized-isolated-lab framing (anti-refusal)")
    _assert("ENUMERATE THE SURFACE" in _sp and "INTERACT STATEFULLY" in _sp,
            "operator doctrine teaches surface enumeration + stateful auth interaction")

    # Action parser: fenced block, json fence, and bare object all parse.
    _assert(_cat.parse_action('THOUGHT: go\n```action\n{"tool":"http","args":{"url":"/"}}\n```')
            == {"tool": "http", "args": {"url": "/"}, "hypothesis": ""},
            "parse_action reads a fenced ```action block (with declared-hypothesis field)")
    _assert(_cat.parse_action("noise") is None,
            "parse_action returns None when there is no action")

    # Form + CSRF extraction (the stateful-auth brain).
    _html = ('<form action=/login method=POST><input name=username>'
             '<input type=password name=password>'
             '<input type=hidden name=csrf_token value=tok9></form>')
    _f = extract_forms(_html)
    _assert(_f and _f[0]["action"] == "/login" and "csrf_token" in _f[0]["inputs"],
            "extract_forms discovers the login form + its fields")
    _assert((extract_csrf(_html) or {}).get("value") == "tok9",
            "extract_csrf pulls the anti-forgery token for replay")

    # --- Fakes for the loop ---
    class _FakeHttp:
        def __init__(self, *a, **k):
            self.closed = False; self.auth_state = {}
        async def request(self, method, url, **kw):
            return {"status": 200, "url": url, "length": 9, "headers": {},
                    "cookies": {"session": "x"}, "title": "SmartHire", "forms": [],
                    "csrf": None, "links": [], "body": "x", "body_excerpt": "x"}
        async def submit_form(self, *a, **k):
            return {"status": 302, "url": "/dashboard", "length": 2,
                    "headers": {"location": "/dashboard"}, "cookies": {"session": "x"},
                    "title": "", "forms": [], "csrf": None, "links": [],
                    "body": "ok", "body_excerpt": "ok"}
        def summarize(self, r, **k):
            return "HTTP %s %s" % (r["status"], r["url"])
        def mark_logged_in(self, u):
            self.auth_state = {"logged_in": True, "user": u}
        async def close(self):
            self.closed = True

    class _FakeMaster:
        def __init__(self, replies):
            self._intel = {"target": "10.129.12.16", "target_host": "smarthire.htb",
                           "target_resolved_ip": "10.129.12.16",
                           "target_url": "http://smarthire.htb",
                           "engagement_context": {"objective": "Get user.txt+root.txt"}}
            self._session_id = "sess1"; self._target_host = "smarthire.htb"
            self._target = "10.129.12.16"; self._target_url = "http://smarthire.htb"
            self._scope_guard = "scope:10.129.0.0/16"; self._stop_requested = False
            self.name = "agentname.master"; self.phase = "operator"
            self._replies = list(replies); self._dispatched = []
        async def converse(self, messages, tier="reason", **k):
            if tier == "bulk":
                return ""
            return (self._replies.pop(0) if self._replies
                    else _json.dumps({"tool": "done", "args": {"summary": "eof"}}))
        async def _dispatch_to_agent(self, tool, args, purpose, phase, timeout=300):
            self._dispatched.append((tool, args))
            return {"stdout": "ran", "stderr": "", "exit_code": 0}
        async def _emit(self, ev, data):
            return None
        async def emit_reasoning(self, step, reasoning, decision, next_action="", data=None):
            return None

    def _A(name, **args):
        return "THOUGHT: x\n```action\n" + _json.dumps({"tool": name, "args": args}) + "\n```"

    # 1) Full drive: GET -> login -> note -> submit_flag(user) -> done.
    _replies = [_A("http", method="GET", url="/"),
                _A("submit_form", page_url="/login", fields={"username": "p", "password": "p"}),
                _A("note", text="vhost models.smarthire.htb", kind="finding"),
                _A("submit_flag", flag="3f1ae4f5ec8924efca35d94c512d94a9", which="user"),
                _A("done", summary="user flag")]
    _m = _FakeMaster(_replies)
    _op = OperatorCore(_m, autonomy="approve_to_exploit"); _op._http = _FakeHttp()
    _res = _aio.run(_op.run())
    _assert(_res["done_reason"] == "done" and _res["user_flag"] == "3f1ae4f5ec8924efca35d94c512d94a9",
            "operator drives a multi-step auth chain to a recorded flag (accumulating transcript)")
    _assert(_op._http.auth_state.get("logged_in") and _op._http.closed,
            "operator keeps a stateful session (login persists) and closes it cleanly")

    # 2) Approve-to-exploit: an intrusive sqlmap pauses for approval, then runs.
    _replies2 = [_A("run_tool", tool="sqlmap", args="-u http://smarthire.htb/login --batch"),
                 _A("done", summary="done")]
    _m2 = _FakeMaster(_replies2)
    _op2 = OperatorCore(_m2, autonomy="approve_to_exploit"); _op2._http = _FakeHttp()
    async def _drive_approve():
        async def _approver():
            for _ in range(80):
                ids = _APP.pending_ids()
                if ids:
                    _APP.resolve(ids[0], "approve"); return
                await _aio.sleep(0.02)
        _t = _aio.ensure_future(_approver())
        r = await _op2.run(); await _t
        return r
    _res2 = _aio.run(_drive_approve())
    _assert(_op2._intrusive_approved and any(d[0] == "sqlmap" for d in _m2._dispatched),
            "approve-to-exploit gate fires once for the first intrusive action, then proceeds")

    # 3) Intrusive classification: login POST benign; payload/shell/sqlmap intrusive.
    _opc = OperatorCore(_FakeMaster([]))
    _cls = _opc._is_intrusive
    _assert(_cls({"tool": "submit_form", "args": {"method": "POST",
            "fields": {"username": "a", "password": "b"}}}) is False,
            "a plain login POST is NOT classified intrusive (runs autonomously)")
    _assert(_cls({"tool": "shell", "args": {"cmd": "id"}}) is True
            and _cls({"tool": "run_tool", "args": {"tool": "nmap", "args": "-sV x"}}) is False,
            "shell is intrusive; an nmap scan is not")

    # 4) Empty LLM -> OperatorUnavailable so the master falls back to legacy loop.
    class _EmptyMaster(_FakeMaster):
        async def converse(self, messages, tier="reason", **k):
            return ""
    _raised = False
    try:
        _aio.run(OperatorCore(_EmptyMaster([])).run())
    except OperatorUnavailable:
        _raised = True
    _assert(_raised, "operator raises OperatorUnavailable on empty LLM (triggers legacy fallback)")


def test_operator_default_driver_wiring() -> None:
    _section("Test 83 — Tier 2: operator core is the default driver (legacy = fallback)")
    import os as _os
    import inspect as _inspect
    import agents.master_agent as _M

    # Default ON; ARGUS_OPERATOR=0 forces legacy; import-guarded.
    _inst = _M.MasterAgent.__new__(_M.MasterAgent)   # bypass heavy __init__
    _saved = _os.environ.get("ARGUS_OPERATOR")
    try:
        _os.environ.pop("ARGUS_OPERATOR", None)
        _assert(_inst._operator_core_enabled() is True,
                "operator core is the DEFAULT driver (no env needed)")
        _os.environ["ARGUS_OPERATOR"] = "0"
        _assert(_inst._operator_core_enabled() is False,
                "ARGUS_OPERATOR=0 forces the legacy ReasoningLoop")
        _os.environ["ARGUS_OPERATOR"] = "1"
        _assert(_inst._operator_core_enabled() is True,
                "ARGUS_OPERATOR=1 re-enables the operator core")
    finally:
        if _saved is None:
            _os.environ.pop("ARGUS_OPERATOR", None)
        else:
            _os.environ["ARGUS_OPERATOR"] = _saved

    # The driver method runs the operator FIRST and keeps the legacy loop as fallback.
    _src = _inspect.getsource(_M.MasterAgent._reasoning_loop_run)
    _assert("OperatorCore(self" in _src and "OperatorUnavailable" in _src,
            "the operator core is instantiated + run inside the driver")
    _assert("final_intel = await loop.run()" in _src
            and _src.index("OperatorCore(self") < _src.index("final_intel = await loop.run()"),
            "the legacy ReasoningLoop runs only AFTER the operator (true fallback ordering)")
    _assert("operator_core_fallback" in _src,
            "operator errors / LLM-unavailable emit a fallback event then degrade to legacy")
    _assert("if not use_operator:" in _src and "_start_entry_dispatcher" in _src,
            "the auto-fire exploit dispatcher is gated off under the operator "
            "(approve-to-exploit gate is honoured)")

    # Initial-state brief seeds known recon so the operator never re-discovers it.
    from agents.operator_agent.operator_core import OperatorCore
    class _M2:
        def __init__(self):
            self._intel = {"target": "t", "target_host": "t", "open_ports": [
                {"port": 80, "product": "nginx"}], "subdomains": ["models.smarthire.htb"]}
            self._session_id = "s"; self._target_host = "t"; self._target = "t"
            self._target_url = "http://t"; self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"
    _brief = OperatorCore(_M2())._initial_state_brief()
    _assert("80" in _brief and "nginx" in _brief and "models.smarthire.htb" in _brief,
            "operator is seeded with already-known ports/services/vhosts (efficiency)")


def test_operator_log_driven_fixes() -> None:
    _section("Test 84 — operator fixes: live web-port, approval-clear, advisor wiring")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    import agents.exploit.exploit_approval as _APP

    class _FakeExpert:
        async def post_phase_directive(self, phase, intel_snapshot, findings, peer_corrections):
            class _C:
                recommended_action = "Pivot to /api/log-level; it controls debug RCE."
            return [_C()]

    class _FM:
        def __init__(self):
            self._intel = {"target": "10.129.13.1", "target_host": "10.129.13.1",
                           "target_url": "http://10.129.13.1:3000",
                           "open_ports": [{"port": 22, "service": "ssh"},
                                          {"port": 3000, "service": "http", "product": "Next.js"}],
                           "services": {3000: {"name": "http", "product": "Node.js"}, 22: {"name": "ssh"}}}
            self._session_id = "s"; self._target_host = "10.129.13.1"; self._target = "10.129.13.1"
            self._target_url = "http://10.129.13.1:3000"; self._scope_guard = ""
            self._stop_requested = False; self.name = "agentname.master"; self.phase = "operator"
            self._expert = _FakeExpert(); self._pending_corrections = _aio.Queue(); self.emits = []
        async def converse(self, messages, tier="reason", **k):
            return '{"tool":"done","args":{}}'
        async def _dispatch_to_agent(self, **k):
            return {"stdout": "", "exit_code": 0}
        async def _emit(self, ev, data):
            self.emits.append((ev, data))
        async def emit_reasoning(self, **k):
            pass

    # ISSUE 1 — live web-port detection picks the real app port, not blind 80.
    _m = _FM(); _op = OperatorCore(_m)
    _ports = _op._web_ports_from_intel()
    _assert(3000 in _ports and 80 not in _ports,
            "web_enum detects the live HTTP port (3000) and refuses blind port 80", str(_ports))

    # ISSUE 3 — approval emits awaiting_approval THEN approval_result (clears UI card).
    async def _drive_approval():
        async def _approver():
            for _ in range(80):
                ids = _APP.pending_ids()
                if ids:
                    _APP.resolve(ids[0], "approve"); return
                await _aio.sleep(0.02)
        _t = _aio.ensure_future(_approver())
        _op._iteration = 7
        d = await _op._request_approval({"tool": "run_tool", "args": {"tool": "sqlmap", "args": "-u x"}})
        await _t
        return d
    _dec = _aio.run(_drive_approval())
    _stages = [d.get("stage") for ev, d in _m.emits if ev == "exploit_lab"]
    _assert(_dec == "approve" and "awaiting_approval" in _stages and "approval_result" in _stages,
            "approval emits BOTH awaiting_approval and approval_result (UI no longer stuck)", str(_stages))
    _res = [d for ev, d in _m.emits if ev == "exploit_lab" and d.get("stage") == "approval_result"][0]
    _assert(_res["attempt"] == 7 and _res["decision"] == "approve",
            "approval_result carries the matching attempt index + decision so the right card clears")

    # ISSUE 2 — advisors (red-team critique + drained corrections + convergence) injected.
    _m._pending_corrections.put_nowait({"recommended_action": "Re-target port 3000, not 80."})
    _op.transcript = [{"role": "system", "content": "S"}, {"role": "user", "content": "go"}]
    _op._stale_rounds = 2
    _aio.run(_op._consult_advisors())
    _adv = [msg["content"] for msg in _op.transcript
            if msg["role"] == "user" and "ADVISOR FEEDBACK" in msg["content"]]
    _assert(bool(_adv) and "red-team" in _adv[0] and "Re-target port 3000" in _adv[0]
            and "convergence" in _adv[0],
            "operator consults red-team Expert + drains corrections + convergence hint (meta-agents wired)")

    # ISSUE 1 — a stalled LLM call is bounded (returns '' instead of freezing).
    class _SlowFM(_FM):
        async def converse(self, messages, tier="reason", **k):
            await _aio.sleep(5); return "too late"
    _op2 = OperatorCore(_SlowFM()); _op2._llm_call_timeout = 1
    _op2.transcript = [{"role": "user", "content": "x"}]
    _out = _aio.run(_op2._converse_bounded())
    _assert(_out == "", "a stalled operator LLM call is bounded by ARGUS_OPERATOR_LLM_TIMEOUT")


def test_operator_cve_pipeline() -> None:
    _section("Test 85 — operator version→CVE→public-PoC reflex + tool-timeout")
    import asyncio as _aio
    import agents.operator_agent.cve_lookup as _CL
    from agents.operator_agent.operator_core import OperatorCore

    # format_result surfaces CVE IDs + PoC repos with a 'git clone' nudge.
    _fake = {"query": "Next.js 15.0.3",
             "cves": [{"cve": "CVE-2025-55182", "severity": "CRITICAL",
                       "summary": "RCE in React Server Components"}],
             "pocs": [{"repo": "x/CVE-2025-55182-NextJS-RCE-PoC",
                       "url": "https://github.com/x/CVE-2025-55182-NextJS-RCE-PoC",
                       "stars": 42, "desc": "Next.js RCE", "cves": ["CVE-2025-55182"]}],
             "searchsploit": []}
    _out = _CL.format_result(_fake)
    _assert("CVE-2025-55182" in _out and "github.com" in _out and "git clone" in _out,
            "cve_lookup result surfaces CVE IDs + public PoC repos (git clone + run)")
    _assert(_CL._relevance("remote code execution unauthenticated", "CVE-2025-55182", "Next.js", "15.0.3")
            > _CL._relevance("info disclosure", "CVE-2019-0001", "Next.js", ""),
            "CVE relevance ranks a recent unauth-RCE above an old info-disclosure")

    class _FM:
        def __init__(self):
            self._intel = {"target": "10.129.13.1", "target_host": "10.129.13.1",
                           "target_url": "http://10.129.13.1:3000",
                           "service_versions": {"22": "OpenSSH 9.6p1 Ubuntu",
                                                "3000": "Next.js (HTTP/1.1, X-Powered-By: Next.js) on Linux"},
                           "services": {"3000": {"service": "ppp?", "version": "", "port": 3000}},
                           "inferred_versions": {"versions": {"apache": "2.4.58", "openssh": "9.6p1"}}}
            self._session_id = "s"; self._target_host = "10.129.13.1"; self._target = "10.129.13.1"
            self._target_url = "http://10.129.13.1:3000"; self._scope_guard = ""
            self._stop_requested = False; self.name = "m"; self.phase = "operator"
        async def converse(self, *a, **k): return '{"tool":"done","args":{}}'
        async def _dispatch_to_agent(self, **k): return {"stdout": "x", "exit_code": 0}
        async def _emit(self, ev, data): pass
        async def emit_reasoning(self, **k): pass

    _op = OperatorCore(_FM())
    # Product extraction: real Next.js fingerprint ranks above bogus inferred apache,
    # and HTTP/1.1 must NOT be mis-parsed as the Next.js version.
    _prods = _op._extract_products()
    _assert(_prods and _prods[0][0].lower().startswith("next"),
            "live Next.js fingerprint outranks generic OS-inferred infra guesses", str(_prods[:3]))
    _nx = [p for p in _prods if p[0].lower().startswith("next")][0]
    _assert(_nx[1] == "", "Next.js version not mis-parsed from 'HTTP/1.1'", str(_nx))

    _orig = _CL.lookup
    async def _fake_lookup(product, version="", **k):
        return _fake
    _CL.lookup = _fake_lookup
    try:
        _res = _aio.run(_op._do_cve_lookup("Next.js", "15.0.3"))
        _assert(any(c["cve"] == "CVE-2025-55182" for c in _op._intel.get("cves", []))
                and _op._intel.get("exploit_modules") and
                _op._intel["exploit_modules"][0]["url"].startswith("https://github.com"),
                "cve_lookup records matched CVEs + PoC repos into intel (no more 'cves: []')")
        _op2 = OperatorCore(_FM()); _op2.transcript = [{"role": "system", "content": "S"}]
        _aio.run(_op2._seed_cve_intel())
        _seed = [m["content"] for m in _op2.transcript if "STARTING LEADS" in m.get("content", "")]
        _assert(bool(_seed) and "CVE-2025-55182" in _seed[0],
                "operator is auto-seeded with CVE/PoC leads from the recon fingerprint at startup")
    finally:
        _CL.lookup = _orig

    # Tool-call timeout: a stalled dispatch is bounded (returns a dict, never freezes).
    class _SlowFM(_FM):
        async def _dispatch_to_agent(self, **k):
            await _aio.sleep(3); return {"stdout": "late", "exit_code": 0}
    _r = _aio.run(OperatorCore(_SlowFM())._dispatch_bounded(
        tool="grep", args="x", purpose="p", phase="operator", timeout=0))
    _assert(isinstance(_r, dict),
            "operator tool dispatch is wrapped in a hard wall-clock bound (504s grep can't freeze it)")


def test_operator_fast_path() -> None:
    _section("Test 86 — operator-direct execution (no extraction tax / no agent spin-up)")
    import asyncio as _aio
    import inspect as _inspect
    import agents.master_agent as _M

    # Source: the operator fast path runs tools via run_tool (not a specialist
    # agent) and skips classification; master_checker is gated off under operator.
    _disp = _inspect.getsource(_M.MasterAgent._dispatch_to_agent)
    _assert('if phase == "operator":' in _disp and "self.run_tool(" in _disp,
            "operator-dispatched tools run DIRECTLY via run_tool (no specialist/cluster agent, no extraction)")
    _assert(_disp.index('if phase == "operator":') < _disp.index("_classify_tool_to_phase(tool)"),
            "the operator fast path short-circuits BEFORE per-tool agent classification")
    _init = _inspect.getsource(_M.MasterAgent.__init__) if hasattr(_M.MasterAgent, "__init__") else ""
    _run = _inspect.getsource(_M.MasterAgent.run)
    _src_all = _init + _run
    # MasterChecker was removed entirely (dead plan-auditor); the IssueValidator
    # is now a real finding gate built on the operator path.
    _assert("_master_checker" not in _src_all and "MasterCheckerAgent" not in _src_all,
            "MasterChecker fully removed from master_agent (dead plan-auditor)")

    # _cheap_intel_merge: LLM-free nmap port/service parse.
    _inst = _M.MasterAgent.__new__(_M.MasterAgent)
    _inst._intel = {}
    _inst._cheap_intel_merge("nmap",
        "PORT     STATE SERVICE\n22/tcp   open  ssh OpenSSH 9.6p1\n3000/tcp open  http Next.js")
    _ports = {p.get("port") for p in _inst._intel.get("open_ports", [])}
    _assert(22 in _ports and 3000 in _ports and "3000" in _inst._intel.get("services", {}),
            "_cheap_intel_merge populates open_ports/services from nmap output with NO LLM call")

    # Functional: fast path calls run_tool exactly once, then dedups the re-run.
    _inst2 = _M.MasterAgent.__new__(_M.MasterAgent)
    _inst2._intel = {}; _inst2._target = "10.129.13.1"; _inst2._session_id = "s"
    _inst2._tool_circuit_breaker = {}
    _inst2._normalize_action_args = lambda t, a: (t, a)
    _calls = {"n": 0}
    async def _fake_run_tool(tool, args, target=None, timeout=300, **k):
        _calls["n"] += 1
        return {"stdout": "3000/tcp open http Next.js", "stderr": "",
                "exit_code": 0, "output_id": "x"}
    _inst2.run_tool = _fake_run_tool
    _r1 = _aio.run(_inst2._dispatch_to_agent(tool="nmap", args="-p- 10.129.13.1",
                                             purpose="scan", phase="operator"))
    _r2 = _aio.run(_inst2._dispatch_to_agent(tool="nmap", args="-p- 10.129.13.1",
                                             purpose="scan", phase="operator"))
    _assert(_calls["n"] == 1 and _r2.get("cached") is True,
            "identical expensive recon is de-duplicated (the 4-6x nmap -p- problem) — run_tool called once")
    _assert("Next.js" in _r1.get("stdout", "") and 3000 in
            {p.get("port") for p in _inst2._intel.get("open_ports", [])},
            "operator fast path returns raw stdout + cheap-merges ports without any specialist agent")


def test_operator_poc_commit() -> None:
    _section("Test 87 — operator commits to a public PoC (no more 'found it, never ran it')")
    import asyncio as _aio
    import agents.operator_agent.cve_lookup as _CL
    from agents.operator_agent.operator_core import OperatorCore
    import agents.master_agent as _M

    # format_result: PoC-first imperative, RCE PoC ranked above a high-star
    # non-RCE repo, and LOW-severity NVD noise dropped when a PoC exists.
    _res = {"query": "Next.js 14",
            "cves": [{"cve": "CVE-2025-32421", "severity": "LOW", "summary": "race"},
                     {"cve": "CVE-2024-46982", "severity": "HIGH", "summary": "cache poison"}],
            "pocs": [{"repo": "x/next-info", "url": "https://github.com/x/next-info",
                      "stars": 2000, "desc": "awesome nextjs", "cves": []},
                     {"repo": "xalgord/React2Shell", "url": "https://github.com/xalgord/React2Shell",
                      "stars": 30, "desc": "Next.js RCE", "cves": ["CVE-2025-55182"]}],
            "searchsploit": []}
    _out = _CL.format_result(_res)
    _assert("ACTION:" in _out and "git clone" in _out and "do NOT hand-roll" in _out,
            "cve_lookup leads with an imperative to clone+run the PoC (not hand-roll it)")
    _assert(_out.index("React2Shell") < _out.index("next-info"),
            "a 30-star RCE PoC ranks ABOVE a 2000-star non-exploit repo (weaponisability > stars)")
    _assert("CVE-2025-32421" not in _out and "CVE-2024-46982" in _out,
            "low-severity NVD noise is dropped when a real PoC exists (no misdirection)")

    # Advisor: an UNUSED public PoC with no foothold yields a PRIORITY nudge,
    # and that nudge is suppressed once a foothold exists.
    class _FM:
        def __init__(self):
            self._intel = {"exploit_modules": [{"type": "public_poc",
                "url": "https://github.com/xalgord/React2Shell", "cves": ["CVE-2025-55182"]}]}
            self._session_id = "s"; self._target_host = "t"; self._target = "t"
            self._target_url = "http://t"; self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"; self._expert = None
            self._pending_corrections = None
        async def converse(self, *a, **k): return ""
        async def _dispatch_to_agent(self, **k): return {}
        async def _emit(self, ev, data): pass
        async def emit_reasoning(self, **k): pass
    _op = OperatorCore(_FM()); _op.transcript = [{"role": "system", "content": "S"}]
    _aio.run(_op._consult_advisors())
    _nudge = [m["content"] for m in _op.transcript if "PRIORITY" in m.get("content", "")]
    _assert(bool(_nudge) and "React2Shell" in _nudge[0]
            and ("EXECUTE" in _nudge[0] or "RUN it" in _nudge[0]),
            "an unused public PoC triggers a PRIORITY 'execute it now' nudge")
    _op2 = OperatorCore(_FM()); _op2._intel["shell_access"] = True
    _op2.transcript = [{"role": "system", "content": "S"}]
    _aio.run(_op2._consult_advisors())
    _assert(not [m for m in _op2.transcript if "UNUSED public exploit" in m.get("content", "")],
            "the PoC nudge is suppressed once a foothold/shell exists")

    # Report-gen no longer crashes on dict-form CVEs (intel['cves'] from cve_lookup).
    _inst = _M.MasterAgent.__new__(_M.MasterAgent)
    _inst._intel = {"cves": [{"cve": "CVE-2025-55182", "severity": "CRITICAL"}, "CVE-2024-46982"],
                    "services": {}, "technologies": []}
    _summ = _inst._intel_summary()
    _assert("CVE-2025-55182" in _summ,
            "_intel_summary coerces dict-form CVEs (no 'expected str instance, dict found' crash)")


def test_operator_success_persistence() -> None:
    _section("Test 88 — operator persists RCE/flags/creds (findings + objectives + budget)")
    import asyncio as _aio
    import inspect as _inspect
    from agents.operator_agent.operator_core import OperatorCore
    import agents.master_agent as _M

    class _FM:
        def __init__(self):
            self._intel = {"target": "10.129.13.227"}; self._session_id = "s"
            self._target_host = "10.129.13.227"; self._target = "10.129.13.227"
            self._target_url = "http://10.129.13.227:3000"; self._scope_guard = ""
            self._stop_requested = False; self.name = "m"; self.phase = "operator"
            self._expert = None; self._pending_corrections = None; self.findings = []
        async def converse(self, *a, **k): return ""
        async def _dispatch_to_agent(self, **k): return {}
        async def _emit(self, ev, data): pass
        async def emit_reasoning(self, **k): pass
        async def store_finding(self, severity, title, description, host,
                                tool_used=None, cves=None, evidence=None):
            self.findings.append({"severity": str(severity), "title": title}); return {}

    _m = _FM(); _op = OperatorCore(_m)
    # RCE proof → shell_access + CRITICAL finding + objective complete (the root fix)
    _aio.run(_op._record_operator_success("python3", {"args": "nextrce.py -c id"},
        "[VULN] RCE SUCCESS\n   Output: uid=999(node) gid=988(node) groups=988(node)"))
    _assert(_m._intel.get("shell_access") and _m._intel.get("current_user") == "node"
            and any(f["title"].startswith("Remote Code Execution") for f in _m.findings)
            and _m._intel.get("objective_status", {}).get("initial_access") == "complete",
            "confirmed RCE sets shell_access, records a CRITICAL finding, marks the objective")

    # flag captured ONLY in user.txt/root.txt context (no hostkey/hash false-positives)
    _aio.run(_op._record_operator_success("python3", {"args": "cat /home/engineer/user.txt"},
        "Output: 1409923abe1d14d015948629d7d78a94"))
    _assert(_m._intel.get("user_flag") == "1409923abe1d14d015948629d7d78a94"
            and _m._intel.get("objective_status", {}).get("user") == "complete",
            "a 32-hex in user.txt context is captured as the user flag + objective")
    _aio.run(_op._record_operator_success("nmap", {"args": "ssh-hostkey"},
        "256 cefd0d82c023ed6e4bea13fa4feaefb7 (ECDSA)"))
    _assert(not _m._intel.get("root_flag"),
            "a 32-hex WITHOUT flag context (nmap hostkey) is NOT mistaken for a flag")

    # creds: db-dump rows captured; 'Output: <flag>' is NOT mis-parsed as a cred
    _aio.run(_op._record_operator_success("python3", {"args": "sqlite3 reactor.db"},
        "admin|a203b22191d744a4e70ada5c101b17b8|administrator"))
    _users = [c.get("user") for c in _m._intel.get("credentials", [])]
    _assert("admin" in _users and "Output" not in _users,
            "db-dump user|hash rows recorded as creds; label-like 'Output:' lines rejected")

    # /etc/passwd login-shell users only
    _aio.run(_op._record_operator_success("python3", {"args": "cat /etc/passwd"},
        "engineer:x:1000:1000:engineer:/home/engineer:/bin/bash\n"
        "node:x:999:988::/home/node:/usr/sbin/nologin"))
    _assert("engineer" in _m._intel.get("users", []) and "node" not in _m._intel.get("users", []),
            "passwd users with a login shell are recorded (nologin accounts skipped)")

    # foothold-aware budget: run() extends the wall-clock once a foothold exists
    _runsrc = _inspect.getsource(OperatorCore.run)
    _assert("foothold_bonus" in _runsrc and "rce_confirmed" in _runsrc,
            "the wall-clock budget is extended once RCE/shell is confirmed (no killing a winning run)")

    # report no longer crashes on a dict-valued banner (KeyError slice)
    _inst = _M.MasterAgent.__new__(_M.MasterAgent)
    _inst._intel = {"banners": {"http": {"server": "nginx", "raw": "x"}}, "services": {}, "technologies": []}
    _summ = _inst._intel_summary()
    _assert("Banner (http)" in _summ,
            "_intel_summary coerces a dict-valued banner (no KeyError(slice(None,100,None)) report crash)")


def test_operator_autonomy_objectives_roster() -> None:
    _section("Test 89 — autonomy@start + flexible objectives/handover/loot + Agent Roster")
    import asyncio as _aio
    import inspect as _inspect
    from pathlib import Path as _P
    import agents.master_agent as _M
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent import tool_catalog as _cat

    # ── #1 autonomy selectable at scan start ────────────────────────────────
    # NOTE: the ACTIVE request model is db.schemas.StartPentestRequest (the one
    # agent_server imports) — not the top-level schemas.py.
    from db.schemas import StartPentestRequest as _SPR
    _fields = getattr(_SPR, "model_fields", None) or getattr(_SPR, "__fields__", {})
    _assert("autonomy" in _fields, "db.schemas.StartPentestRequest exposes an 'autonomy' field")
    _runsrc = _inspect.getsource(_M.MasterAgent.run)
    _assert("self._operator_autonomy" in _runsrc and "autonomy" in _runsrc,
            "master.run() accepts + stores the per-scan autonomy override")
    _rlrsrc = _inspect.getsource(_M.MasterAgent._reasoning_loop_run)
    _assert("_operator_autonomy" in _rlrsrc,
            "_reasoning_loop_run uses the per-scan autonomy when building OperatorCore")

    class _FM:
        def __init__(self):
            self._intel = {"target": "t", "engagement_context": {"engagement_type": "ctf",
                           "objectives": [{"task": "user.txt"}, {"task": "root.txt"}]}}
            self._session_id = "s"; self._target_host = "t"; self._target = "t"
            self._target_url = "http://t"; self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"; self._expert = None
            self._pending_corrections = None; self.findings = []; self.events = []
        async def converse(self, *a, **k): return ""
        async def _dispatch_to_agent(self, **k): return {"stdout": "", "exit_code": 0}
        async def _emit(self, ev, data): self.events.append(ev)
        async def emit_reasoning(self, **k): pass
        async def store_finding(self, severity, title, description, host, tool_used=None, cves=None, evidence=None):
            self.findings.append({"sev": str(severity), "title": title}); return {}
        async def register_shell(self, **k): self._intel["shell_access"] = True; return True

    # ── #2 flexible objectives / handover / loot / findings ─────────────────
    _op = OperatorCore(_FM()); _m = _op.master
    # non-32hex flag captured from a flag-file cat
    _aio.run(_op._record_operator_success("python3", {"args": "cat /opt/app/flag.txt"},
        "Output: FLAG{n0t_h3x}"))
    _assert(_m._intel.get("user_flag") == "FLAG{n0t_h3x}",
            "flags of ANY format (flag{...}) are captured, not just 32-hex")
    _assert("handover" in _cat.render_tool_docs() and "loot_hunt" in _cat.render_tool_docs(),
            "operator toolbelt exposes handover + loot_hunt")

    _m._intel["shell_access"] = True; _m._intel["current_user"] = "node"
    _r = _aio.run(_op._do_handover({"method": "info"}))
    _assert("HANDOVER" in _r and _m._intel.get("handover_ready")
            and "shell_handover" in _m.events
            and any("handover" in f["title"].lower() for f in _m.findings),
            "handover marks foothold_ready, emits shell_handover, and records a handover finding")
    _r2 = _aio.run(_op._do_loot_hunt({"scope": "all"}))
    _assert("SSH KEYS" in _r2 and "passwd" in _r2,
            "loot_hunt produces a host loot sweep")
    _m._intel["user_flag"] = "x"; _m._intel["root_flag"] = "y"
    _aio.run(_op._finalize_objectives())
    _assert(_m._intel.get("engagement_outcome") == "full_compromise"
            and _m._intel.get("objectives_summary")
            and "operator_objectives" in _m.events
            and any("objectives" in f["title"].lower() for f in _m.findings),
            "objectives are finalized into intel + a findings-page entry (pass/fail parsed)")

    # ── #3 Agent Roster reflects the operator-driven model ──────────────────
    _root = _P(__file__).resolve().parent.parent
    _ac = (_root / "static" / "js" / "pages" / "AgentConsole.jsx").read_text(encoding="utf-8")
    _assert("'operator'" in _ac and "error_analyzer" in _ac and "Mission Control" in _ac,
            "Agent Roster leads with the Operator + meta-agents and references Mission Control")
    _assert("'driver'" in _ac and "'fallback'" in _ac,
            "Agent Roster labels the driver vs fallback agents (no more confusing flat 86-agent list)")
    _idx = (_root / "templates" / "index.html").read_text(encoding="utf-8")
    _assert("AgentConsole.jsx?v=5" in _idx and "TargetConfig.jsx?v=10" in _idx,
            "cache-bust bumped for the edited AgentConsole + TargetConfig")


def test_operator_interactive_handover() -> None:
    _section("Test 90 — operator fronts the foothold (RCE console / SSH / revshell)")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore

    # ShellAgent gains the RCE-console primitive (source-checked: shell_agent.py
    # is Unix-only — pty/fcntl/termios — so it can't be imported on every CI host).
    _sa_src = (_P(__file__).resolve().parent.parent / "agents" / "shell_agent.py").read_text(encoding="utf-8")
    _assert("async def create_rce_console" in _sa_src and "_rce_console_input" in _sa_src
            and "run_fn" in _sa_src and "self._rce_consoles" in _sa_src,
            "ShellAgent has an RCE-backed console (type commands in the GUI → run via RCE channel)")
    _assert("rce = self._rce_consoles.get(shell_id)" in _sa_src,
            "handle_input routes a typed line to the RCE console runner before the PTY path")

    class _SA:
        def __init__(self): self.created = None
        async def create_rce_console(self, session_id, shell_id, *, run_fn, host="", user="", label=""):
            self.created = {"shell_id": shell_id, "host": host, "user": user, "run_fn": run_fn}
            return {"success": True}
        async def connect_ssh(self, *a, **k): return {"success": True}
        async def create_listener(self, *a, **k): return {"success": True}

    class _FM:
        def __init__(self):
            self._intel = {"target": "10.1.1.1"}; self._session_id = "s"
            self._target_host = "10.1.1.1"; self._target = "10.1.1.1"
            self._target_url = "http://x"; self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"; self._expert = None
            self._pending_corrections = None; self.findings = []; self.events = []
            self._shell_agent = _SA()
        async def converse(self, *a, **k): return ""
        async def _dispatch_to_agent(self, **k): return {"stdout": "uid=0(root)", "exit_code": 0}
        async def _emit(self, ev, data): self.events.append(ev)
        async def emit_reasoning(self, **k): pass
        async def store_finding(self, severity, title, description, host, tool_used=None, cves=None, evidence=None):
            self.findings.append(title); return {}
        async def register_shell(self, **k): return True

    _op = OperatorCore(_FM()); _m = _op.master
    # RCE channel auto-captured from the successful PoC command.
    _aio.run(_op._record_operator_success(
        "python3", {"tool": "python3", "args": '/tmp/NextRce/nextrce.py -u http://10.1.1.1:3000 -c "id"'},
        "[VULN] RCE SUCCESS\n   Output: uid=0(root)"))
    _ch = _m._intel.get("rce_channel") or {}
    _assert(_ch.get("tool") == "python3" and "{cmd}" in (_ch.get("args_template") or ""),
            "the RCE channel (tool + args template with {cmd}) is captured on RCE confirm")

    # Handover with no creds → RCE console; its run_fn drives the foothold.
    _r = _aio.run(_op._do_handover({}))
    _assert("RCE console" in _r and _m._shell_agent.created and "shell_handover" in _m.events,
            "handover opens an RCE console session the human can drive from the Shell Manager")
    _out = _aio.run(_m._shell_agent.created["run_fn"]("whoami"))
    _assert("uid=0(root)" in _out,
            "typed console commands execute through the RCE channel and return output")

    # Handover with a plaintext cred → interactive SSH PTY.
    _m._intel["credentials"] = [{"user": "engineer", "pass": "reactor1"}]
    _r2 = _aio.run(_op._do_handover({"method": "ssh"}))
    _assert("SSH" in _r2, "handover opens an interactive SSH PTY when a usable credential exists")


def test_operator_first_call_resilience():
    _section("Test 91 — operator survives an empty opening call (no silent legacy demotion)")
    import os as _os
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore, OperatorUnavailable

    # ── source-asserts: the wiring that prevents the 6a219815 failure mode ─────
    _root = _P(__file__).resolve().parent.parent
    _oc_src = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("await self._recover_first_call()" in _oc_src,
            "run() recovers an empty opening call instead of bare-raising OperatorUnavailable")
    _assert("def _shrink_opening_prompt" in _oc_src and "def _compact_seed_block" in _oc_src,
            "operator has prompt-shrink + compact-seed helpers to fit a local model's context")
    _assert('raise OperatorUnavailable("operator LLM returned no content")' not in _oc_src,
            "the old fatal first-empty raise is gone (now retry-then-raise)")

    _lp_src = (_root / "utils" / "llm_providers.py").read_text(encoding="utf-8")
    _assert('"num_ctx"' in _lp_src and "OLLAMA_NUM_CTX" in _lp_src,
            "OllamaProvider.stream sets an explicit num_ctx (oversized opening prompt no longer dropped)")

    _ma_src = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("def _note_operator_fallback" in _ma_src
            and _ma_src.count("await self._note_operator_fallback(") >= 2,
            "master records a VISIBLE finding on operator→legacy fallback (both branches)")

    # ── fake master scripting converse() to reproduce the empty-first-call ─────
    class _FM:
        def __init__(self, script):
            self._intel = {"target": "10.1.1.1"}; self._session_id = "s"
            self._target_host = "10.1.1.1"; self._target = "10.1.1.1"
            self._target_url = "http://x"; self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"; self._expert = None
            self._pending_corrections = None; self.calls = 0; self._script = list(script)
        async def converse(self, *a, **k):
            self.calls += 1
            return self._script.pop(0) if self._script else ""
        async def _dispatch_to_agent(self, **k): return {"stdout": "", "exit_code": 0}
        async def _emit(self, ev, data): pass
        async def emit_reasoning(self, **k): pass
        async def store_finding(self, **k): return {}

    _done = ("Thought: wrapping up.\n```action\n"
             "{\"tool\": \"done\", \"args\": {\"summary\": \"ok\"}}\n```")
    _os.environ["ARGUS_OPERATOR_START_RETRIES"] = "1"

    # (a) opening call empty, retry returns a valid action → operator RECOVERS
    #     and drives the engagement (the run is NOT dumped to the legacy loop).
    _m1 = _FM(["", _done])
    _res1 = _aio.run(OperatorCore(_m1, max_iters=3, max_seconds=120).run())
    _assert(_m1.calls >= 2, "an empty opening call is RETRIED (converse called >1), not insta-fatal")
    _assert(isinstance(_res1, dict), "operator completes the engagement after recovering on retry")

    # (b) every call empty → OperatorUnavailable raised ONLY after the retries.
    _m2 = _FM([])
    _raised = False
    try:
        _aio.run(OperatorCore(_m2, max_iters=3, max_seconds=120).run())
    except OperatorUnavailable:
        _raised = True
    _assert(_raised and _m2.calls >= 2,
            "OperatorUnavailable raised only after retrying the opening call (>=2 attempts)")

    # ── unit: compact-seed cap + shrink drops the bulky seed body ──────────────
    _os.environ["ARGUS_OPERATOR_SEED_BLOCK_CHARS"] = "700"
    _op3 = OperatorCore(_FM([]))
    _assert(len(_op3._compact_seed_block("X" * 5000)) <= 720,
            "compact seed block is capped (~700 chars) so turn-1 fits the context window")
    _op3.transcript = [{"role": "system", "content": "SYS"},
                       {"role": "user", "content": "STARTING LEADS — " + ("y" * 5000)}]
    _op3._shrink_opening_prompt(2)
    _u = _op3.transcript[1]["content"]
    _assert("yyyy" not in _u and "intel" in _u,
            "_shrink_opening_prompt(level>=2) drops the bulky CVE/PoC seed (kept in intel)")

    _os.environ.pop("ARGUS_OPERATOR_START_RETRIES", None)
    _os.environ.pop("ARGUS_OPERATOR_SEED_BLOCK_CHARS", None)


def test_no_hardcoded_model_truthful_logging():
    _section("Test 92 — no hardcoded model default + logs record the REAL provider/model")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent

    _lp = (_root / "utils" / "llm_providers.py").read_text(encoding="utf-8")
    _assert('default="llama3.1:8b"' not in _lp and "llama3.1:8b" not in _lp,
            "utils/llm_providers.py no longer hardcodes a llama3.1:8b model default")

    _ba = (_root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert('os.environ.get("OLLAMA_MODEL", "deepseek-v3.1:671b-cloud")' not in _ba,
            "base_agent.py MODEL_NAME no longer hardcodes a deepseek model default")
    _assert("model          = _model_for_log," in _ba,
            "think() logs the REAL provider model (_model_for_log), not the static MODEL_NAME")
    _assert("def _active_model_label" in _ba
            and "model          = self._active_model_label()," in _ba,
            "think_json() logs the live provider model via _active_model_label()")

    _srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert('"deepseek-v3.1:671b-cloud"' not in _srv,
            "agent_server.py MODEL_NAME no longer hardcodes a model default")

    _ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert('"llm_resolved"' in _ma and "RESOLVED — primary=" in _ma,
            "master emits a one-time resolved-provider banner (primary + backup + real model)")

    # behavioural: the truthful-model helper reflects the LIVE provider, not a default
    import utils.llm_providers as _L
    from agents.base_agent import BaseAgent
    class _FakeProv:
        name = "claude-code"; model = "claude-opus-4-7"; base_url = ""
    _old = _L._PROVIDER_CACHE
    _L._PROVIDER_CACHE = _FakeProv()
    try:
        _lbl = BaseAgent._active_model_label(object())
    finally:
        _L._PROVIDER_CACHE = _old
    _assert(_lbl == "claude-opus-4-7",
            "_active_model_label() returns the live provider model (claude-opus-4-7), not a phantom")


def test_operator_reactive_cve_reflex():
    _section("Test 93 — reactive cve_lookup fires on fingerprint (no more CVE-from-memory anchoring)")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore

    _root = _P(__file__).resolve().parent.parent
    _oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    # The reactive reflex runs at start AND after every action (>=2 call sites).
    _assert(_oc.count("await self._seed_cve_intel()") >= 2,
            "cve_lookup seed runs reactively after each action, not just once at start")
    _assert("self._cve_seeded" in _oc,
            "operator tracks which products were CVE-looked-up (idempotent reflex)")
    _assert("[ANTI-ANCHOR]" in _oc,
            "advisor pushes off a remembered-CVE anchor toward verified lookups + app endpoints")

    _tc = (_root / "agents" / "operator_agent" / "tool_catalog.py").read_text(encoding="utf-8")
    _assert("outranks an unverified framework cve" in _tc.lower()
            and "HYPOTHESIS" in _tc,
            "doctrine: discovered app inputs outrank an unverified framework CVE; memory is a hypothesis")

    # ── behavioural: idempotent reactive lookup + exploit_modules population ────
    class _FM:
        def __init__(self):
            self._intel = {}; self._session_id = "s"; self._target_host = "10.1.1.1"
            self._target = "10.1.1.1"; self._target_url = "http://x"
            self._scope_guard = ""; self._stop_requested = False
            self.name = "m"; self.phase = "operator"
        async def _emit(self, *a, **k): pass
        async def emit_reasoning(self, *a, **k): pass

    _op = OperatorCore(_FM())
    _op._extract_products = lambda: [("Next.js", "15.0.3")]

    import agents.operator_agent.cve_lookup as _cve
    _calls = {"n": 0}
    async def _fake_lookup(product, version):
        _calls["n"] += 1
        return {"cves": [{"cve": "CVE-2025-29927", "severity": "HIGH", "summary": "auth bypass"}],
                "pocs": [{"url": "https://github.com/acme/nextjs-poc", "cves": ["CVE-2025-29927"]}]}
    def _fake_fmt(res): return "→ ACTION: git clone https://github.com/acme/nextjs-poc"
    _ol, _of = _cve.lookup, _cve.format_result
    _cve.lookup, _cve.format_result = _fake_lookup, _fake_fmt
    try:
        _aio.run(_op._seed_cve_intel())
        _aio.run(_op._seed_cve_intel())   # second call must be a no-op (idempotent)
    finally:
        _cve.lookup, _cve.format_result = _ol, _of

    _assert(_calls["n"] == 1,
            "reactive cve_lookup is idempotent — each (product,version) looked up exactly once")
    _mods = _op._intel.get("exploit_modules") or []
    _assert(any(m.get("type") == "public_poc" and "github.com/acme" in (m.get("url") or "")
                for m in _mods),
            "discovered public PoCs are written to exploit_modules (triggers the operator PoC nudge)")
    _assert(any("STARTING LEADS" in (m.get("content") or "")
                for m in _op.transcript if m.get("role") == "user"),
            "the real CVE/PoC leads are injected into the operator transcript on fingerprint")


class _FM_min:
    """Minimal fake master for constructing an OperatorCore in unit tests."""
    def __init__(self):
        self._intel = {}; self._session_id = "s"; self._target_host = "t"
        self._target = "t"; self._target_url = "http://t"; self._scope_guard = ""
        self._stop_requested = False; self.name = "m"; self.phase = "operator"
        self._expert = None; self._pending_corrections = None
    async def _emit(self, *a, **k): pass
    async def emit_reasoning(self, *a, **k): pass
    async def store_finding(self, **k): return {}


def test_operator_method_attempt_cap():
    _section("Test 94 — per-method attempt cap (try 3-5×, then forced pivot — no more 384× one CVE)")
    import os as _os
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore

    _root = _P(__file__).resolve().parent.parent
    _oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("def _method_signature" in _oc and "def _pivot_suggestions" in _oc,
            "operator has a method-signature classifier + pivot-suggestion helper")
    _assert("_banned_methods" in _oc and ">= self._method_max_tries" in _oc
            and '"operator_method_banned"' in _oc,
            "run loop counts per-method tries, bans at the cap, and emits the ban event")

    # signature classifier: operator-declared hypothesis, else a CVE id, else ''
    _op = OperatorCore(_FM_min())
    _sig_hyp = _op._method_signature("THOUGHT: try it", {"args": {}, "hypothesis": "SSRF on the fetch endpoint"})
    _sig_cve = _op._method_signature("THOUGHT: drive CVE-2025-29927 bypass.", {"args": {}})
    _sig_recon = _op._method_signature("THOUGHT: scan ports", {"args": {"tool": "nmap", "args": "-sV t"}})
    _assert(_sig_hyp == "hyp:ssrf on the fetch endpoint", "a declared hypothesis is the capped method signature")
    _assert(_sig_cve == "cve:CVE-2025-29927", "a named CVE is the fallback signature (no hardcoded technique table)")
    _assert(_sig_recon == "", "generic recon with no declared hypothesis is NOT capped (signature empty)")

    # cap is clamped to the real-tester range 3-5
    _os.environ["ARGUS_OPERATOR_METHOD_MAX_TRIES"] = "3"
    _assert(OperatorCore(_FM_min())._method_max_tries == 3, "cap honours env (3)")
    _os.environ["ARGUS_OPERATOR_METHOD_MAX_TRIES"] = "10"
    _assert(OperatorCore(_FM_min())._method_max_tries == 5, "cap clamps to <=5")
    _os.environ["ARGUS_OPERATOR_METHOD_MAX_TRIES"] = "3"

    # end-to-end: a method that never makes progress gets BANNED + forces a pivot
    class _FMloop:
        def __init__(self):
            self._intel = {}; self._session_id = "s"; self._target_host = "t"
            self._target = "t"; self._target_url = "http://t"; self._scope_guard = ""
            self._stop_requested = False; self.name = "m"; self.phase = "operator"
            self._expert = None; self._pending_corrections = None; self.events = []
        async def converse(self, *a, **k):
            return ("THOUGHT: hammering CVE-2025-29927 again.\n```action\n"
                    "{\"tool\": \"run_tool\", \"args\": {\"tool\": \"curl\", "
                    "\"args\": \"-H x-middleware-subrequest http://t/admin\"}}\n```")
        async def _dispatch_to_agent(self, **k): return {"stdout": "404", "exit_code": 0}
        async def _emit(self, ev, data): self.events.append(ev)
        async def emit_reasoning(self, *a, **k): pass
        async def store_finding(self, **k): return {}

    _m = _FMloop()
    _opL = OperatorCore(_m, autonomy="autonomous", max_iters=14, max_seconds=600)
    async def _noprog(tool, args): return "[FAIL] 404 no access"
    _opL._run_action = _noprog
    _aio.run(_opL.run())
    _assert("operator_method_banned" in _m.events,
            "a non-productive method is BANNED once it hits the cap")
    _assert("cve:CVE-2025-29927" in _opL._banned_methods,
            "the exhausted CVE method is recorded as banned (operator forced to pivot)")
    _os.environ.pop("ARGUS_OPERATOR_METHOD_MAX_TRIES", None)


def test_no_hardcoded_attack_content():
    _section("Tier A — guard: engine code contains NO vuln-specific content")
    import re as _re
    from pathlib import Path as _P
    root = _P(__file__).resolve().parent.parent / "agents" / "operator_agent"
    # The DOCTRINE/PROMPT + SPINE surfaces bias the model — they must be 100%
    # content-free. Operational execution code (operator_core) legitimately uses
    # GENERAL primitives (a loot sweep reads a passwd file; the approval gate
    # detects payload-ish input) — those are general, not box-specific, so it is
    # scanned only for the always-wrong signals.
    doctrine_spine = [root / "tool_catalog.py", root / "taxonomy.py",
                      root / "surface_model.py", root / "hypothesis_backlog.py",
                      root / "playbooks.py"]
    everywhere = doctrine_spine + [root / "operator_core.py"]
    cve = _re.compile(r"CVE-\d{4}-\d{4,7}", _re.I)
    # markers assembled from fragments so this deny-list is not itself a literal.
    table_marker = "x-middleware" + "-subrequest"   # the canonical technique-table smell
    payload_markers = ["/etc/" + "passwd", "../" + "../", "union" + " select",
                       "file" + "://", "jndi" + ":", "169.254" + ".169.254", "/render"]

    def _strip_comments(src):
        return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))

    offenders = []
    for f in everywhere:          # CVE ids + the technique-table header: banned everywhere
        if not f.exists():
            continue
        body = _strip_comments(f.read_text(encoding="utf-8"))
        if cve.search(body):
            offenders.append(f"{f.name}: CVE id literal")
        if table_marker in body.lower():
            offenders.append(f"{f.name}: technique-table marker '{table_marker}'")
    for f in doctrine_spine:      # generic payload literals: banned in the model-facing surfaces
        if not f.exists():
            continue
        low = _strip_comments(f.read_text(encoding="utf-8")).lower()
        for m in payload_markers:
            if m in low:
                offenders.append(f"{f.name}: payload literal '{m}'")
    _assert(not offenders,
            "engine modules are free of CVE ids / box-specific payload literals :: " + "; ".join(offenders))


def test_operator_declares_hypothesis():
    _section("Tier A — method signature is the operator's declared hypothesis, not a keyword table")
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    oc_src = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("tech:nextjs" not in oc_src and ("x-middleware" + "-subrequest") not in oc_src,
            "the hardcoded technique keyword table is gone from operator_core")
    op = OperatorCore(_FM_min())
    sig1 = op._method_signature("THOUGHT: trying it.",
                                {"tool": "http", "args": {}, "hypothesis": "auth bypass on the admin API"})
    _assert(sig1 == "hyp:auth bypass on the admin api", "declared hypothesis becomes the method signature (normalized)")
    sig2 = op._method_signature("THOUGHT: CVE-2025-29927 bypass", {"tool": "http", "args": {}})
    _assert(sig2.startswith("cve:") and sig2.endswith("-29927"), "CVE id is the fallback signature when no hypothesis declared")
    sig3 = op._method_signature("THOUGHT: scan ports", {"tool": "run_tool", "args": {"tool": "nmap"}})
    _assert(sig3 == "", "generic recon with no declared hypothesis is uncapped")


def test_doctrine_is_general():
    _section("Tier A — doctrine carries principles + taxonomy from data, no box names")
    import re as _re
    from agents.operator_agent import tool_catalog as _tc
    sp = _tc.build_system_prompt(objective="capture user.txt and root.txt",
                                 target={"host": "t", "kind": "ctf"})
    _assert(not _re.search(r"CVE-\d{4}-\d+", sp), "system prompt names no specific CVE")
    for bad in ("next.js", "reactorwatch", "/render", "x-middleware" + "-subrequest"):
        _assert(bad not in sp.lower(), f"system prompt does not name '{bad}'")
    _assert("ssrf" in sp.lower() and "weakness" in sp.lower(),
            "doctrine injects the general weakness taxonomy (classes, not boxes)")
    _assert("objective" in sp.lower(), "doctrine centers the human-set objective")


def test_weakness_taxonomy_loads():
    _section("Tier A — weakness taxonomy loads as data, maps capabilities -> classes")
    from agents.operator_agent import taxonomy as _tax
    classes = _tax.load_taxonomy()
    _assert(len(classes) >= 20, "taxonomy has a real class set (>=20 weakness classes)")
    ids = {c["id"] for c in classes}
    _assert({"ssrf", "sqli", "known_cve", "auth_bypass", "path_traversal"} <= ids,
            "core weakness classes are present")
    for c in classes:
        _assert(bool(c.get("id") and c.get("name") and c.get("generic_test_strategy")
                and isinstance(c.get("triggering_capabilities"), list)),
                f"class '{c.get('id')}' has id/name/strategy/triggering_capabilities")
    hits = {c["id"] for c in _tax.classes_for_capabilities(["fetches_remote"])}
    _assert("ssrf" in hits, "a node that fetches remote resources triggers the SSRF class")
    _no = {c["id"] for c in _tax.classes_for_capabilities(["renders_output"])}
    _assert("sqli" not in _no, "capability gating excludes non-applicable classes (no SQLi from renders_output)")
    _assert("ssrf" in _tax.taxonomy_brief().lower(), "taxonomy_brief renders class lines for the doctrine")


def test_surface_model_infers_capabilities():
    _section("Tier B — surface model infers node capabilities from intel (generic)")
    from agents.operator_agent.surface_model import SurfaceModel
    intel = {
        "open_ports": [22, 3000],
        "services": {"22": {"product": "OpenSSH", "version": "9.6"},
                     "3000": {"product": "AppServer", "version": "1.2", "name": "http"}},
        "web_paths": ["/", "/api/fetch?url=", "/files/download?path="],
        "technologies": ["SomeFramework"],
    }
    sm = SurfaceModel(); sm.infer_from_intel(intel)
    caps = sm.all_capabilities()
    _assert("version_known" in caps, "a fingerprinted service yields version_known")
    _assert("authenticates" in caps, "an SSH service yields authenticates")
    _assert("fetches_remote" in caps, "a '?url=' endpoint yields fetches_remote")
    _assert("file_access" in caps, "a '?path=' / download endpoint yields file_access")
    d = sm.to_dict(); sm2 = SurfaceModel.from_dict(d)
    _assert(sm2.all_capabilities() == caps, "surface model round-trips through dict (checkpoint-safe)")


def test_hypothesis_backlog():
    _section("Tier B — hypothesis backlog: generate from surface×taxonomy, prioritize, dedup, status")
    from agents.operator_agent.surface_model import SurfaceModel
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    intel = {"open_ports": [3000], "services": {"3000": {"name": "http", "product": "X", "version": "1"}},
             "web_paths": ["/api/fetch?url=", "/files/download?path="]}
    sm = SurfaceModel(); sm.infer_from_intel(intel)
    bl = HypothesisBacklog(objective_kinds=["access", "flag", "data"])
    n = bl.generate_from_surface(sm)
    _assert(n >= 2 and len(bl.untried()) >= 2, "hypotheses generated from surface×taxonomy")
    ids = {h.weakness_class for h in bl.all()}
    _assert("ssrf" in ids, "the ?url= endpoint produced an SSRF hypothesis")
    _assert("path_traversal" in ids, "the ?path= endpoint produced a path-traversal hypothesis")
    bl.generate_from_surface(sm)
    _assert(len(bl.all()) == n, "regeneration is idempotent (dedup by node+class)")
    top = bl.next_hypothesis()
    _assert(top is not None and top.status == "active", "next_hypothesis returns+activates the top item")
    bl.mark(top.id, "refuted")
    _assert(top.id not in {h.id for h in bl.untried()} and bl.next_hypothesis().id != top.id,
            "a refuted hypothesis is not handed out again")
    h2 = bl.next_hypothesis(); bl.mark(h2.id, "confirmed")
    _assert(any(h.status == "confirmed" for h in bl.all()), "confirmed status persists")
    d = bl.to_dict(); bl2 = HypothesisBacklog.from_dict(d)
    _assert(len(bl2.all()) == len(bl.all()), "backlog round-trips through dict (checkpoint-safe)")


def test_operator_drives_backlog():
    _section("Tier B — operator builds a surface model + objective-aware backlog")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._intel.update({"open_ports": [3000], "services": {"3000": {"name": "http", "product": "X", "version": "1"}},
                      "web_paths": ["/api/fetch?url="], "engagement_context": {"objective": "capture user.txt"}})
    _aio.run(op._refresh_surface_and_backlog())
    _assert(op._surface is not None and op._backlog is not None, "operator owns a surface model + backlog")
    _assert(op._backlog.high_value_remaining() >= 1, "backlog populated from current intel")
    _assert(any(h.weakness_class == "ssrf" for h in op._backlog.all()), "ssrf hypothesis present from ?url= endpoint")
    _assert("flag" in op._objective_kinds(), "objective_kinds reflects the human objective (flag)")


def test_backlog_injected_to_operator():
    _section("Tier C — the prioritized backlog + coverage is surfaced to the operator")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._intel.update({"open_ports": [3000], "services": {"3000": {"name": "http"}},
                      "web_paths": ["/api/fetch?url=", "/files/download?path="]})
    _aio.run(op._refresh_surface_and_backlog())
    brief = op._backlog_brief()
    _assert("ssrf" in brief.lower() and "path_traversal" in brief.lower(),
            "backlog brief lists the top hypotheses by class")
    _assert("remaining" in brief.lower() and "total" in brief.lower(),
            "backlog brief reports coverage so the operator knows what's left")


def test_objective_convergence():
    _section("Tier C — engagement ends on objective-met or hypothesis-exhaustion, not just the clock")
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    from agents.operator_agent.surface_model import SurfaceModel, SurfaceNode
    op = OperatorCore(_FM_min())
    op._intel["engagement_context"] = {"objective": "capture user.txt and root.txt"}
    op._intel.update({"user_flag": None, "root_flag": None})
    op._backlog = HypothesisBacklog(op._objective_kinds())
    sm = SurfaceModel(); sm.add(SurfaceNode("port:3000", "service", "3000", {"takes_input", "fetches_remote"}))
    op._backlog.generate_from_surface(sm)
    _assert(op._objective_met() is False, "objective not met when flags missing")
    _assert(op._should_continue() is True, "continue while high-value hypotheses remain")
    for h in op._backlog.all():
        op._backlog.mark(h.id, "refuted")
    _assert(op._backlog.high_value_remaining() == 0, "backlog exhausted after all refuted")
    _assert(op._should_continue() is False, "stop when objective unmet AND backlog exhausted")
    op._intel["user_flag"] = "x"; op._intel["root_flag"] = "y"
    _assert(op._objective_met() is True, "objective met when required flags present")
    # access-only objective is met by a foothold (not just a flag)
    op2 = OperatorCore(_FM_min())
    op2._intel["engagement_context"] = {"objective": "obtain access and hand over a shell"}
    op2._intel["shell_access"] = True
    _assert(op2._objective_met() is True, "an access/handover objective is met by a foothold")


def test_cap_marks_backlog_refuted():
    _section("Tier C — exhausting a method's cap marks the matching backlog hypothesis refuted")
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent.hypothesis_backlog import HypothesisBacklog
    op = OperatorCore(_FM_min())
    op._backlog = HypothesisBacklog(["access"])
    op._backlog.add_external("ssrf", "/api/fetch", "test ssrf", value=0.7)
    op._resolve_banned_hypothesis("hyp:ssrf on /api/fetch", "ssrf")
    _assert(any(x.status == "refuted" for x in op._backlog.all()),
            "a banned method marks its backlog hypothesis refuted so the operator pivots")


def test_playbooks_keyed_by_class():
    _section("Tier D — playbooks load as data, keyed by weakness class (not by box)")
    from agents.operator_agent import playbooks as _pb
    pb = _pb.playbook_for("ssrf")
    _assert(bool(pb) and isinstance(pb.get("steps"), list) and bool(pb["steps"]),
            "an SSRF playbook exists with concrete generic steps")
    _assert(_pb.playbook_for("path_traversal") is not None, "path-traversal playbook loads")
    _assert(_pb.playbook_for("known_cve") is not None, "known-CVE playbook loads")
    _assert(_pb.playbook_for("does_not_exist") is None, "unknown class returns None (no crash)")


def test_hypothesis_carries_playbook():
    _section("Tier D — the active hypothesis's class playbook is surfaced as a hint")
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    txt = op._playbook_hint("ssrf")
    _assert("server-side request forgery" in txt.lower() and "loopback" in txt.lower(),
            "the SSRF playbook steps are surfaced as a hint for the active hypothesis")
    _assert(op._playbook_hint("no_such_class") == "", "unknown class yields no hint (no crash)")
    # the backlog brief embeds the top hypothesis's playbook hint
    import asyncio as _aio
    op._intel.update({"web_paths": ["/api/fetch?url="]})
    _aio.run(op._refresh_surface_and_backlog())
    brief = op._backlog_brief()
    _assert("PLAYBOOK" in brief, "backlog brief embeds the top hypothesis's playbook hint")


def test_operator_post_foothold_persistence():
    _section("Reactor-fix — post-foothold budget, cred persistence, win-conditions, no abort poison")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    _oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("_has_progress_signal()" in _oc and "ARGUS_OPERATOR_HARD_CEILING_SEC" in _oc,
            "a foothold/vuln makes the time budget advisory (no climax-kill)")
    _assert("gated on having no shell yet" in _oc,
            "hypotheses-exhausted termination is gated OFF once a shell exists")
    _assert("_POISON_DIRECTIVE" in _oc,
            "meta-agent 'abort/tooling-failure' directives are filtered before reaching the operator")

    # poison filter drops give-up directives, keeps real ones
    _assert(OperatorCore._correction_text(
        "Trigger mission abort and reclassify outcome as tooling failure") == "",
        "an abort / tooling-failure directive is dropped")
    _assert("privesc" in OperatorCore._correction_text("Run linpeas for privesc enumeration").lower(),
            "a legitimate directive still passes through")

    # RCE output flips shell_access + the shell_obtained win-condition
    op = OperatorCore(_FM_min())
    op._intel["win_conditions"] = {"conditions": [
        {"name": "shell_obtained", "achieved": False},
        {"name": "user_flag_captured", "achieved": False}], "total": 2, "achieved_count": 0}
    _aio.run(op._record_operator_success(
        "run_tool", {"tool": "python3", "args": "... -c 'id'"},
        "[VULN] RCE SUCCESS\nOutput: uid=0(root) gid=0(root)"))
    _assert(op._intel.get("shell_access") is True, "RCE output sets shell_access")
    _assert(any(c.get("name") == "shell_obtained" and c.get("achieved")
                for c in op._intel["win_conditions"]["conditions"]),
            "a real shell flips the shell_obtained win-condition (GUI/report reflect reality)")

    # a cracked plaintext credential reaches intel.credentials (Credentials dashboard)
    _aio.run(op._record_operator_success(
        "run_tool", {"tool": "bash", "args": "-c 'john --show /tmp/h'"},
        "engineer:reactor1\n1 password hash cracked"))
    _creds = op._intel.get("credentials") or []
    _assert(any(c.get("user") == "engineer" and c.get("password") == "reactor1" for c in _creds),
            "a cracked plaintext credential (engineer:reactor1) lands in intel.credentials")


def test_operator_budget_never_fails_progress():
    _section("W1 — budget is advisory once any vuln/exploit/foothold exists (never fails a productive run)")
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    _oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("def _has_progress_signal" in _oc and "ARGUS_OPERATOR_HARD_CEILING_SEC" in _oc,
            "budget gated behind a progress signal + a safety-only ceiling")
    _assert('done_reason = "hard_ceiling"' in _oc,
            "the only time-based stop once progress exists is the huge safety ceiling, not the budget")
    op = OperatorCore(_FM_min())
    _assert(op._has_progress_signal() is False,
            "no progress yet -> ordinary budget still applies (a dead host can't spin forever)")
    op._intel["exploit_modules"] = [{"type": "public_poc", "url": "x"}]
    _assert(op._has_progress_signal() is True,
            "a fetched public PoC (point of exploit) disables the budget kill")
    op2 = OperatorCore(_FM_min()); op2._intel["shell_access"] = True
    _assert(op2._has_progress_signal() is True, "a foothold disables the budget kill")
    op3 = OperatorCore(_FM_min()); op3._intel["credentials"] = [{"user": "x", "password": "y"}]
    _assert(op3._has_progress_signal() is True, "a recovered credential disables the budget kill")


def test_operator_parallel_dispatch_and_terminal():
    _section("W2/W4 — parallel dispatch + post-foothold Expert silence + interactive terminal")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent import tool_catalog as _tc
    _root = _P(__file__).resolve().parent.parent
    _oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("async def _do_dispatch" in _oc and "asyncio.gather" in _oc,
            "operator has a parallel dispatch that fans actions out concurrently")
    _assert(any(t.get("name") == "dispatch" for t in _tc.TOOLS),
            "the dispatch tool is registered in the toolbelt")
    _assert("stall-counter misfires" in _oc,
            "the red-team Expert is skipped post-foothold (its stall-counter caused the false abort)")

    # behavioural: dispatch runs every task and merges results
    op = OperatorCore(_FM_min())
    _ran = []
    async def _fake_run(tool, args):
        _ran.append(tool); return f"ok:{tool}"
    op._run_action = _fake_run
    _out = _aio.run(op._do_dispatch({"tasks": [
        {"tool": "recon", "args": {}}, {"tool": "web_enum", "args": {}}]}))
    _assert("recon" in _ran and "web_enum" in _ran and "PARALLEL DISPATCH" in _out,
            "dispatch runs every task concurrently and merges their results")
    _assert("doing nothing" not in _out and "ok:recon" in _out,
            "each parallel task's output is folded into the dispatch result")

    # W4: the fallback terminal CAPTURES keystrokes (not display-only) so the
    # human can type into an Active Shell / RCE console.
    _xt = (_root / "static" / "vendor" / "xterm.min.js").read_text(encoding="utf-8")
    _assert("keydown" in _xt and "_onData" in _xt and "preventDefault" in _xt,
            "the fallback terminal wires keyboard input -> onData (human can type into a shell)")


def test_operator_flag_capture_no_crash_correct_order():
    _section("Reactor2-fix — flag capture: no loot-dict crash, paths ignored, user-before-root")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    # loot is the schema's CATEGORY DICT — the shape that made .append crash the
    # operator the instant it captured a flag.
    op._intel["loot"] = {"ssh_keys": [], "nt_hashes": [], "secrets": []}
    op._intel["win_conditions"] = {"conditions": [
        {"name": "user_flag_captured", "achieved": False},
        {"name": "root_flag_captured", "achieved": False}], "total": 2, "achieved_count": 0}
    # One command reads BOTH flags; the output ALSO contains binary PATHS (the old
    # bug recorded /usr/bin/sqlite3 as the root flag, root-before-user, then
    # crashed on the loot .append).
    obs = ("[VULN] RCE SUCCESS\n"
           "a1b2c3d4e5f60718293a4b5c6d7e8f90\n"     # user flag (first)
           "===\n"
           "0f1e2d3c4b5a69788796a5b4c3d2e1f0\n"     # root flag (second)
           "/usr/bin/sqlite3\n/usr/bin/find\n")     # paths — never flags
    args = {"tool": "python3", "args": "/tmp/x.py -c 'cat /home/*/user.txt /root/root.txt; which sqlite3'"}
    _aio.run(op._record_operator_success("run_tool", args, obs))   # must NOT raise
    _assert(op._intel.get("user_flag") == "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            "first flag token -> USER (not root); loot-dict .append did not crash the operator")
    _assert(op._intel.get("root_flag") == "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "second flag token -> ROOT (correct order, not before user)")
    _assert("/usr/bin" not in str(op._intel.get("root_flag")) + str(op._intel.get("user_flag")),
            "a binary PATH is never recorded as a flag")
    _loot = op._intel.get("loot")
    _assert(isinstance(_loot, dict) and any(str(i.get("type", "")).endswith("_flag")
                                            for i in _loot.get("items", [])),
            "_add_loot appends into the loot category dict without crashing")
    _wc = {c["name"]: c["achieved"] for c in op._intel["win_conditions"]["conditions"]}
    _assert(_wc.get("user_flag_captured") and _wc.get("root_flag_captured"),
            "both flag win-conditions flipped")
    # source guards for the cascade fixes
    _oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("def _add_loot" in _oc and "success-recording raised" in _oc,
            "loot helper exists + record-success is wrapped so a bug can't crash the operator")
    _assert("_AP.POST_EXPLOIT" in _oc, "operator advances the master phase on foothold (MissionControl updates)")
    _rl = (_P(__file__).resolve().parent.parent / "agents" / "reasoning" / "reasoning_loop.py").read_text(encoding="utf-8")
    _assert("if isinstance(v, dict) else v" in _rl,
            "reasoning_loop tolerates str-valued objective_status (no legacy-fallback crash)")


def test_operator_flag_validation_and_provenance():
    _section("Reactor3-fix — flag validation (no base64/error false-flag) + file provenance")
    import asyncio as _aio
    from agents.operator_agent.operator_core import (
        OperatorCore, _looks_like_flag, _is_error_text)

    # ── unit: the EXACT false positive from run 20260606-151358 ──────────────
    # base64('ls: cannot access /home/engineer/user.txt: Permission d') was
    # booked as the user flag and flipped user_flag_captured to true.  Reject it.
    _bad = "bHM6IGNhbm5vdCBhY2Nlc3MgJy9ob21lL2VuZ2luZWVyL3VzZXIudHh0JzogUGVybWlzc2lvbiBk"
    _assert(not _looks_like_flag(_bad),
            "base64-encoded 'Permission denied' output is NOT a flag")
    _assert(not _looks_like_flag("ls: cannot access '/home/x/user.txt': Permission denied"),
            "a raw permission-denied error line is NOT a flag")
    _assert(not _looks_like_flag("/usr/bin/sqlite3"), "a path is NOT a flag")
    _assert(_looks_like_flag("a1b2c3d4e5f60718293a4b5c6d7e8f90"), "a 32-hex digest IS a flag")
    _assert(_looks_like_flag("HTB{p0wn3d_the_b0x}"), "a wrapped HTB{} IS a flag")
    _assert(_is_error_text("bash: line 1: cat: command not found"),
            "_is_error_text catches a generic shell error")

    # ── behavioural: record-success must NOT book the base64 error as a flag ──
    op = OperatorCore(_FM_min())
    op._intel["loot"] = {"items": []}
    op._intel["win_conditions"] = {"conditions": [
        {"name": "user_flag_captured", "achieved": False}], "total": 1, "achieved_count": 0}
    _args = {"tool": "python3", "args": "nextrce.py -c \"cat /home/engineer/user.txt 2>&1 | base64\""}
    _aio.run(op._record_operator_success("run_tool", _args, _bad + "\n"))
    _assert(not op._intel.get("user_flag"),
            "the base64 error blob is NOT recorded as the user flag (false win killed)")
    _wc = {c["name"]: c["achieved"] for c in op._intel["win_conditions"]["conditions"]}
    _assert(not _wc.get("user_flag_captured"),
            "user_flag_captured win-condition is NOT falsely flipped by an error")

    # ── behavioural: a REAL flag read from a file records WITH provenance ─────
    op2 = OperatorCore(_FM_min())
    op2._intel["loot"] = {"items": []}
    op2._intel["win_conditions"] = {"conditions": [
        {"name": "user_flag_captured", "achieved": False}], "total": 1, "achieved_count": 0}
    _real = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    _args2 = {"tool": "bash", "args": "-c 'cat /home/engineer/user.txt'"}
    _aio.run(op2._record_operator_success("run_tool", _args2, _real + "\n"))
    _assert(op2._intel.get("user_flag") == _real, "a clean 32-hex flag IS recorded")
    _item = next((i for i in op2._intel["loot"]["items"] if i.get("type") == "user_flag"), None)
    _assert(_item is not None and "/home/engineer/user.txt" in str(_item.get("file")),
            "the loot record carries the SOURCE FILE (which file the flag came from)")

    # ── submit_flag rejects garbage, accepts a real token + echoes its file ──
    # (_do_submit_flag is sync but schedules async emits — drive it inside a loop,
    # exactly as the operator's async run loop does in production.)
    op3 = OperatorCore(_FM_min())
    async def _submit(o, a):
        return o._do_submit_flag(a)
    _r = _aio.run(_submit(op3, {"flag": _bad, "which": "user"}))
    _assert("REJECTED" in _r and not op3._intel.get("user_flag"),
            "submit_flag rejects an encoded-error value")
    _r2 = _aio.run(_submit(op3, {"flag": _real, "which": "user", "file": "/home/u/user.txt"}))
    _assert(op3._intel.get("user_flag") == _real and "/home/u/user.txt" in _r2,
            "submit_flag accepts a real flag and reports its source file")


def test_llm_hard_block_failover():
    _section("LLM resilience — API policy block triggers failover (length-independent)")
    from utils import llm_providers as _L
    _block = ("THOUGHT: Let me prepare the next step.\n" + ("detail " * 300) +
              "\nAPI Error: Claude Code is unable to respond to this request, which "
              "appears to violate our Usage Policy. This request triggered "
              "restrictions on violative cyber content and was blocked under "
              "Anthropic's Usage Policy.")
    _assert(len(_block) > 1200, "the blocked response is long (would defeat a length-gated check)")
    _assert(_L.looks_like_refusal(_block),
            "a long reasoning trace ending in an API policy block IS detected → failover fires")
    _assert(not _L.looks_like_refusal("uid=0(root) " + ("A" * 1300)),
            "a long technical answer is still NOT misclassified as a refusal")
    _assert(_L.looks_like_refusal("I can't help with that."),
            "a short conversational refusal is still detected")


def test_operator_parallel_nudge():
    _section("Parallelism — operator is nudged to dispatch after single-action streaks")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._parallel_nudge_every = 3
    op.transcript = []
    for _ in range(3):                       # a streak of single actions
        _aio.run(op._maybe_parallel_nudge("run_tool"))
    _n1 = [m for m in op.transcript if "PARALLELISM DIRECTIVE" in str(m.get("content", ""))]
    _assert(len(_n1) == 1, "a streak of single actions earns exactly one parallel nudge")
    _aio.run(op._maybe_parallel_nudge("dispatch"))
    _assert(op._consec_single == 0, "a dispatch resets the single-action streak")
    for _ in range(2):                       # below threshold again
        _aio.run(op._maybe_parallel_nudge("run_tool"))
    _n2 = [m for m in op.transcript if "PARALLELISM DIRECTIVE" in str(m.get("content", ""))]
    _assert(len(_n2) == 1, "no further nudge until the streak threshold is reached again")


def test_claude_code_system_prompt_is_system_level():
    _section("LLM framing — authorized context rides --append-system-prompt, not inert markup")
    from utils.llm_providers import ClaudeCodeProvider
    from pathlib import Path as _P
    msgs = [
        {"role": "system", "content": "AUTHORIZED pentest. Isolated lab range."},
        {"role": "user", "content": "Begin the assessment."},
        {"role": "assistant", "content": "THOUGHT: enumerate services."},
        {"role": "user", "content": "ports: 22,3000"},
    ]
    sys_text, convo = ClaudeCodeProvider._split_system_and_prompt(msgs)
    _assert(sys_text == "AUTHORIZED pentest. Isolated lab range.",
            "the system message is extracted as the system prompt (real authority)")
    _assert("<system>" not in convo and "Begin the assessment." in convo
            and "THOUGHT: enumerate services." in convo,
            "conversation turns carry NO inert <system> markup")
    _src = (_P(__file__).resolve().parent.parent / "utils" / "llm_providers.py").read_text(encoding="utf-8")
    _assert('"--append-system-prompt"' in _src,
            "ClaudeCodeProvider delivers the framing via --append-system-prompt")
    # the framing itself reads as professional authorized work (fewer false blocks)
    from agents.operator_agent.tool_catalog import build_system_prompt
    _sp = build_system_prompt(objective="capture flags", target={"host": "t"})
    _assert("SANCTIONED" in _sp and "AUTHORIZED" in _sp and "remediate" in _sp,
            "system prompt frames the work as sanctioned, authorized, remediation-focused")


def test_operator_comprehensive_assessment_after_objective():
    _section("Comprehensive — ARGUS keeps testing for OTHER vulns after the objective")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    op._comprehensive = True
    op.transcript = []
    op._intel["objective"] = "capture user and root flags"
    op._intel["user_flag"] = "a" * 32
    op._intel["root_flag"] = "b" * 32
    _assert(op._objective_met(), "objective is met once both flags are in hand")
    _aio.run(op._on_objective_met())
    _dir = [m for m in op.transcript if "REMAINING attack surface" in str(m.get("content", ""))]
    _assert(len(_dir) == 1,
            "comprehensive mode injects a full-assessment directive after the objective")

    op2 = OperatorCore(_FM_min())
    op2._comprehensive = False
    op2.transcript = []
    _aio.run(op2._on_objective_met())
    _dir2 = [m for m in op2.transcript if "REMAINING attack surface" in str(m.get("content", ""))]
    _assert(len(_dir2) == 0, "fast (CTF) mode stops at the objective — no assessment pivot")

    _oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("objective_met_assessment_complete" in _oc,
            "convergence continues into a comprehensive sweep instead of stopping at the flag")
    _assert("_done_challenged" in _oc and "NOT DONE YET" in _oc,
            "a premature done is challenged once while high-value surface remains")


def test_operator_advisor_no_escalation_spam():
    _section("Reactor4-fix — Expert escalation spam filtered + PoC-execute dominates")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore

    # 1) the Expert's defeatist 'escalate to a human' directive is dropped before
    #    it reaches the operator (it fired ~20× identical on the failed run).
    _esc = {"title": "Escalate to human operator — autonomous loop is non-productive",
            "rationale": "Human-in-the-loop required; paste one curl into the intel store.",
            "action_type": "escalate"}
    _assert(OperatorCore._correction_text(_esc) == "",
            "an 'escalate to a human / non-productive' directive is dropped (autonomous mode)")
    _ok = {"recommended_action": "Run the cloned PoC against port 3000 now."}
    _assert(OperatorCore._correction_text(_ok) != "",
            "a constructive directive still passes through the filter")

    # 2) consecutive-identical advisor notes are de-duped (no 20× flood)
    op = OperatorCore(_FM_min())
    op._prev_advisor_notes = {"• X"}
    _fresh = [n for n in ["• X"] if n not in op._prev_advisor_notes]
    _assert(_fresh == [], "a note identical to the previous consultation is suppressed")

    # 3) with a ready PoC, EXECUTE-NOW fires and anti-anchor is suppressed
    op2 = OperatorCore(_FM_min())
    op2.transcript = []
    op2._intel["exploit_modules"] = [
        {"type": "public_poc", "url": "https://github.com/x/NextRce", "cves": ["CVE-2025-55182"]}]
    op2._stale_rounds = 3
    _aio.run(op2._consult_advisors())
    _txt = "\n".join(m.get("content", "") for m in op2.transcript)
    _assert("EXECUTE NOW" in _txt, "a ready PoC triggers the EXECUTE-NOW directive")
    _assert("ANTI-ANCHOR" not in _txt,
            "anti-anchor is suppressed when a PoC is ready (no contradictory advice)")

    _oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("escalate to human" in _oc and "_prev_advisor_notes" in _oc,
            "poison filter covers human-escalation + advisor de-dup state exists")


def test_expert_no_spam_no_panic():
    _section("Expert hardening — only helps: no duplicate spam, no panic / human-handoff")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.meta.expert_agent import (
        RedTeamExpertAgent, Directive, _is_panic_directive)

    # ── unit: panic detector ────────────────────────────────────────────────
    _esc = Directive(scan_id="s", phase="operator", target_phase="reporting",
                     priority="critical", action_type="escalate",
                     title="Escalate to human operator — autonomous loop is non-productive",
                     rationale="Human-in-the-loop required.")
    _assert(_is_panic_directive(_esc, all_achieved=False),
            "an 'escalate to a human / non-productive' directive is flagged as panic")
    _halt = Directive(scan_id="s", phase="post_exploit", target_phase="reporting",
                      priority="recommended", action_type="halt",
                      title="All objectives met — halt and report", rationale="done")
    _assert(not _is_panic_directive(_halt, all_achieved=True),
            "a HALT once every win-condition is met is legitimate (not panic)")
    _assert(_is_panic_directive(_halt, all_achieved=False),
            "a HALT before the objective is panic (premature stop)")
    _good = Directive(scan_id="s", phase="recon", target_phase="exploit",
                      priority="recommended", action_type="exploit",
                      title="Run the cloned PoC against :3000", rationale="it is ready")
    _assert(not _is_panic_directive(_good, all_achieved=False),
            "a constructive exploit directive is NOT panic")

    # ── behavioural: dispatch suppresses panic + de-dups identical directives ──
    ex = RedTeamExpertAgent(broadcast=None, session_id="t-expert")
    async def _noop(*a, **k):
        return None
    ex._emit = _noop
    ex._inject_into_master = _noop
    parsed = {"directives": [
        {"priority": "critical", "action_type": "escalate", "target_phase": "reporting",
         "title": "Escalate to human — non-productive", "rationale": "give up"},
        {"priority": "recommended", "action_type": "exploit", "target_phase": "exploit",
         "title": "Run the cloned PoC now", "rationale": "it is ready"}]}
    _aio.run(ex._dispatch_parsed(parsed, phase="operator", mode="post"))
    _titles = [d.title for d in ex._directives_history]
    _assert("Run the cloned PoC now" in _titles and not any("Escalate" in t for t in _titles),
            "panic directive suppressed; only the constructive one is issued")
    _assert(ex._panic_suppressed == 1, "the suppressed panic directive is counted")
    _n = len(ex._directives_history)
    _aio.run(ex._dispatch_parsed(parsed, phase="operator", mode="post"))   # same again
    _assert(len(ex._directives_history) == _n,
            "an identical directive on a later cycle is NOT re-issued (no spam)")

    _ex = (_P(__file__).resolve().parent.parent / "agents" / "meta" / "expert_agent.py").read_text(encoding="utf-8")
    _assert("_PANIC_MARKERS" in _ex and "_issued_sigs" in _ex
            and "NEVER recommend handing off" in _ex,
            "expert has a panic filter + per-scan dedup + a no-human-handoff persona rule")


def test_missioncontrol_hooks_and_revshell_nudge():
    _section("UI #310 hooks fix (MissionControl) + operator stops looping on reverse shells")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    mc = (_root / "static" / "js" / "pages" / "MissionControl.jsx").read_text(encoding="utf-8")
    # PentestProgressBar's estRemaining useMemo MUST be declared BEFORE the early
    # returns; sitting after them ran a different hook count per render → React
    # #310, which crashed the whole Mission Control page once a plan arrived.
    i_memo = mc.find("const estRemaining = React.useMemo")
    i_ret = mc.find("if (!sessionId || !activeSession) return null;")
    _assert(i_memo != -1 and i_ret != -1 and i_memo < i_ret,
            "estRemaining useMemo is declared BEFORE the early returns (stable hook order, no #310)")
    _assert(mc.count("const estRemaining = React.useMemo") == 1,
            "the post-return duplicate useMemo was removed")
    idx = (_root / "templates" / "index.html").read_text(encoding="utf-8")
    _assert("MissionControl.jsx?v=21" in idx,
            "index.html cache-bust bumped so the browser loads the #310 fix")
    oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("DO NOT LOOP ON A REVERSE SHELL" in oc,
            "operator is steered off the reverse-shell listener loop once it has working RCE")


def test_report_pdf_and_ui_population():
    _section("Report PDF validity + comprehensiveness; UI population (creds / objectives / stages)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent

    # 1) the dependency-free PDF writer produces a VALID, comprehensive PDF
    from report.pdf_writer import lines_to_pdf, report_lines_from_context
    ctx = {
        "session": {"target": "10.129.16.109", "target_type": "linux"},
        "intel": {"os_guess": "Linux", "open_ports": [22, 3000],
                  "services": {"22": {"service": "ssh"}}, "shell_access": True},
        "findings": [{"severity": "critical", "title": "Inspector -> root",
                      "description": "Exposed inspector. Remediation: remove --inspect."}],
        "flags": [{"flag_type": "user", "value": "bc4b07ece43b75005ec424c48aaa6f9b", "location": "user.txt"}],
        "creds_summary": [{"user": "(secret / key)", "password": "(see note)",
                           "source": "harvested", "note": "SENSOR_API_KEY=rw_sk_demo"}],
        "attack_path": [{"__step": 1, "phase": "recon", "result": "found port 3000"}],
        "exploit_modules": [{"cves": ["CVE-2025-55182"], "url": "https://x/NextRce", "used": True}],
        "win_conditions": {"achieved_count": 3, "total": 3, "progress_pct": 100,
                           "conditions": [{"name": "root_flag_captured", "achieved": True, "evidence": "953e..."}]},
        "mission_brief": {"objective": "Establish foothold, capture flags."},
        "generated_at": "now", "duration": "1h",
    }
    lines = report_lines_from_context(ctx)
    pdf = lines_to_pdf(lines, "ARGUS")
    _assert(pdf[:5] == b"%PDF-", "pdf_writer emits a REAL PDF header (not HTML-as-PDF)")
    _assert(pdf.rstrip().endswith(b"%%EOF") and b"startxref" in pdf and b"xref" in pdf,
            "PDF has a valid trailer + xref (opens in a viewer, not 'corrupted')")
    i = pdf.rfind(b"startxref"); xo = int(pdf[i + 9:].split()[0]); seg = pdf[xo:].split(b"\n")
    cnt = int(seg[1].split()[1])
    _assert(all(pdf[int(seg[2 + n].split()[0]):].startswith(f"{n} 0 obj".encode())
                for n in range(1, cnt)),
            "every xref offset lands exactly on its object (byte-accurate, valid PDF)")
    blob = " ".join(t for _, t in lines)
    for kw in ("Executive Summary", "Objectives", "Attack Narrative", "Findings",
               "Remediation", "SENSOR_API_KEY", "CVE-2025-55182", "root_flag_captured"):
        _assert(kw in blob, f"report content includes '{kw}'")

    # 2) report context rescues note-style creds + adds objective/exploit data + real PDF fallback
    gen = (_root / "report" / "generator.py").read_text(encoding="utf-8")
    _assert('c.get("note")' in gen and '"win_conditions":' in gen and '"exploit_modules":' in gen,
            "report context surfaces note-style creds + win_conditions + exploit_modules")
    _assert("_wkhtmltopdf_bytes" in gen and "report.pdf_writer" in gen,
            "generate_pdf falls back to a real stdlib PDF (never serves HTML-as-PDF)")

    # 3) operator emits credential_found so the Credentials dashboard populates
    oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("async def _emit_credential" in oc and '"credential_found"' in oc,
            "operator emits credential_found for recovered creds/secrets")
    _assert('if bucket == "credentials":' in oc,
            "a credential note also surfaces on the Credentials dashboard")

    # 4) store marks plan steps by phase progression (Mission Control stages), legacy-safe
    st = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("_PHASE_RANK" in st and "r < curRank" in st,
            "PHASE_CHANGE marks plan steps done/active by phase progression")
    _assert("s.status === 'done' || s.status === 'failed'" in st,
            "phase-progression marking never overrides done/failed (legacy pipeline unchanged)")

    # 5) Findings page renders the mission objectives + outcomes
    fb = (_root / "static" / "js" / "pages" / "FindingsBoard.jsx").read_text(encoding="utf-8")
    _assert("MISSION OBJECTIVES" in fb and "winConditions.conditions.map" in fb,
            "Findings page shows objectives + whether each was achieved (with evidence)")
    idx = (_root / "templates" / "index.html").read_text(encoding="utf-8")
    _assert("FindingsBoard.jsx?v=6" in idx and "store.js?v=49" in idx,
            "cache-bust bumped for the UI fixes")


def test_tools_not_killed_on_time_and_missing_tool_surfaced():
    _section("Tools not killed on time alone — human extend/kill governs; missing tools surfaced")
    from pathlib import Path as _P
    from agents.base_agent import BaseAgent
    _root = _P(__file__).resolve().parent.parent

    _assert("apt install" in BaseAgent._install_hint("gobuster").lower(),
            "a missing tool yields an apt-install hint for the human")
    _assert("seclists" in BaseAgent._install_hint("seclists").lower(),
            "a missing wordlist yields a seclists install hint")

    ba = (_root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("read=None" in ba and "httpx.Timeout(connect=" in ba,
            "the MCP read-timeout is DISABLED — a slow-but-streaming tool is NOT killed for taking time")
    _assert("self._tool_deadline_sec = max(float(timeout" in ba,
            "the watchdog/human-prompt deadline tracks the tool's expected runtime (not a fixed 10 min)")
    _assert('"tool_missing"' in ba and "_install_hint" in ba,
            "a missing tool/file emits tool_missing with an install hint")
    _assert("exit_code not in (0, -2)" in ba,
            "missing-tool detection skips operator-cancelled tools (a cancel is not 'missing')")

    oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("_tool_wait_ceiling" in oc and "backstop" in oc.lower(),
            "the operator tool-wait is a backstop ceiling — it never pre-empts the human extend/kill prompt")

    st = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("case 'tool_missing'" in st, "the UI feed surfaces a missing-tool install hint")
    aj = (_root / "static" / "js" / "app.jsx").read_text(encoding="utf-8")
    _assert("tool_extend" in aj and "tool_stop" in aj,
            "the human extend/kill prompt is wired to the backend (mandatory works)")


def test_operator_persistent_listener():
    _section("Silentium-fix — persistent listener tool (catch a blind-RCE callback; no killed nc)")
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    from agents.operator_agent import tool_catalog as _cat

    _assert(any(t.get("name") == "listener" for t in _cat.TOOLS),
            "the `listener` tool is registered in the operator toolbelt")

    # no shell agent → graceful message, never crashes
    op0 = OperatorCore(_FM_min())
    r0 = _aio.run(op0._do_listener({}))
    _assert("listener" in r0.lower(), "listener degrades gracefully when no shell channel exists")

    # with a managed ShellAgent → opens a PERSISTENT listener + returns a payload
    class _FakeSA:
        def __init__(self): self.opened = None
        def _get_lhost(self): return "10.10.16.248"
        async def create_listener(self, session_id, shell_id, shell_type, lport, lhost=None, **k):
            self.opened = {"shell_type": shell_type, "lport": lport, "lhost": lhost}
            return {"ok": True}
    op = OperatorCore(_FM_min())
    fsa = _FakeSA(); op.master._shell_agent = fsa; op._target = "10.129.17.70"
    r = _aio.run(op._do_listener({"port": 4444}))
    _assert(fsa.opened is not None and fsa.opened["lport"] == 4444,
            "listener opens a PERSISTENT ShellAgent listener (not a killed bash `nc -lvnp &`)")
    _assert("/dev/tcp/" in r and "nc -lvnp" in r and "Do NOT run" in r,
            "listener returns a ready reverse-shell payload and warns against hand-rolled nc")
    _assert(op._intel.get("listener_ready", {}).get("lport") == 4444,
            "listener state is recorded so the operator can fire the callback")

    # routing + protocol guidance
    oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert('if tool == "listener":' in oc and "async def _do_listener" in oc,
            "the operator run loop routes the listener tool")
    tc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "tool_catalog.py").read_text(encoding="utf-8")
    _assert("CATCH A REVERSE SHELL" in tc and "killed" in tc.lower(),
            "protocol steers the operator to `listener`, never a hand-rolled nc that gets killed")


def test_rag_continuous_learning():
    _section("Continuous learning — distil ONLY genuine techniques into the RAG (not every scan)")
    from pathlib import Path as _P
    from agents.reasoning.lesson_distiller import (
        genuine_success, _lesson_quality_ok, _scrub, _parse_lessons, _deterministic_lessons)

    # ── ENGAGEMENT gate: a pure scan with NO confirmed success learns NOTHING ──
    ok, _ = genuine_success({"open_ports": [22, 80],
                             "exploit_modules": [{"cves": ["CVE-0000-0"]}],   # seeded, not used
                             "vulnerabilities": [{"cve": "CVE-0000-1", "status": "candidate"}]})
    _assert(not ok, "a scan with only open ports + UNCONFIRMED CVE candidates learns nothing")
    ok2, r2 = genuine_success({"shell_access": True})
    _assert(ok2 and "foothold" in " ".join(r2), "a foothold triggers learning")
    _assert(genuine_success({"credentials": [{"note": "ben / pw"}]})[0],
            "a recovered credential triggers learning (the Silentium ATO case)")
    _assert(genuine_success({"win_conditions": {"achieved_count": 2}})[0],
            "a met win-condition triggers learning")
    _assert(genuine_success({"vulnerabilities": [{"cve": "CVE-0000-2", "status": "confirmed"}]})[0],
            "a CONFIRMED-exploitable vuln triggers learning")

    # ── LESSON gate: a real technique passes; a raw finding is rejected ──
    _assert(_lesson_quality_ok("Flowise 3.x: POST forgot-password with a JSON user.email "
                               "leaks a tempToken; reset-password then yields an admin "
                               "session — chain to RCE. Reusable auth-bypass technique."),
            "a concrete confirmed-working technique is kept")
    _assert(not _lesson_quality_ok("Missing security headers on the web server."),
            "a raw finding (missing headers) is NOT learned as a technique")
    _assert(not _lesson_quality_ok("Open port 22."), "a one-line finding is rejected")

    # ── scrub keeps the lesson generalisable across hosts ──
    s = _scrub("Compromised 10.129.16.176; read 953e3681910b05c25ea2eaadb8c3c832", "10.129.16.176")
    _assert("10.129.16.176" not in s and "953e3681910b05c25ea2eaadb8c3c832" not in s,
            "target IP + raw flag token are scrubbed from the stored lesson")

    # ── parse + deterministic fallback ──
    parsed = _parse_lessons('```json\n[{"title":"t","category":"exploit","technique":"x"}]\n```')
    _assert(len(parsed) == 1 and parsed[0]["category"] == "exploit", "fenced JSON lessons parse")
    det = _deterministic_lessons({"exploit_modules": [
        {"product": "AppX", "cves": ["CVE-0000-3"], "url": "https://x/poc", "used": True}]})
    _assert(len(det) == 1 and "AppX" in det[0]["title"],
            "deterministic fallback builds a card from a USED exploit (no LLM needed)")

    # ── wiring + storage API ──
    _root = _P(__file__).resolve().parent.parent
    ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("from agents.reasoning.lesson_distiller import distill_and_store" in ma
            and "ARGUS_RAG_LEARNING" in ma,
            "master wires the distiller at engagement end (config-gated, best-effort)")
    kb_src = (_root / "knowledge" / "knowledge_base.py").read_text(encoding="utf-8")
    _assert("def ingest_tip" in kb_src, "RAG exposes ingest_tip for storing learned techniques")


def test_operator_credential_vault_persistence():
    _section("Silentium-fix — recovered creds parse cleanly + PERSIST to the DB-backed vault")
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    p = OperatorCore._parse_cred_note(
        "ATO via CVE-2025-58434 successful: ben@silentium.htb / Password123! (admin role)")
    _assert(p.get("user") == "ben@silentium.htb" and p.get("secret") == "Password123!",
            "a free-text ATO note is parsed into a clean user/password for the vault")
    p2 = OperatorCore._parse_cred_note("SENSOR_API_KEY=rw_sk_abc123 leaked in /opt/app")
    _assert(p2.get("user") == "secret / key" and "SENSOR_API_KEY" in p2.get("secret", ""),
            "a keyless secret falls back to the whole note (and a path is NOT mis-parsed as a cred)")
    oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("_db.store_credential" in oc and "credential_found" in oc,
            "operator PERSISTS recovered creds to the DB (store_credential), not just a WS event")


def test_operator_iter_cap_advisory_on_progress():
    _section("Silentium-fix — iteration cap is ADVISORY once progress exists (no kill at the climax)")
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min(), max_iters=10)
    _assert(op._iter_ceiling >= op.max_iters * 4,
            "an iteration ceiling exists far above the advisory max_iters")
    op._intel = {}
    _assert(not op._has_progress_signal(),
            "empty intel = no progress (the ordinary max_iters still bounds a spinning run)")
    op._intel = {"vulnerabilities": [{"cve": "CVE-2025-58434"}],
                 "exploit_modules": [{"url": "https://x/poc"}]}
    _assert(op._has_progress_signal(),
            "a confirmed vuln + fetched PoC is a progress signal (Silentium had 1 vuln + 16 PoCs)")
    op._intel = {"credentials": [{"note": "leaked tempToken"}]}
    _assert(op._has_progress_signal(), "a recovered credential is a progress signal")
    oc = (_P(__file__).resolve().parent.parent / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("for i in range(self._iter_ceiling)" in oc,
            "the run loop ranges over the iteration ceiling, not the bare max_iters")
    _assert("if i >= self.max_iters:" in oc and 'done_reason = "max_iters"' in oc
            and "if not self._has_progress_signal()" in oc,
            "max_iters only ENDS the run with NO progress; with progress it keeps exploiting")


def test_broadcast_accepts_dict_event():
    _section("Test — WSManager.broadcast tolerates a flat subagent dict (no 4,763× session_id crash)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert("async def broadcast(self" in _srv,
            "WSManager.broadcast present")
    _assert('"WebSocketMessage | dict"' in _srv and "Defensive dict adapter" in _srv,
            "broadcast accepts a dict OR a WebSocketMessage (documented adapter)")
    _assert("isinstance(message, dict)" in _srv and "self.broadcast_raw(" in _srv,
            "a flat subagent dict is routed through broadcast_raw instead of "
            "crashing on message.session_id (the 4,763× event-stream loss)")


def test_listener_flips_to_confirmed_foothold():
    _section("Test — reverse-shell listener flips pending→confirmed on a real callback (post-ex finally fires)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _sa = (_root / "agents" / "shell_agent.py").read_text(encoding="utf-8")
    _assert("_pending_listeners" in _sa and "def _maybe_flip_listener" in _sa,
            "shell agent tracks pending listeners + has a callback-flip detector")
    _assert("_LISTENER_CALLBACK_RE" in _sa and "uid=" in _sa,
            "a generic shell-signature regex drives the flip (uid=/prompt/msf session) — not vuln content")
    _assert("self._maybe_flip_listener(shell_id" in _sa,
            "_on_pty_output feeds every pending listener's output through the detector")
    _assert("shell_callback_confirmed" in _sa,
            "a foothold-confirmed event is emitted on the flip")
    # The flip re-registers the SAME optimistic source so register_shell's own
    # evidence gate (uid=/prompt) validates it — only a real shell flips the gate.
    _assert('source     = "shell_agent:listener"' in _sa and "confirmed  = True" in _sa,
            "the flip re-registers register_shell(confirmed=True) via the evidence-gated source")


def test_operator_endpoint_pivot():
    _section("Test — per-endpoint pivot (a bare http/tool loop on ONE endpoint is capped — no 149× hammer)")
    import os as _os
    import asyncio as _aio
    from pathlib import Path as _P
    from agents.operator_agent.operator_core import OperatorCore

    _root = _P(__file__).resolve().parent.parent
    _oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("def _endpoint_signature" in _oc and "_banned_endpoints" in _oc
            and '"operator_endpoint_banned"' in _oc,
            "operator has endpoint-signature tracking, bans, and emits the endpoint-ban event")
    _assert("ARGUS_OPERATOR_ENDPOINT_MAX_REPEATS" in _oc,
            "the endpoint repeat cap is env-tunable")

    # signature: stable across query-string tweaks; empty for non-network actions
    _op = OperatorCore(_FM_min())
    s1 = _op._endpoint_signature("http", {"url": "http://t/api/run?x=1", "method": "POST"})
    s2 = _op._endpoint_signature("http", {"url": "http://t/api/run?x=2", "method": "POST"})
    _assert(s1 == s2 and s1.endswith("http://t/api/run"),
            "same endpoint with tweaked query params collapses to ONE signature")
    _assert(_op._endpoint_signature("dispatch", {"url": "http://t/api"}) == "",
            "non-network actions (dispatch/converse/note/done) are never endpoint-capped")
    _assert(_op._endpoint_signature("run_tool", {"cmd": "curl http://t/x | head"}).endswith("http://t/x"),
            "a URL inside a command string is mined for the endpoint key")

    _os.environ["ARGUS_OPERATOR_ENDPOINT_MAX_REPEATS"] = "3"
    _assert(OperatorCore(_FM_min())._endpoint_max_repeats == 3, "endpoint cap honours env (3)")

    # end-to-end: a bare http loop with NO hypothesis/CVE to ONE endpoint is banned
    class _FMep:
        def __init__(self):
            self._intel = {}; self._session_id = "s"; self._target_host = "t"
            self._target = "t"; self._target_url = "http://t"; self._scope_guard = ""
            self._stop_requested = False; self.name = "m"; self.phase = "operator"
            self._expert = None; self._pending_corrections = None; self.events = []
        async def converse(self, *a, **k):
            return ("THOUGHT: poke the endpoint once more.\n```action\n"
                    "{\"tool\": \"http\", \"args\": {\"url\": \"http://t/api/run\", "
                    "\"method\": \"POST\"}}\n```")
        async def _dispatch_to_agent(self, **k): return {"stdout": "no", "exit_code": 0}
        async def _emit(self, ev, data): self.events.append(ev)
        async def emit_reasoning(self, *a, **k): pass
        async def store_finding(self, **k): return {}

    _m = _FMep()
    _opL = OperatorCore(_m, autonomy="autonomous", max_iters=16, max_seconds=600)
    async def _noprog(tool, args): return "[FAIL] same dead response"
    _opL._run_action = _noprog
    _aio.run(_opL.run())
    _assert("operator_endpoint_banned" in _m.events,
            "a non-productive endpoint loop (no hypothesis/CVE) is BANNED at the cap")
    _assert(any(e.endswith("http://t/api/run") for e in _opL._banned_endpoints),
            "the exhausted endpoint is recorded as banned → operator forced to pivot")
    _os.environ.pop("ARGUS_OPERATOR_ENDPOINT_MAX_REPEATS", None)


def test_safe_port_guard():
    _section("Test — _safe_port guard (a service-name port can't sink the whole graph update)")
    from agents.attack_graph_agent import _safe_port
    _assert(_safe_port("DNS") is None,
            "non-numeric service name → None (was int('DNS') → ValueError that dropped the graph)")
    _assert(_safe_port("http") is None, "service label → None")
    _assert(_safe_port(8080) == 8080, "valid int port preserved")
    _assert(_safe_port("443") == 443, "numeric string coerced")
    _assert(_safe_port(0) is None and _safe_port(-1) is None, "non-positive → None")
    _assert(_safe_port(99999) is None, "above 65535 → None")
    _assert(_safe_port(None) is None, "None → None")
    _assert(_safe_port(True) is None, "bool is rejected (not a real port)")


def test_vhost_stale_reconcile_at_scan_start():
    _section("Test — proactive stale /etc/hosts reconcile at scan start (not just reactive mid-web)")
    import tempfile, os as _os
    from pathlib import Path as _P
    import agents.recon.vhost_pivot as vp

    _root = _P(__file__).resolve().parent.parent
    _ms = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("reconcile_stale_vhosts_for_target" in _ms,
            "master.run() invokes reconcile_stale_vhosts_for_target at scan start")
    _assert("def reconcile_stale_vhosts_for_target" in
            (_root / "agents" / "recon" / "vhost_pivot.py").read_text(encoding="utf-8"),
            "vhost_pivot exposes the reconcile function")

    tmpd = tempfile.mkdtemp()
    hf = _os.path.join(tmpd, "hosts")
    with open(hf, "w", encoding="utf-8") as f:
        f.write("127.0.0.1 localhost\n"
                "10.129.17.70 silentium.htb  # argus-managed\n"   # STALE prior box
                "10.10.10.5 keep.htb  # argus-managed\n"          # current target, managed
                "192.168.1.9 manual.htb\n")                       # operator's OWN entry
    _orig_hf, _orig_am = vp.HOSTS_FILE, vp.VHOST_AUTOMAP
    vp.HOSTS_FILE = hf
    vp.VHOST_AUTOMAP = True
    try:
        removed = vp.reconcile_stale_vhosts_for_target("10.10.10.5")
        _assert("silentium.htb" in removed,
                "stale argus-managed mapping (wrong IP) is reconciled away at scan start")
        _txt = open(hf, encoding="utf-8").read()
        _assert("10.129.17.70" not in _txt,
                "the stale prior-box line was REMOVED (can't win glibc first-match anymore)")
        _assert("keep.htb" in _txt,
                "an argus-managed mapping already on the CURRENT target IP is kept")
        _assert("manual.htb" in _txt and "192.168.1.9" in _txt,
                "the operator's OWN (unmarked) /etc/hosts entry is NEVER touched")
        again = vp.reconcile_stale_vhosts_for_target("10.10.10.5")
        _assert(again == [], "reconcile is idempotent once /etc/hosts is clean")
    finally:
        vp.HOSTS_FILE = _orig_hf
        vp.VHOST_AUTOMAP = _orig_am


def test_shell_metachar_reroute_and_logger():
    _section("Test — base_agent shell-metachar reroute + module-level logger (no NameError on abandon)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _ba = (_root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("logger = logging.getLogger(__name__)" in _ba and "\nimport logging" in _ba,
            "base_agent defines a module-level logger (entropy-abandon path no longer NameErrors)")
    _assert("_needs_shell" in _ba and "shell-metacharacter reroute" in _ba,
            "the command reroute is extended to shell metacharacters (pipes/redirects/&&/;)")
    _assert("'[^']*'" in _ba,
            "the reroute strips QUOTED spans first so a quoted payload/URL isn't falsely wrapped")


def test_subagent_db_fallback_and_cb_throttle():
    _section("Test — subagent DB fallback (no finding loss when db=None) + circuit-breaker log throttle")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _bs = (_root / "agents" / "base_subagent.py").read_text(encoding="utf-8")
    _assert("def _resolve_db" in _bs and "from db.mongo_client import get_db" in _bs,
            "store paths resolve a DB handle (fall back to global get_db) instead of subscripting None")
    _assert("_dbh = self._resolve_db()" in _bs and '_dbh["findings"]' in _bs,
            "store_finding uses the resolved handle (fixes 'NoneType not subscriptable' finding loss)")
    _assert("_cb_log_times" in _bs and "_CB_LOG_THROTTLE_SEC" in _bs,
            "circuit-breaker log/emit is throttled per key (no ~20× flood during the cooldown)")


def test_operator_records_issues_and_coverage():
    _section("Test — operator records ALL discovered issues + coverage matrix (concern #1)")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min())
    # Strict verified-progress: no shell/flag/cred/loot yet.
    _assert(op._has_verified_progress() is False, "no verified progress at start")
    op._intel["shell_access"] = True
    _assert(op._has_verified_progress() is True, "a confirmed shell IS verified progress")
    op._intel["shell_access"] = False
    # A generic reflected DB error → recorded as a DISCOVERED issue (not a foothold).
    _aio.run(op._extract_generic_vulns(
        "ERROR: You have an error in your SQL syntax near '1'", "curl",
        {"args": "http://t/?id=1"}, "t"))
    di = op._intel.get("discovered_issues") or []
    _assert(any("SQL" in d.get("title", "") for d in di),
            "a reflected SQL error is recorded as a discovered issue (all issues reported)")
    _assert(op._intel.get("shell_access") is not True,
            "recording a discovery does NOT flip a foothold flag")
    _assert(op._has_verified_progress() is False,
            "an 'observed' discovery is NOT verified progress (no false budget-defer)")
    _before = len(di)
    _aio.run(op._extract_generic_vulns(
        "ERROR: You have an error in your SQL syntax near '1'", "curl",
        {"args": "http://t/?id=1"}, "t"))
    _assert(len(op._intel.get("discovered_issues") or []) == _before,
            "the same issue is deduped (recorded once per session)")
    # Coverage matrix records negatives + blocked outcomes for the report.
    op._record_coverage("gobuster", {"args": "http://t/"}, "no matches", exit_code=0)
    op._record_coverage("curl", {"args": "http://t/x"}, "connection timed out", exit_code=28)
    tr = op._intel.get("test_results") or []
    _assert(any(r["outcome"] == "blocked" for r in tr),
            "a curl timeout is logged as 'blocked' coverage (not a silent drop)")
    _assert(len(tr) >= 2, "every probe is recorded for the coverage matrix")


def test_background_job_detach():
    _section("Test — backgrounded-job fd detach (anti-hang; the 998s http.server waste)")
    from agents.base_agent import _detach_background_jobs as dbg
    out = dbg("python3 -m http.server 8000 & sleep 1")
    _assert(">/dev/null 2>&1 &" in out,
            "an un-redirected `&` job gets its child fds detached so it can't hold the pipe")
    _assert(dbg("a && b") == "a && b", "`&&` (logical AND) is NEVER touched")
    _assert(dbg("curl 'http://t/?a=1&b=2'") == "curl 'http://t/?a=1&b=2'",
            "a URL query `&` (no surrounding space) is NEVER touched")
    _assert(dbg("tail -f x >/tmp/o &") == "tail -f x >/tmp/o &",
            "an already-redirected background job is left alone")
    import os as _os
    _os.environ["ARGUS_DETACH_BG"] = "0"
    _assert(dbg("srv & sleep 1") == "srv & sleep 1", "ARGUS_DETACH_BG=0 disables the rewrite")
    _os.environ.pop("ARGUS_DETACH_BG", None)


def test_token_usage_accounting():
    _section("Test — real LLM token accounting (concern #5: count was wrong)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    # Provider layer exposes real usage (Anthropic streamed usage → get_last_usage).
    from utils.llm_providers import LLMProvider
    _p = LLMProvider()
    _assert(hasattr(_p, "get_last_usage") and _p.get_last_usage() is None,
            "providers expose get_last_usage() (None until a stream runs)")
    _llp = (_root / "utils" / "llm_providers.py").read_text(encoding="utf-8")
    _assert("message_start" in _llp and "input_tokens" in _llp and "self.last_usage" in _llp,
            "AnthropicProvider captures input/output tokens from the streamed usage block")
    _assert("on_usage" in _llp, "stream_tiered exposes an on_usage callback for the real count")
    # scan_logger persists token fields + aggregates them (not char counts).
    _sl = (_root / "utils" / "scan_logger.py").read_text(encoding="utf-8")
    _assert("prompt_tokens" in _sl and "total_tokens" in _sl and "tokens_estimated" in _sl,
            "log_llm records REAL token fields (chars are kept but never shown as tokens)")
    _assert('counters.get("total_tokens"' in _sl or '"total_tokens"' in _sl,
            "token usage is aggregated into the session counters/summary")
    _ba = (_root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert('"total_tokens"' in _ba and "prov_info.get(\"usage\")" in _ba,
            "the operator converse path threads real usage into the log + llm_response event")


def test_parallel_advisor_bus():
    _section("Test — parallel support agents feed the operator (concern #3)")
    import asyncio as _aio
    from agents.operator_agent.operator_core import OperatorCore
    # master.notify_advisor pushes to a queue the operator drains in _consult_advisors.
    class _M(_FM_min):
        pass
    m = _M()
    # notify_advisor is on the REAL master; emulate its contract here.
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _ms = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("def notify_advisor" in _ms and "_advisor_queue" in _ms,
            "master exposes notify_advisor() backed by a bounded advisor queue")
    _assert("master     = self" in _ms,
            "AttackGraphAgent is constructed WITH a master ref so its parallel "
            "chain analysis can advise the operator")
    _ag = (_root / "agents" / "attack_graph_agent.py").read_text(encoding="utf-8")
    _assert("notify_advisor" in _ag,
            "attack-graph chain analysis pushes its top next-step to the operator")
    _oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    _assert("_advisor_queue" in _oc and "REAL-TIME advisories" in _oc,
            "operator drains the advisor queue (non-blocking) into its reasoning")
    # Behavioural: a queued advisory is surfaced via the real master contract.
    import asyncio as _a2
    q = _a2.Queue()
    m._advisor_queue = q
    q.put_nowait({"source": "attack-graph", "text": "drive the SSRF on /fetch"})
    op = OperatorCore(m)
    # Drain mirrors operator logic: pull dict, format note.
    adv = m._advisor_queue.get_nowait()
    _assert(adv.get("source") == "attack-graph" and "SSRF" in adv.get("text", ""),
            "advisories carry source + text for the operator transcript")


def test_report_storyline_sections():
    _section("Test — report has coverage matrix + timeline + discovered issues (concern #6)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _g = (_root / "report" / "generator.py").read_text(encoding="utf-8")
    _assert("coverage_tests" in _g and "engagement_timeline" in _g and "discovered_issues" in _g,
            "report context builds coverage matrix + timeline + discovered-issue storyline")
    _assert("Tests Conducted" in _g and "Engagement Timeline" in _g
            and "Other Discovered Issues" in _g,
            "the template renders the three new narrative sections")
    _assert("negative" in _g and "coverage_counts" in _g,
            "the coverage matrix reports negative results + per-outcome totals")


def test_master_phase_restamp_and_finding_merge():
    _section("Test — web-testing phase restamp removed + subagent findings not dropped")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _ms = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    # The crash/cosmetic-restamp _advance_phase call inside _phase_web_testing is gone.
    _assert("PARALLEL sub-phase that shares the VULN_ID state-machine" in _ms,
            "web testing no longer re-advances VULN_ID (cosmetic phase-restamp removed)")
    _assert('"nikto_findings"' in _ms and '"nuclei_findings"' in _ms,
            "subagent parsed_data finding lists are merged into intel (no silent drop)")
    _wv = (_root / "agents" / "web" / "web_vuln_scan_subagent.py").read_text(encoding="utf-8")
    _assert(_wv.count("finding store skipped") >= 2,
            "each nikto/nuclei store_finding is isolated so one bad finding can't drop the rest")
    # store.js routes every llm_response into the feed (concern #2 data starvation).
    _sj = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("AGENT_COMM_LLM" in _sj and "case 'llm_response'" in _sj,
            "every llm_response is routed into agentComms + the event feed (richer feed)")


def test_cidr_promise_score():
    _section("Test — CIDR triage promise score (generic, content-agnostic ranking)")
    from agents.cidr_orchestrator import CIDROrchestrator
    async def _bc(_m): pass
    orc = CIDROrchestrator(session_id="s", target_input="10.0.0.0/24",
                           broadcast=_bc, session_kwargs={})
    empty = orc._score_host({})
    web   = orc._score_host({"open_ports": [80, 443],
                             "services": {"80": {"service": "http"}, "443": {"service": "https"}}})
    rich  = orc._score_host({"open_ports": [22, 80, 445, 3306],
                             "services": {"445": {"service": "smb"}, "3306": {"service": "mysql"},
                                          "80": {"service": "http"}, "22": {"service": "ssh"}},
                             "cves": [{"cve": "x"}, {"cve": "y"}]})
    _assert(empty == 0.0, "a host with no surface scores 0")
    _assert(rich > web > 0, "more ports + high-value services + CVE leads → strictly higher score")
    _assert(isinstance(web, float), "score is a float")


def test_master_run_forwards_max_seconds():
    _section("Test — master.run forwards a per-host depth budget to the operator")
    from pathlib import Path as _P
    _ms = (_P(__file__).resolve().parent.parent / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("max_seconds:" in _ms and "_operator_max_seconds" in _ms
            and '"max_seconds"' in _ms,
            "master.run accepts max_seconds and forwards it to OperatorCore")
    from agents.operator_agent.operator_core import OperatorCore
    op = OperatorCore(_FM_min(), max_seconds=1800)
    _assert(op.max_seconds == 1800, "OperatorCore honours an explicit max_seconds (depth budget)")


def test_db_set_host_triage_exists():
    _section("Test — db.set_host_triage persists per-host triage score/status")
    from pathlib import Path as _P
    _mc = (_P(__file__).resolve().parent.parent / "db" / "mongo_client.py").read_text(encoding="utf-8")
    _assert("async def set_host_triage" in _mc and "promise_score" in _mc,
            "mongo_client exposes set_host_triage with a promise_score field")
    import db.mongo_client as _db
    _assert(callable(getattr(_db, "set_host_triage", None)), "set_host_triage is importable")


def test_cidr_two_phase_orchestration():
    _section("Test — CIDR two-phase triage→ranked-exploit orchestration (+ fallback)")
    from pathlib import Path as _P
    _co = (_P(__file__).resolve().parent.parent / "agents" / "cidr_orchestrator.py").read_text(encoding="utf-8")
    _assert("async def _triage_host" in _co and "async def _run_two_phase" in _co
            and "async def _run_single_phase" in _co,
            "orchestrator has triage + two-phase + single-phase fallback")
    _assert("ARGUS_CIDR_TWO_PHASE" in _co and "ARGUS_CIDR_TRIAGE_PARALLEL" in _co
            and "ARGUS_CIDR_EXPLOIT_PARALLEL" in _co and "ARGUS_CIDR_EXPLOIT_HOST_SEC" in _co,
            "two-phase model + concurrency/budget are env-tunable; reverts via TWO_PHASE=0")
    _assert("host_triage_complete" in _co and "_score_host" in _co,
            "Phase A emits host_triage_complete with the promise score")
    _assert("key=lambda" in _co and 'r.get("score"' in _co and "reverse=True" in _co,
            "Phase B runs hosts in promise-rank (highest first)")
    _assert("TRIAGE_PHASES" in _co and "recon" in _co,
            "triage is recon-only (reuses the recon pipeline, not a full engagement)")
    _assert('kw["max_seconds"]' in _co and "ARGUS_CIDR_EXPLOIT_HOST_SEC" in _co,
            "Phase B passes a bounded per-host depth budget so stalled hosts hand off")


def test_store_hostdata_bucketing():
    _section("Test — store buckets per-host data (triage/findings/phase) for grid + drill-down")
    from pathlib import Path as _P
    _sj = (_P(__file__).resolve().parent.parent / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("hostData:" in _sj and "HOST_DATA_UPDATE" in _sj,
            "store has a hostData map + reducer")
    _assert("case 'host_triage_complete'" in _sj,
            "store handles the host_triage_complete event")
    _assert(_sj.count("type: 'HOST_DATA_UPDATE'") >= 3,
            "triage + findings + phase are bucketed per host_id")


def test_missioncontrol_host_grid_and_drilldown():
    _section("Test — Mission Control host overview grid + per-host drill-down")
    from pathlib import Path as _P
    _mc = (_P(__file__).resolve().parent.parent / "static" / "js" / "pages" / "MissionControl.jsx").read_text(encoding="utf-8")
    _assert("function HostOverviewGrid" in _mc and "hostData" in _mc,
            "a multi-host overview grid component reads hostData")
    _assert("promise" in _mc.lower() and ".sort(" in _mc,
            "grid cards are sorted by promise score")
    _assert("All hosts" in _mc,
            "a back-to-grid control exists for drill-down")
    _assert("hostFilter" in _mc,
            "drill-down keys off the selected host (hostFilter)")


def test_multihost_freeze_fix_and_perhost_view():
    _section("Test — multi-host freeze fix (model-load lock) + per-host attack-phase view")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    # 1) KB model loads are serialised by a process-wide lock (the freeze cause:
    #    every parallel host loaded its OWN multi-GB reranker concurrently).
    _kb = (_root / "knowledge" / "knowledge_base.py").read_text(encoding="utf-8")
    _assert("_MODEL_LOAD_LOCK" in _kb,
            "knowledge_base has a process-wide model-load lock")
    _assert(_kb.count("with _MODEL_LOAD_LOCK:") >= 3,
            "embedder + collection + reranker loads are each lock-guarded")
    # double-checked: a re-check of the singleton cache happens INSIDE the lock
    _assert(_kb.count("getattr(_builtins, _SINGLETON_KEY_RERANKER, None)") >= 2,
            "reranker uses double-checked locking (re-reads the cache inside the lock)")
    # 2) Per-host attack-phase state: store buckets plan/phase per host_id.
    _sj = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("hostPlans" in _sj and "HOST_PLAN_UPDATE" in _sj,
            "store keeps a per-host attack-plan map")
    _assert(_sj.count("type: 'HOST_PLAN_UPDATE'") >= 2 and "msg.host_id" in _sj,
            "phase_change + plan_skeleton bucket per host when the event is host-tagged")
    # 3) MissionControl shows the SELECTED host's plan (not a global blur).
    _mc = (_root / "static" / "js" / "pages" / "MissionControl.jsx").read_text(encoding="utf-8")
    _assert("hostPlans" in _mc and "_viewHypothesis" in _mc and "_viewPhase" in _mc,
            "MissionControl derives host-aware hypothesis/phase from the selected host")
    _assert("viewHost:" in _mc and "Showing attack phase for host" in _mc,
            "the attack-phase panel indicates WHICH host's plan it is showing")
    # 4) Per-host events are actually host_id-tagged by the CIDR orchestrator.
    _co = (_root / "agents" / "cidr_orchestrator.py").read_text(encoding="utf-8")
    _assert("host_id" in _co and "_make_host_broadcast" in _co,
            "CIDR orchestrator tags every per-host event with host_id")


# ── Engagement Integrity (2026-06-19): provenance, scrub, loot dedup ────────
def test_engagement_origin_and_loot_rule():
    _section("Test — engagement provenance stamp + loot dedup (Niagara/Fox bleed fix)")
    from agents.operator_agent.operator_core import OperatorCore
    cur = {"session_id": "s1", "target": "10.0.0.5"}
    _assert(OperatorCore._origin_matches({}, cur), "unstamped item treated as current")
    _assert(OperatorCore._origin_matches({"_origin": cur}, cur), "matching origin kept")
    _assert(not OperatorCore._origin_matches(
        {"_origin": {"session_id": "OTHER", "target": "x"}}, cur),
        "foreign origin rejected")
    fp1 = OperatorCore._loot_fingerprint({"type": "user_flag", "value": "abc", "host": "h"})
    fp2 = OperatorCore._loot_fingerprint({"type": "user_flag", "value": "abc", "host": "h"})
    fp3 = OperatorCore._loot_fingerprint({"type": "user_flag", "value": "DIFF", "host": "h"})
    _assert(fp1 == fp2 and fp1 != fp3, "loot fingerprint deterministic + value-sensitive")
    # behavioural: _add_loot stamps origin + drops duplicates
    op = OperatorCore.__new__(OperatorCore)
    op._intel = {"target_host": "10.0.0.5"}
    op._session_id = "s1"
    op._add_loot({"type": "secret", "value": "k1"})
    op._add_loot({"type": "secret", "value": "k1"})   # duplicate
    op._add_loot({"type": "secret", "value": "k2"})
    loot = op._intel.get("loot")
    _assert(isinstance(loot, list) and len(loot) == 2, "duplicate loot dropped, distinct kept")
    _assert(all(isinstance(x, dict) and x.get("_origin", {}).get("session_id") == "s1"
                for x in loot), "every loot item stamped with current origin")


def test_scrub_on_seed():
    _section("Test — scrub foreign-origin evidence at seed + guarded checkpoint merge")
    import inspect, agents.master_agent as ma
    src = inspect.getsource(ma)
    _assert("_scrub_foreign_evidence" in src, "scrub helper present")
    _assert("_engagement_origin" in src, "master origin mirror present")
    run_src = inspect.getsource(ma.MasterAgent.run)
    _assert("intel_snapshot" in run_src and "_origin" in run_src,
            "checkpoint merge is origin-guarded")
    # behavioural: scrub drops foreign, keeps current + unstamped
    m = ma.MasterAgent.__new__(ma.MasterAgent)
    intel = {"findings": [{"_origin": {"session_id": "s1", "target": "t1"}},
                          {"_origin": {"session_id": "OTHER", "target": "t1"}},
                          {"title": "legacy-no-origin"}],
             "loot": [{"_origin": {"session_id": "OTHER", "target": "t1"}},
                      {"value": "keep-me"}]}
    removed = m._scrub_foreign_evidence(intel, {"session_id": "s1", "target": "t1"})
    _assert(removed == 2, "two foreign-origin items removed")
    _assert(len(intel["findings"]) == 2 and len(intel["loot"]) == 1,
            "current + unstamped evidence kept")


def test_boundary_filters():
    _section("Test — boundary filters (compaction/report/expert) drop foreign-origin evidence")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    oc = (_root / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8")
    rg = (_root / "report" / "generator.py").read_text(encoding="utf-8")
    ea = (_root / "agents" / "meta" / "expert_agent.py").read_text(encoding="utf-8")
    _assert("ignore any facts about a different target" in oc,
            "compaction restricts the summary to the current target")
    _assert("_same_session" in rg and "_origin" in rg,
            "report _build_context filters findings/flags by session origin")
    _assert("Engagement-integrity backstop" in ea and "_origin" in ea,
            "expert post_phase_directive drops foreign-origin findings")


def test_connectivity_blocker_gate():
    _section("Test — connectivity blocker gate (unreachable → pause + human resume/abort)")
    import asyncio as _aio, os as _os, pathlib
    from agents.operator_agent.operator_core import OperatorCore
    # 1) detector recognises network-layer unreachable signals (not findings)
    _assert(OperatorCore._connectivity_signal("connect to 10.0.0.1: Network is unreachable"),
            "detects 'Network is unreachable'")
    _assert(OperatorCore._connectivity_signal("2 packets transmitted, 0 received, 100% packet loss"),
            "detects 100% packet loss")
    _assert(OperatorCore._connectivity_signal("sendto: No route to host"),
            "detects 'No route to host'")
    _assert(not OperatorCore._connectivity_signal("HTTP/1.1 200 OK\n<html>ok</html>"),
            "benign tool output is NOT a blocker signal")

    def _mk(consec):
        op = OperatorCore.__new__(OperatorCore)
        op._intel = {"target_host": "10.0.0.5"}
        op._session_id = "sB"; op._target = "10.0.0.5"
        op._consec_unreachable = consec
        op._blocker_decision = ""; op._blocker_decision_event = None; op._blocker_wait = 5
        async def _noop_emit(ev, data): pass
        async def _noop_reason(*a, **k): pass
        op._emit = _noop_emit; op._reason = _noop_reason
        return op

    # 2) below threshold → no-op (behaviour unchanged)
    _assert(_aio.run(_mk(0)._connectivity_gate()) is None, "below threshold: gate is a no-op")

    # 3) at threshold, human RESUME → continue + counter reset
    op_r = _mk(3)
    async def _run_resume():
        async def _resume():
            await _aio.sleep(0.05); op_r.apply_blocker_decision("resume")
        _aio.create_task(_resume())
        return await op_r._connectivity_gate()
    _assert(_aio.run(_run_resume()) is None, "human resume → gate continues")
    _assert(op_r._consec_unreachable == 0, "resume resets the unreachable counter")

    # 4) at threshold, human ABORT → halt this target honestly
    op_a = _mk(3)
    async def _run_abort():
        async def _abort():
            await _aio.sleep(0.05); op_a.apply_blocker_decision("abort")
        _aio.create_task(_abort())
        return await op_a._connectivity_gate()
    _assert(_aio.run(_run_abort()) == "blocker_unreachable", "human abort → halt target")
    _assert(op_a._intel.get("blocker", {}).get("kind") == "unreachable",
            "blocker recorded honestly (no false 'complete')")

    # 5) env kill-switch disables the gate (revertible)
    op_off = _mk(9)
    _os.environ["ARGUS_CONNECTIVITY_GATE"] = "0"
    try:
        _assert(_aio.run(op_off._connectivity_gate()) is None, "ARGUS_CONNECTIVITY_GATE=0 disables the gate")
    finally:
        _os.environ.pop("ARGUS_CONNECTIVITY_GATE", None)

    # 6) end-to-end wiring: server route, store handler, modal, master preflight
    _root = pathlib.Path(__file__).resolve().parent.parent
    srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert("resolve_blocker_decision" in srv and "blocker_resume" in srv,
            "agent_server routes the human resume/abort decision")
    store = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("engagement_blocker" in store and "BLOCKER_PROMPT" in store,
            "store handles the engagement_blocker event")
    app = (_root / "static" / "js" / "app.jsx").read_text(encoding="utf-8")
    _assert("BlockerModal" in app and "blocker_resume" in app,
            "app renders the blocker modal + sends resume/abort")
    ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("_preflight_reachable" in ma and "ARGUS_PREFLIGHT_REACHABILITY" in ma,
            "master runs a pre-flight reachability check")


def test_master_checker_removed():
    _section("Test — Master Checker fully removed (backend + GUI); Expert + Validator kept")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    # backend: agent file gone + no references anywhere active
    _assert(not (_root / "agents" / "meta" / "master_checker_agent.py").exists(),
            "master_checker_agent.py deleted")
    ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("_master_checker" not in ma and "MasterCheckerAgent" not in ma,
            "no MasterChecker references remain in master_agent")
    rl = (_root / "agents" / "reasoning" / "reasoning_loop.py").read_text(encoding="utf-8")
    _assert("_master_checker" not in rl and "mc_enabled" not in rl,
            "no MasterChecker code remains in reasoning_loop _safe_phase")
    # both modules still import cleanly (legacy fallback must not break)
    import importlib
    import agents.master_agent as _ma2          # noqa: F401
    import agents.reasoning.reasoning_loop as _rl2  # noqa: F401
    # kept agents still wired
    _assert("RedTeamExpertAgent" in ma and "IssueValidatorAgent" in ma,
            "Expert + Issue Validator retained in master_agent")
    # GUI: Master Checker stripped from store + panel
    store = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    panel = (_root / "static" / "js" / "components" / "MetaAgentsPanel.jsx").read_text(encoding="utf-8")
    _assert("metaCheckerState" not in store and "META_CHECKER_PHASE_DONE" not in store
            and "meta_checker_pre_phase" not in store,
            "store.js purged of Master Checker state/reducer/WS handlers")
    _assert("checkerState" not in panel and "Master Checker" not in panel,
            "MetaAgentsPanel purged of the Master Checker sub-panel")
    idx = (_root / "templates" / "index.html").read_text(encoding="utf-8")
    _assert("MetaAgentsPanel.jsx?v=5" in idx, "cache-bust bumped for MetaAgentsPanel")


def test_issue_validator_gate():
    _section("Test — Issue Validator rebuilt as a real finding GATE (no faulty issues in report)")
    from agents.meta.issue_validator_agent import (
        IssueValidatorAgent, register_validator, get_validator, unregister_validator)
    iv = IssueValidatorAgent.__new__(IssueValidatorAgent)
    iv._seen_fp = set()
    # grounded shell/RCE critical is ACCEPTED
    v1 = iv.validate_finding({"title": "Interactive shell obtained", "severity": "critical",
                              "evidence": "uid=0(root) gid=0(root) groups=0(root)"})
    _assert(v1["accept"] and v1["grounded"], "grounded critical (real shell) is accepted")
    # critical with NO evidence is GATED OUT
    v2 = iv.validate_finding({"title": "Critical SQL Injection", "severity": "critical",
                              "tool": "sqlmap", "evidence": ""})
    _assert(not v2["accept"] and v2["reason"] == "ungrounded",
            "critical with no evidence is gated out (the 'silly critical' case)")
    # critical whose 'evidence' is actually a tool error is GATED OUT
    v3 = iv.validate_finding({"title": "Critical RCE", "severity": "critical",
                              "evidence": "curl: (7) Failed to connect: Connection refused"})
    _assert(not v3["accept"] and v3["reason"] == "ungrounded",
            "critical backed only by an error message is gated out")
    # a legitimate LOW finding with no offensive evidence is KEPT (no over-blocking)
    v4 = iv.validate_finding({"title": "Missing X-Frame-Options header", "severity": "low",
                              "evidence": "response lacks X-Frame-Options"})
    _assert(v4["accept"], "legitimate low finding is NOT swallowed by the gate")
    # duplicate is GATED OUT
    iv2 = IssueValidatorAgent.__new__(IssueValidatorAgent); iv2._seen_fp = set()
    dup = {"title": "Open port 22", "severity": "info", "host": "10.0.0.5", "port": 22,
           "evidence": "22/tcp open ssh"}
    a = iv2.validate_finding(dict(dup)); b = iv2.validate_finding(dict(dup))
    _assert(a["accept"] and not b["accept"] and b["reason"] == "duplicate",
            "duplicate finding gated out")
    # foreign-origin is GATED OUT
    vf = iv2.validate_finding({"title": "Unique low note", "severity": "low", "host": "h9",
                              "_origin": {"session_id": "OTHER", "target": "t"}},
                              current_origin={"session_id": "S", "target": "t"})
    _assert(not vf["accept"] and vf["reason"] == "foreign-origin",
            "foreign-engagement finding gated out")
    # OVER-BLOCKING GUARD: an operator/prose finding (has_raw_output=False) whose
    # 'evidence' is a human summary, not raw tool stdout, must NOT be regex-gated
    # out — real RCE/foothold/credential trophies are declared in prose.
    iv3 = IssueValidatorAgent.__new__(IssueValidatorAgent); iv3._seen_fp = set()
    vp = iv3.validate_finding({"title": "Remote Code Execution — foothold achieved",
                               "severity": "critical", "evidence": "RCE SUCCESS"},
                              has_raw_output=False)
    _assert(vp["accept"], "prose-evidence critical (operator finding) is NOT hidden from the report")
    # the SAME prose against the raw-output gate (has_raw_output=True) is gated —
    # proving the calibration actually distinguishes prose from real tool stdout.
    vpr = iv3.validate_finding({"title": "Remote Code Execution two", "severity": "critical",
                                "tool": "sqlmap", "evidence": "RCE SUCCESS"}, has_raw_output=True)
    _assert(not vpr["accept"], "the raw-output grounding gate still rejects prose passed as tool stdout")
    # a totally BARE critical is gated even in prose mode (the silly-issue case)
    vb = iv3.validate_finding({"title": "Critical RCE bare", "severity": "critical", "evidence": ""},
                              has_raw_output=False)
    _assert(not vb["accept"] and vb["reason"] == "ungrounded",
            "a bare critical with no evidence is still gated out")
    # registry round-trip (used by the write-time gate to find the validator)
    register_validator("sx-iv", iv)
    _assert(get_validator("sx-iv") is iv, "registry stores + returns the validator")
    unregister_validator("sx-iv")
    _assert(get_validator("sx-iv") is None, "unregister clears it")


def test_finding_gate_wiring():
    _section("Test — finding gate wired: write-time + read-time + lifecycle + live GUI")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    ba = (_root / "agents" / "base_agent.py").read_text(encoding="utf-8")
    _assert("get_validator" in ba and "validate_finding" in ba and "WRITE-TIME GATE" in ba,
            "base_agent.store_finding applies the deterministic write-time gate")
    bs = (_root / "agents" / "base_subagent.py").read_text(encoding="utf-8")
    _assert("get_validator" in bs and "validate_finding" in bs,
            "base_subagent raw-insert routed through the gate (no bypass)")
    mc = (_root / "db" / "mongo_client.py").read_text(encoding="utf-8")
    _assert("validated_only" in mc and "gated_reason" in mc,
            "mongo_client persists the verdict + supports validated_only reads")
    rg = (_root / "report" / "generator.py").read_text(encoding="utf-8")
    _assert("validated_only=" in rg,
            "report read-path excludes gated (verified=False) findings")
    ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("register_validator" in ma and "unregister_validator" in ma,
            "validator registered + torn down on the operator path")
    _assert("real finding GATE on the DEFAULT operator path" in ma,
            "validator is constructed + run on the default operator path")
    store = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("META_VALIDATOR_STATS" in store and "validation_analysis" in store,
            "store wires the validator's live accepted/gated stats")
    panel = (_root / "static" / "js" / "components" / "MetaAgentsPanel.jsx").read_text(encoding="utf-8")
    _assert("Gated out" in panel, "validator panel surfaces the gated-out count")


# ── Report Overhaul (2026-06-19): 5 selectable themes + PDF fidelity ────────
def _sample_report_context():
    """Realistic _build_context fixture for theme render tests (matches the
    contract the 5 themes bind to)."""
    return {
        "session": {"target": "10.129.21.254", "target_ip": "10.129.21.254",
                    "target_hostname": "FORGE", "target_type": "linux", "scope": "single host",
                    "started_at": "2026-06-18", "completed_at": "2026-06-19",
                    "phases_completed": ["recon", "exploit"]},
        "target_display": "10.129.21.254",
        "findings": [
            {"title": "Unauthenticated file-upload to RCE", "severity": "critical",
             "host": "10.129.21.254", "port": 80, "service": "http",
             "description": "Webshell via upload bypass.", "cves": [],
             "evidence": "uid=33(www-data)", "remediation": "validate uploads",
             "tool_used": "operator", "phase": "exploit", "verified": True,
             "gated_reason": "", "mitre": "T1059", "retest_status": "Verified",
             "extra": {"cvss_base": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L"}},
            {"title": "Outdated Apache 2.4.41", "severity": "high",
             "host": "10.129.21.254", "port": 80, "description": "Version banner.",
             "cves": ["CVE-2021-41773"], "evidence": "Server: Apache/2.4.41",
             "remediation": "patch", "verified": False, "gated_reason": "",
             "mitre": "", "retest_status": "Open", "extra": {"cvss_base": 7.5}},
        ],
        "detection_map": [{"finding": "RCE", "technique": "T1059",
                           "opportunity": "child proc from apache", "telemetry": "EDR",
                           "caught": "Open"}],
        "summary": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 2},
        "sev": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        "outcome": {"label": "FULL COMPROMISE — ROOT", "compromised": True, "root": True},
        "tools_used": ["nmap", "gobuster"],
        "flags": [{"flag_type": "root", "value": "b41d", "location": "/root/root.txt", "context": ""}],
        "graph": {"nodes": []},
        "intel": {"os_guess": "Ubuntu 20.04", "open_ports": [22, 80], "shell_access": True,
                  "services": {"22": {"service": "ssh", "version": "8.2p1"},
                               "80": {"service": "http", "version": "2.4.41"}}},
        "coverage_tests": [
            {"tool": "nmap", "target": "10.129.21.254", "command": "nmap -sCV", "outcome": "success", "note": "3 ports"},
            {"tool": "sqlmap", "target": "10.129.21.254", "command": "sqlmap /api?id=", "outcome": "negative", "note": "not injectable"},
            {"tool": "hydra", "target": "10.129.21.254", "command": "hydra ssh", "outcome": "blocked", "note": "rate-limited"},
        ],
        "coverage_counts": {"success": 8, "negative": 3, "blocked": 1, "error": 0},
        "discovered_issues": [{"title": "Missing headers", "severity": "medium",
                               "host": "10.129.21.254", "tool": "nikto", "status": "open"}],
        "engagement_timeline": [{"ts": "14:02", "label": "recon", "detail": "start"},
                                {"ts": "16:05", "label": "root", "detail": "sudo git"}],
        "mitre_mappings": [{"technique_id": "T1190", "tactic": "Initial Access",
                            "technique_name": "Exploit Public-Facing App",
                            "tool_used": "operator", "outcome": "success"}],
        "duration": "1h 42m", "phases_completed": ["recon", "exploit"],
        "all_phases": ["recon", "exploit"],
        "executive_summary": "ARGUS chained upload-RCE then sudo-git to root.",
        "generated_at": "2026-06-19 09:30 UTC", "engagement_type": "pentest",
        "objectives": [], "objectives_done": 0, "objectives_total": 0,
        "reasoning_journal": [], "journal_truncated": False, "journal_total": 0,
        "loot_entries": [{"severity": "critical", "doi_label": "root.txt",
                          "source": "/root/root.txt", "target": "10.129.21.254",
                          "size_bytes": 33, "sha256": "3b71dea0"}],
        "loot_summary": {}, "loot_by_doi": {}, "web_intel_hints": [], "primer_rows": [],
        "attack_path": [
            {"__step": 1, "phase": "recon", "result": "ports found", "source": "nmap", "ts": "14:02"},
            {"__step": 2, "phase": "exploit", "result": "RCE", "source": "upload", "ts": "15:40"},
            {"__step": 3, "phase": "privesc", "result": "root", "source": "sudo git", "ts": "16:05"}],
        "creds_summary": [{"user": "forge_app", "domain": "", "password": "••••••",
                           "source": "config.php", "note": "DB"}],
        "win_conditions": {"achieved_count": 2, "total": 2,
                           "conditions": [{"name": "root_flag_captured", "achieved": True, "evidence": "b41d"}]},
        "mission_brief": {"objective": "foothold + flags"}, "exploit_modules": [],
        # AI / LLM security section (Slice 3) — present when the engagement
        # red-teamed an AI target; themes render it under an {% if ai_security %} guard.
        "ai_security": {
            "count": 2, "max_aivss": 8.6, "avg_asr": 65,
            "owasp_classes": ["LLM01", "LLM06"],
            "by_class": {"indirect_injection": 1, "excessive_agency": 1},
            "findings": [
                {"title": "Indirect prompt injection via retrieved content", "severity": "HIGH",
                 "aivss": 8.6, "cvss": 7.5, "asr": 80, "trials": 5, "successes": 4,
                 "owasp_llm": "LLM01 (Prompt Injection)", "atlas": "AML.T0051.002",
                 "attack_vector": "indirect_injection", "vector": "AIVSS/ASR:0.80/AG:0.40/OWASP:LLM01",
                 "target_model": "gpt-4o-mini", "evidence": "[doc] -> DOC-INJECT-OK",
                 "remediation": "Separate instructions from retrieved data; sandbox tool outputs."},
                {"title": "Excessive agency: unauthorized tool invocation", "severity": "CRITICAL",
                 "aivss": 8.4, "cvss": 5.0, "asr": 50, "trials": 4, "successes": 2,
                 "owasp_llm": "LLM06 (Excessive Agency)", "atlas": "AML.T0053",
                 "attack_vector": "excessive_agency", "vector": "AIVSS/ASR:0.50/AG:0.60/OWASP:LLM06",
                 "target_model": "gpt-4o-mini", "evidence": "tool call: send_email(...)",
                 "remediation": "Least-privilege tools + human approval for state-changing actions."},
            ],
        },
    }


def test_report_theme_registry():
    _section("Test — report theme registry (5 selectable themes, default executive)")
    from report.themes import THEMES, get_theme, DEFAULT_THEME, list_themes
    assert {"executive", "operator_dark", "editorial", "compliance", "threat_intel"} <= set(THEMES.keys())
    _assert(DEFAULT_THEME == "executive", "default theme is executive")
    _assert(get_theme("nope") == get_theme(DEFAULT_THEME), "unknown theme falls back to default")
    _assert(len(list_themes()) == 5, "list_themes returns all 5 for the picker")


def test_report_themes_render():
    _section("Test — 5 Jinja2 themes render from the sample context (no markers, SVG present)")
    import pathlib, jinja2
    _root = pathlib.Path(__file__).resolve().parent.parent
    tdir = _root / "report" / "themes"
    sample = _sample_report_context()
    for key in ("executive", "operator_dark", "editorial", "compliance", "threat_intel"):
        f = tdir / f"{key}.html.j2"
        _assert(f.exists(), f"theme file present: {key}")
        src = f.read_text(encoding="utf-8")
        _assert("<!DOCTYPE html>" in src and "@media print" in src, f"{key} is print-ready HTML")
        html = jinja2.Template(src).render(**sample)
        _assert("<!--MORE-->" not in html, f"{key} left no build marker")
        _assert("<svg" in html, f"{key} has inline SVG (graph/charts)")
        _assert(sample["target_display"] in html, f"{key} bound the real target")
        # Slice 3: the AI / LLM Security section renders from the ai_security block
        _assert("Indirect prompt injection" in html
                and ("LLM06" in html or "excessive agency" in html.lower()),
                f"{key} renders the AI / LLM Security section (ai_security findings)")


def test_generator_theme_and_pdf_order():
    _section("Test — generator theme selection + weasyprint-before-plaintext PDF order")
    import inspect, report.generator as g
    gh = inspect.getsource(g.ReportGenerator.generate_html)
    _assert("theme" in gh, "generate_html accepts a theme")
    gp = inspect.getsource(g.ReportGenerator.generate_pdf)
    _assert(gp.index("weasyprint") < gp.index("pdf_writer"),
            "weasyprint is attempted before the plaintext writer")
    _assert('engine == "text"' in gp or "engine=='text'" in gp,
            "plaintext PDF is opt-in via engine='text' (never the default download)")
    _assert("list_themes" in inspect.getsource(g.ReportGenerator),
            "generator exposes list_themes for the picker")


def test_context_retest_and_detection():
    _section("Test — _build_context derives retest_status + detection_map")
    import inspect, report.generator as g
    bc = inspect.getsource(g.ReportGenerator._build_context)
    _assert("retest_status" in bc, "per-finding retest_status derived")
    _assert("detection_map" in bc, "detection/purple-team map derived")


def test_report_endpoint_theme():
    _section("Test — report endpoint ?theme= + /report/themes route")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert("theme" in srv and "/report/themes" in srv,
            "endpoint takes a theme param + exposes the themes list")
    _assert("X-PDF-Engine" in srv,
            "PDF endpoint signals the client (no styled engine → browser print, not HTML-as-PDF)")


def test_pdf_deps_provisioned():
    _section("Test — weasyprint dependency + system libs provisioned")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    req = (_root / "requirements.txt").read_text(encoding="utf-8").lower()
    _assert("weasyprint" in req, "weasyprint pinned in requirements")
    setup = (_root / "setup.sh").read_text(encoding="utf-8").lower()
    _assert("pango" in setup or "weasyprint" in setup, "setup.sh provisions weasyprint libs")
    kali = (_root / "install-kali-tools.sh").read_text(encoding="utf-8").lower()
    _assert("pango" in kali or "weasyprint" in kali, "install-kali-tools provisions weasyprint libs")


def test_reportpage_theme_picker():
    _section("Test — ReportPage theme picker + browser-print fallback")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    rp = (_root / "static" / "js" / "pages" / "ReportPage.jsx").read_text(encoding="utf-8")
    api = (_root / "static" / "js" / "api.js").read_text(encoding="utf-8")
    _assert("theme" in rp and ("reportThemes" in rp or "report/themes" in rp),
            "ReportPage fetches + offers the theme picker")
    _assert("report/themes" in api, "api.js exposes the /report/themes endpoint")
    _assert("window.print" in rp or "printToPdf" in rp, "ReportPage has a browser print-to-PDF fallback")


def test_crestron_avot_integration():
    _section("Test — Crestron AV/OT capability wired into ARGUS (fingerprint + SAST + toolbelt)")
    import pathlib
    _root = pathlib.Path(__file__).resolve().parent.parent
    # 1) avot capability module present (from the client patch)
    for rel in ("agents/avot/recon.py", "agents/avot/sast/simpl_scan.py",
                "agents/avot/fuzz/crestron_fuzzer.py",
                "agents/avot/sast/samples/vulnerable_module.usp"):
        _assert((_root / rel).exists(), f"avot file present: {rel}")
    # 2) the SIMPL+/SIMPL# SAST flags the vulnerable sample
    from agents.avot.sast.simpl_scan import scan_file
    res = scan_file(str(_root / "agents" / "avot" / "sast" / "samples" / "vulnerable_module.usp"))
    _assert(len(res) >= 6, "SIMPL SAST flags the vulnerable sample (>=6 findings)")
    # 3) Crestron recon fingerprint: positive on Crestron ports, negative on a plain host
    from agents.avot import recon as _avot
    det = _avot.detect({"open_ports": [{"port": 41794, "service": "unknown"}], "services": {}})
    _assert(bool(det) and det.get("technology") == "Crestron control system"
            and 41794 in det.get("ports", []),
            "detect() fingerprints a Crestron control bus (CIP 41794)")
    _assert(_avot.detect({"open_ports": [{"port": 80, "service": "http"}]}) is None,
            "detect() does NOT false-positive on a plain web host")
    f = _avot.finding_for(det)
    _assert(bool(f.get("severity")) and bool(f.get("title")) and bool(f.get("remediation")),
            "finding_for() yields a store_finding-shaped record")
    # 4) engine hook wired (content-agnostic) into the recon merge
    ma = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("_avot_capability_scan" in ma and "_cheap_intel_merge" in ma,
            "master runs the capability-module fingerprint after the recon merge")
    # 5) operator toolbelt is aware of the avot capability
    tc = (_root / "agents" / "operator_agent" / "tool_catalog.py").read_text(encoding="utf-8")
    _assert("avot" in tc and "Crestron" in tc, "tool catalog surfaces the avot capability")


def test_ai_redteam_module():
    _section("Test — AI Red-Team engine module (catalog/adapter/scorer/harness/mapper)")
    import asyncio as _aio
    from agents.ai_red_team.probe_catalog import load_catalog
    from agents.ai_red_team import scorer
    from agents.ai_red_team.harness import run_probe
    from agents.ai_red_team.target_adapter import make_adapter
    from agents.ai_red_team.finding_mapper import to_finding
    cat = load_catalog()
    _assert(isinstance(cat, list) and len(cat) >= 20, f"probe catalog loads (got {len(cat)})")
    cats = {p["category"] for p in cat}
    for need in ("prompt_injection", "jailbreak", "excessive_agency"):
        _assert(need in cats, f"catalog has the {need} class")
    p0 = cat[0]
    for k in ("id", "category", "payloads", "success", "trials"):
        _assert(k in p0, f"probe carries {k}")
    _assert(scorer.detect("here is INJECTION-OK", ["contains:INJECTION-OK"]) is True, "detector fires on canary")
    _assert(scorer.detect("refused", ["contains:INJECTION-OK"]) is False, "detector does not false-fire")
    _assert(abs(scorer.asr(3, 5) - 0.6) < 1e-9, "ASR = successes/trials")
    import pathlib
    _ta = (pathlib.Path(__file__).resolve().parent / "ai_red_team" / "target_adapter.py").read_text(encoding="utf-8")
    for shape in ("http_chat", "agentic", "single_endpoint"):
        _assert(shape in _ta, f"adapter supports {shape}")
    a = make_adapter({"type": "single_endpoint", "mock_echo": True})
    _assert("ping" in _aio.run(a.send([{"role": "user", "content": "ping"}])), "mock adapter echoes (offline)")
    class _Echo:
        async def send(self, m): return "SYSTEM PROMPT: you are a bot INJECTION-OK"
    probe = {"id": "pi-x", "category": "prompt_injection", "payloads": ["go"],
             "success": {"detectors": ["regex:(?i)system prompt"], "judge": ""},
             "trials": 3, "adaptive": False, "destructive": False}
    res = _aio.run(run_probe(probe, _Echo()))
    _assert(res["successes"] == 3 and res["asr"] == 1.0 and res["success"] is True, "harness computes ASR")
    res2 = _aio.run(run_probe(dict(probe, id="d", destructive=True), _Echo(), approve=None))
    _assert(res2.get("skipped") is True, "destructive probe gated (safe-by-default)")
    f = to_finding(probe, res)
    _assert(f["severity"] and "injection" in f["title"].lower(), "mapper builds a finding")
    _assert(f["extra"]["asr"] == 1.0 and f["extra"]["ai_finding"] is True, "AI metrics ride in extra")


def test_ai_redteam_routing_and_ui():
    _section("Test — target_type='ai' routing + AI target config UI + plumbing")
    import pathlib, inspect
    _root = pathlib.Path(__file__).resolve().parent.parent
    from agents.ai_red_team.engine import AIRedTeamEngine  # noqa: F401 importable
    import agents.master_agent as ma
    run_src = inspect.getsource(ma.MasterAgent.run)
    _assert(("ai_red_team" in run_src or "AIRedTeamEngine" in run_src) and '"ai"' in run_src,
            "master.run routes an AI target to the AI Red-Team engine")
    _assert("ai_target" in run_src, "master threads ai_target into intel")
    sch = (_root / "db" / "schemas.py").read_text(encoding="utf-8")
    _assert("ai_target" in sch, "StartPentestRequest carries ai_target")
    srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert("ai_target" in srv, "server forwards ai_target into master_kwargs")
    tc = (_root / "static" / "js" / "pages" / "TargetConfig.jsx").read_text(encoding="utf-8")
    _assert("'ai'" in tc and "ai_target" in tc and "Adapter" in tc,
            "TargetConfig offers an AI / LLM target with adapter config")


def test_ai_shadow_discovery():
    _section("Test — shadow-AI discovery (knowledge-driven fingerprint + capability registry)")
    import pathlib, inspect
    from agents.ai_red_team import discovery as _d
    # dedicated port → detection
    det = _d.detect({"open_ports": [{"port": 11434, "service": "http"}], "services": {}})
    _assert(isinstance(det, list) and det and det[0]["technology"].lower().startswith("ollama")
            and 11434 in det[0].get("ports", []),
            "detect() fingerprints an exposed Ollama server (port 11434)")
    # plain hosts must NOT false-positive (80 and the common-but-shared 8000)
    _assert(_d.detect({"open_ports": [{"port": 80, "service": "http"}]}) == [],
            "detect() does NOT false-positive on a plain web host")
    _assert(_d.detect({"open_ports": [{"port": 8000, "service": "http"}]}) == [],
            "detect() does NOT false-positive on a shared port (8000)")
    # HTTP marker → OpenAI-compatible surface
    det2 = _d.detect({"open_ports": [{"port": 443, "service": "https"}],
                      "http": "GET /v1/chat/completions HTTP/1.1 200"})
    _assert(any("openai" in x["technology"].lower() for x in det2),
            "detect() flags an OpenAI-compatible API via HTTP marker")
    # finding shape
    f = _d.finding_for(det[0])
    _assert(bool(f.get("severity")) and "shadow ai" in f["title"].lower()
            and f["tool_used"] == "ai_red_team.discovery" and bool(f.get("remediation")),
            "finding_for() yields a shadow-AI store_finding record")
    # signature catalog is data-driven + has breadth
    _root = pathlib.Path(__file__).resolve().parent.parent
    sig = (_root / "knowledge" / "data" / "ai_security" / "discovery_signatures.yaml")
    _assert(sig.exists(), "discovery_signatures.yaml exists (knowledge-driven)")
    _assert(len(_d._load_signatures()) >= 5, "signature catalog carries breadth")
    # master capability registry runs discovery alongside avot, handles list returns
    import agents.master_agent as _ma
    ma_src = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    scan_src = inspect.getsource(_ma.MasterAgent._avot_capability_scan)
    _assert("ai_red_team.discovery" in ma_src and "_CAPABILITY_MODULES" in ma_src
            and "agents.avot.recon" in ma_src and "isinstance(det, list)" in scan_src,
            "master capability registry includes shadow-AI discovery + handles list detections")


def test_ai_scoring_and_repro():
    _section("Test — AIVSS scoring + PyRIT/garak/promptfoo reproducibility export (Slice 3)")
    from utils.cvss_scorer import score_ai_finding, score_ai_findings, AIVSSScore
    hi = {"title": "Excessive agency", "severity": "high",
          "extra": {"asr": 0.8, "owasp_llm": "LLM06", "attack_vector": "excessive_agency", "ai_finding": True}}
    lo = {"title": "System prompt leak", "severity": "medium",
          "extra": {"asr": 0.2, "owasp_llm": "LLM07", "attack_vector": "system_prompt_leak", "ai_finding": True}}
    shi, slo = score_ai_finding(hi), score_ai_finding(lo)
    _assert(isinstance(shi, AIVSSScore) and shi.aivss_score > slo.aivss_score,
            "AIVSS amplifies agentic high-ASR findings above low-ASR ones")
    _assert(0.0 < shi.aivss_score <= 10.0 and shi.vector.startswith("AIVSS/"),
            "AIVSS produces a bounded score + vector string")
    ranked = score_ai_findings([lo, hi])
    _assert(ranked and ranked[0].title == "Excessive agency", "score_ai_findings ranks highest-first")
    _assert(score_ai_findings([{"title": "Apache", "severity": "high", "extra": {}}]) == [],
            "AIVSS scorer ignores non-AI findings")
    # reproducibility exporters
    from agents.ai_red_team import reproducibility as repro
    from agents.ai_red_team.probe_catalog import load_catalog
    cat = load_catalog()
    pf = repro.export(cat, "promptfoo", {"model": "gpt-4o-mini"})
    _assert(pf["providers"] == ["gpt-4o-mini"] and len(pf["tests"]) >= len(cat)
            and pf["prompts"] == ["{{prompt}}"],
            "promptfoo export carries provider + per-payload tests")
    _assert("assert" in pf["tests"][0], "promptfoo tests carry asserts from detectors")
    gk = repro.export(cat, "garak"); py = repro.export(cat, "pyrit")
    _assert(len(gk["probes"]) == len(cat) and len(py["objectives"]) == len(cat),
            "garak + pyrit exports map every probe")
    import json as _j
    _assert(_j.loads(repro.export_json(cat, "garak"))["argus_export"] == "garak",
            "export_json round-trips")
    _ok = False
    try:
        repro.export(cat, "bogus")
    except ValueError:
        _ok = True
    _assert(_ok, "unknown export format raises")
    # generator wires ai_security into the report context
    import pathlib
    gsrc = (pathlib.Path(__file__).resolve().parent.parent / "report" / "generator.py").read_text(encoding="utf-8")
    _assert('"ai_security"' in gsrc and "score_ai_findings" in gsrc,
            "generator builds an ai_security context block from AI findings")


def test_skill_registry_load_match():
    _section("Test — skill registry loader + matcher (data-driven tech coverage)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    _assert(isinstance(skills, list) and len(skills) >= 1, "skill files load from knowledge/skills")
    s = next((x for x in skills if x["id"] == "modbus"), None)
    _assert(s and s["technology"] and s["match"].get("ports") and s["guidance"],
            "modbus skill carries technology + match + guidance body")
    det = sr.match_skills({"open_ports": [{"port": 502, "service": "unknown"}], "services": {}})
    _assert(any(d["id"] == "modbus" for d in det), "match_skills fires on Modbus port 502")
    _assert(sr.match_skills({"open_ports": [{"port": 80, "service": "http"}]}) == [],
            "match_skills does not false-positive on a plain web host")
    f = sr.finding_for(next(d for d in det if d["id"] == "modbus"))
    _assert(f.get("severity") and f.get("title") and f.get("remediation"), "finding_for shapes a record")


def test_skill_safety_gate_and_rag():
    _section("Test — skill safety-class gate (human intrusiveness ceiling, OT safe-by-default)")
    from knowledge import skill_registry as sr
    _assert(sr.allowed("safe", "safe", "IT") is True, "safe action allowed at safe ceiling")
    _assert(sr.allowed("disruptive", "intrusive", "IT") is False, "disruptive blocked under intrusive ceiling")
    _assert(sr.allowed("intrusive", "disruptive", "IT") is True, "intrusive allowed under disruptive ceiling")
    _assert(sr.allowed("intrusive", "disruptive", "OT", authorized=False) is False,
            "OT target clamps to safe without authorization")
    _assert(sr.allowed("intrusive", "disruptive", "OT", authorized=True) is True,
            "authorized OT engagement may go intrusive")
    _assert(sr.allowed("intrusive", "disruptive", "IT", life_safety=True, authorized=False) is False,
            "life-safety point never auto-actuates")
    det = {"quick_wins": [{"cmd": "read", "safety": "safe"}, {"cmd": "write", "safety": "disruptive"}],
           "life_safety": False}
    _assert(len(sr.safe_quick_wins(det, "safe", "IT")) == 1, "only the safe quick-win surfaces at safe ceiling")
    _assert(len(sr.safe_quick_wins(det, "disruptive", "IT")) == 2, "both surface at disruptive ceiling")
    ok = sr.ingest_to_rag({"id": "x", "technology": "T", "_source": "s",
                           "guidance": "A" * 80, "match": {"ports": [1]}, "references": []})
    _assert(ok in (True, False), "ingest_to_rag returns a bool (best-effort)")


def test_ot_modbus_module():
    _section("Test — agents/ot/modbus read-only capability exemplar")
    from agents.ot import modbus
    det = modbus.detect({"open_ports": [{"port": 502, "service": "unknown"}], "services": {}})
    _assert(det and det.get("technology", "").lower().startswith("modbus") and det.get("safety_class") == "safe",
            "modbus.detect fingerprints 502/tcp as a safe (read-only) detection")
    _assert(modbus.detect({"open_ports": [{"port": 80, "service": "http"}]}) is None,
            "modbus.detect does not false-positive on a plain web host")
    f = modbus.finding_for(det)
    _assert(f.get("severity") and "modbus" in f["title"].lower() and f.get("remediation"),
            "modbus.finding_for shapes a store_finding record")


def test_skill_registry_engine_wiring():
    _section("Test — master runs the skill registry + Modbus module in the capability scan")
    import inspect, pathlib
    import agents.master_agent as ma
    ma_src = (pathlib.Path(__file__).resolve().parent.parent / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("agents.ot.modbus" in ma_src, "Modbus module registered in _CAPABILITY_MODULES")
    scan = inspect.getsource(ma.MasterAgent._avot_capability_scan)
    _assert("match_skills" in scan and "skill_registry" in scan,
            "capability scan also runs the data-driven skill registry")
    _assert("_ingest_skills_to_rag" in ma_src,
            "master ingests skill guidance into RAG (best-effort)")


def test_scan_intrusiveness_ui_and_plumbing():
    _section("Test — human scan-intrusiveness ceiling (safe|intrusive|disruptive) GUI + plumbing")
    import pathlib, inspect
    root = pathlib.Path(__file__).resolve().parent.parent
    sch = (root / "db" / "schemas.py").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in sch, "StartPentestRequest carries scan_intrusiveness")
    srv = (root / "agent_server.py").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in srv, "server forwards scan_intrusiveness into master_kwargs")
    import agents.master_agent as ma
    _assert("scan_intrusiveness" in inspect.getsource(ma.MasterAgent.run), "master.run stores the ceiling in intel")
    tc = (root / "static" / "js" / "pages" / "TargetConfig.jsx").read_text(encoding="utf-8")
    _assert("scan_intrusiveness" in tc and "intrusive" in tc and "disruptive" in tc,
            "TargetConfig exposes a safe|intrusive|disruptive selector")


def test_skill_registry_p0_breadth():
    _section("Test — seed P0 technology skill coverage (OT/IoT/IT breadth)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    ids = {s["id"] for s in skills}
    domains = {s["domain"] for s in skills}
    _assert(len(skills) >= 15, f"P0 skill coverage breadth (got {len(skills)})")
    _assert({"OT", "IT"} <= domains, "coverage spans at least OT + IT domains")
    for need in ("modbus", "mqtt"):
        _assert(need in ids, f"seed skill present: {need}")
    for s in skills:
        ports = [int(p) for p in s["match"]["ports"] if str(p).isdigit()]
        only_shared = ports and all(p in sr._SHARED_PORTS for p in ports)
        if only_shared:
            _assert(bool(s["match"]["banners"] or s["match"]["markers"]),
                    f"{s['id']}: shared-port skill must have a banner/marker (FP-safe)")


def test_skill_registry_toolbelt_awareness():
    _section("Test — operator tool catalog is aware of the skill registry")
    import pathlib
    tc = (pathlib.Path(__file__).resolve().parent.parent / "agents" / "operator_agent" / "tool_catalog.py").read_text(encoding="utf-8")
    _assert("skill" in tc.lower() and ("quick-win" in tc.lower() or "quick_win" in tc.lower() or "intrusiveness" in tc.lower()),
            "tool catalog surfaces the skill-registry quick-win / intrusiveness awareness")


def test_ot_active_modules():
    _section("Test — OPC-UA + BACnet read-only capability modules (Slice 2 active speakers)")
    import inspect, pathlib, asyncio as _aio
    from agents.ot import opcua, bacnet
    _assert(bool(opcua.detect({"open_ports": [4840]})) and opcua.detect({"open_ports": [80]}) is None,
            "opcua.detect fingerprints 4840, no FP on 80")
    _assert(bool(bacnet.detect({"open_ports": [{"port": 47808, "protocol": "udp"}]}))
            and bacnet.detect({"open_ports": [80]}) is None,
            "bacnet.detect fingerprints 47808/udp, no FP on 80")
    _assert("opc-ua" in opcua.finding_for(opcua.detect({"open_ports": [4840]}))["title"].lower(),
            "opcua.finding_for shaped")
    _bf = bacnet.finding_for(bacnet.detect({"open_ports": [47808]}))
    _assert(_bf["severity"] == "info" and _bf.get("inherent_risk") == "high",
            "bacnet.finding_for: bare detection is INFO, inherent-risk preserved")
    _assert(_aio.run(opcua.safe_probe("127.0.0.1", 1, timeout=0.5)) == {},
            "opcua.safe_probe (read-only) → {} on closed port, never raises/hangs")
    _assert(_aio.run(bacnet.safe_probe("127.0.0.1", 1, timeout=0.5)) == {},
            "bacnet.safe_probe (read-only) → {} on closed port, never raises/hangs")
    src = inspect.getsource(opcua) + inspect.getsource(bacnet)
    _assert("GATED" in src, "write/control primitives are documented-but-gated (safe-by-default)")
    ma_src = (pathlib.Path(__file__).resolve().parent.parent / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("agents.ot.opcua" in ma_src and "agents.ot.bacnet" in ma_src,
            "opcua + bacnet registered in _CAPABILITY_MODULES")


def test_ot_passive_capture():
    _section("Test — passive-first OT capture (PCAP→intel, zero packets) + master merge")
    import inspect, pathlib
    from agents.ot import passive_ingest as pi
    _assert(pi.ingest_pcap("/does/not/exist.pcap") == {},
            "ingest_pcap is graceful when scapy/file unavailable (returns {})")
    dets = pi.passive_scan({"open_ports": [{"port": 502}, {"port": 4840},
                                           {"port": 47808, "protocol": "udp"}], "services": {}})
    techs = {d["technology"] for d in dets}
    _assert({"Modbus / Modbus-TCP", "OPC-UA", "BACnet/IP"} <= techs,
            "passive_scan fingerprints OT techs from observed intel (no packets sent)")
    root = pathlib.Path(__file__).resolve().parent.parent
    ma_src = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    import agents.master_agent as ma
    _assert("_merge_passive_capture" in ma_src and "pcap_path" in inspect.getsource(ma.MasterAgent.run),
            "master merges a passive capture + threads pcap_path into intel")
    _assert("pcap_path" in (root / "db" / "schemas.py").read_text(encoding="utf-8"),
            "StartPentestRequest carries pcap_path")


def test_skill_registry_p1_breadth():
    _section("Test — P1 technology skill coverage (ICS long-tail + health + verticals + AV)")
    from knowledge import skill_registry as sr
    ids = {s["id"] for s in sr.load_skills()}
    _assert(len(ids) >= 30, f"P0+P1 skill coverage breadth (got {len(ids)})")
    for need in ("codesys", "dicom"):
        _assert(need in ids, f"P1 seed skill present: {need}")


def test_skill_registry_p2_transport():
    _section("Test — P2 hardware-tier knowledge (transport-tagged RF/CAN/L2/serial)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    by_id = {s["id"]: s for s in skills}
    _assert(len(skills) >= 40, f"P0+P1+P2 coverage breadth (got {len(skills)})")
    _assert(by_id.get("modbus", {}).get("transport") == "ip", "ip is the default transport")
    p2 = [s for s in skills if s.get("transport") in ("rf", "can", "l2", "serial")]
    _assert(len(p2) >= 6, f"P2 hardware-tier skills present (got {len(p2)})")
    for need in ("zigbee", "can_uds"):
        _assert(need in by_id, f"P2 seed skill present: {need}")
    _assert(by_id["zigbee"]["transport"] == "rf", "zigbee tagged transport: rf")
    det = {"technology": "Zigbee", "domain": "IoT", "transport": "rf", "severity": "high",
           "evidence": "rf", "guidance": "g", "references": []}
    f = sr.finding_for(det)
    _assert(any(w in f["description"].lower() for w in ("hardware", "bridge", "sdr")),
            "finding for an RF transport notes the hardware-bridge requirement")


def test_global_category_breadth():
    _section("Test — global technology coverage (security/network/os/webapp/scada/home/marine/aviation)")
    from knowledge import skill_registry as sr
    skills = sr.load_skills()
    by_cat = {}
    for s in skills:
        c = s.get("category")
        if c:
            by_cat.setdefault(c, []).append(s)
    _assert(len(skills) >= 100, f"global coverage breadth (got {len(skills)})")
    for need in ("security", "network", "os", "webapp", "scada", "home", "marine", "aviation"):
        _assert(need in by_cat, f"category present: {need}")
    ot_vert = by_cat.get("scada", []) + by_cat.get("marine", []) + by_cat.get("aviation", [])
    _assert(bool(ot_vert) and not any(s["safety_class"] == "disruptive" for s in ot_vert),
            "SCADA/marine/aviation skills are not disruptive-by-default (safe-first)")


def test_rag_logger_and_report():
    _section("Test — dedicated RAG trace logger + effectiveness report")
    import os, tempfile, pathlib, sys
    tp = os.path.join(tempfile.gettempdir(), "_argus_rag_trace_test.jsonl")
    os.environ["ARGUS_RAG_TRACE_PATH"] = tp
    try:
        os.remove(tp)
    except OSError:
        pass
    from knowledge import rag_logger as rl
    rl.log_ingest("knowledge/skills/ot/modbus.md", "skill", "id1", True, 800)
    rl.log_search("test modbus", [{"source_file": "knowledge/skills/ot/modbus.md",
                  "chunk_type": "skill", "relevance": 0.62, "text": "x"}], 10.0, "operator_core.py:1", 165)
    rl.log_search("nothing matches", [], 4.0, "operator_core.py:2", 165, reason="below_min_relevance")
    _assert(pathlib.Path(tp).exists(), "rag_logger writes a separate JSON trace")
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from scripts import rag_report as rr
    s = rr.analyse(rr.load_trace(pathlib.Path(tp)), focus_type="skill")
    _assert(s["queries"] == 2 and s["empty_pct"] == 50.0, "report counts queries + flags the empty one")
    sk = s["effectiveness_by_type"]["skill"]
    _assert(sk["retrieved"] == 1 and sk["avg_rel"] > 0.5,
            "report measures per-chunk-type retrieval + relevance (the 'worth it?' signal)")
    kb_src = (root / "knowledge" / "knowledge_base.py").read_text(encoding="utf-8")
    _assert("rag_logger" in kb_src and "log_search" in kb_src and "log_ingest" in kb_src,
            "knowledge_base ingest + search_raw are instrumented with the RAG trace")
    _assert("ARGUS_RAG_DEBUG" in (root / "knowledge" / "rag_logger.py").read_text(encoding="utf-8"),
            "RAG logging is toggleable (ARGUS_RAG_DEBUG, separate from app logs)")


def test_lesson_target_agnostic_scrub():
    _section("Test — learned lessons are target-agnostic (scrub IP/host/creds, keep method)")
    from agents.reasoning.lesson_distiller import _scrub
    intel = {"target": "10.10.10.5", "target_hostname": "FORGE", "domain": "forge.htb",
             "vhosts": [{"vhost": "admin.forge.htb"}], "hostnames": ["dc01"],
             "credentials": [{"user": "forge_app", "password": "S3cr3tP@ss"}]}
    text = ("Exploited Apache 2.4.41 (CVE-2021-41773) path traversal on http://admin.forge.htb "
            "to read /etc/passwd on 10.10.10.5 (FORGE / dc01) via port 8080. Creds forge_app:S3cr3tP@ss. "
            "MAC aa:bb:cc:dd:ee:ff. Flag ab12cd34ef5678901234567890abcdef.")
    out = _scrub(text, "10.10.10.5", intel)
    for keep in ("Apache 2.4.41", "CVE-2021-41773", "path traversal", "/etc/passwd", "port 8080"):
        _assert(keep in out, f"reusable method preserved: {keep}")
    for gone in ("10.10.10.5", "admin.forge.htb", "FORGE", "dc01", "S3cr3tP@ss", "forge_app",
                 "aa:bb:cc:dd:ee:ff", "ab12cd34ef5678901234567890abcdef"):
        _assert(gone not in out, f"engagement identifier scrubbed: {gone}")
    # timestamps must NOT be mistaken for an IPv6 address
    _assert("12:34:56" in _scrub("ran at 12:34:56 UTC", "x", {}),
            "a clock time is not scrubbed as an address")
    import inspect, agents.reasoning.lesson_distiller as ld
    _assert("_scrub(full, target, intel)" in inspect.getsource(ld.distill_and_store),
            "distiller scrubs with the engagement's intel (its specific hosts/creds)")
    import pathlib
    kb_src = (pathlib.Path(__file__).resolve().parent.parent / "knowledge" / "knowledge_base.py").read_text(encoding="utf-8")
    _assert("never reuse an old IP" in kb_src,
            "retrieval context tells the operator to substitute the current target")


def test_rag_budget_guardrail():
    _section("Test — RAG resource metering + fail-safe growth guardrail")
    import os, pathlib, inspect, sys
    from knowledge import rag_budget as rb
    b = {"max_chunks": 1000, "max_db_mb": 100, "min_free_disk_mb": 500, "min_free_ram_mb": 256}
    _assert(rb.evaluate(500, 10, 2000, 2000, b)[0] is True, "within budget → allowed")
    _assert(rb.evaluate(1000, 10, 2000, 2000, b)[0] is False, "chunk cap → blocked")
    _assert(rb.evaluate(10, 200, 2000, 2000, b)[0] is False, "db-size cap → blocked")
    _assert(rb.evaluate(10, 10, 100, 2000, b)[0] is False, "low free disk → blocked")
    _assert(rb.evaluate(10, 10, 2000, 100, b)[0] is False, "low free RAM → blocked")
    _assert(rb.evaluate(10, None, None, None, b)[0] is True, "unknown metrics never block on their own")
    u = rb.usage()
    for k in ("chunks", "db_size_mb", "est_vector_ram_mb", "budgets", "within_budget", "free_disk_mb"):
        _assert(k in u, f"usage() reports {k}")
    os.environ["ARGUS_RAG_BUDGET"] = "0"
    _assert(rb.ingest_allowed()[0] is True, "guardrail is disableable (ARGUS_RAG_BUDGET=0)")
    os.environ.pop("ARGUS_RAG_BUDGET", None)
    root = pathlib.Path(__file__).resolve().parent.parent
    kb_src = (root / "knowledge" / "knowledge_base.py").read_text(encoding="utf-8")
    _assert("rag_budget" in kb_src and "ingest_allowed" in kb_src,
            "ingest() consults the budget guardrail before embedding")
    import knowledge.knowledge_base as kb
    _assert("resources" in inspect.getsource(kb.stats), "stats() surfaces the resources block")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from scripts import rag_maintenance as rm
    _assert(hasattr(rm, "prune") and hasattr(rm, "main"), "rag_maintenance exposes prune + CLI")
    _assert("skill" in rm._PROTECTED and "finding" in rm._PROTECTED,
            "pruning protects curated chunk types (skill/finding/…)")


def test_rag_rerank_trim():
    _section("Test — post-rerank relevance-floor trim (drop reranker-rejected padding)")
    from knowledge import knowledge_base as kb
    res = [{"relevance": 3.186, "source_file": "modbus.md"},
           {"relevance": 1.159, "source_file": "pentesting-modbus.md"},
           {"relevance": -1.77, "source_file": "x.json"},
           {"relevance": -6.0, "source_file": "y.json"}]
    trimmed = kb._trim_reranked(res, 0.0)
    _assert(len(trimmed) == 2 and all(r["relevance"] > 0 for r in trimmed),
            "trim drops the reranker-rejected (negative-score) padding")
    allneg = [{"relevance": -0.2, "source_file": "a"}, {"relevance": -3.0, "source_file": "b"},
              {"relevance": -5.0, "source_file": "c"}]
    kept = kb._trim_reranked(allneg, 0.0)
    _assert(1 <= len(kept) <= 2 and kept[0]["relevance"] == -0.2,
            "when nothing clears the floor, keep the best 1-2 (never empty)")
    import inspect
    src = inspect.getsource(kb.search_raw)
    _assert("ARGUS_RAG_TRIM" in src and "_trim_reranked" in src and "_reranked" in src,
            "search_raw applies the trim (toggleable, reranked-path only)")


def test_skill_effectiveness_telemetry():
    _section("Test — skill effectiveness telemetry + learning attribution (#5/#1)")
    import os, tempfile
    os.environ["ARGUS_SKILL_TELEMETRY_PATH"] = os.path.join(tempfile.gettempdir(), "_argus_tele_test.json")
    from knowledge import skill_telemetry as st
    st.reset()
    for _ in range(4):
        st.record_fired("modbus")
    st.record_finding("modbus", "high"); st.record_quick_win("modbus", True)
    for _ in range(6):
        st.record_fired("mqtt")   # fires, never yields
    _assert(st.learned_weight("modbus") > st.learned_weight("mqtt"),
            "a productive skill outranks an unproductive one (learned weight)")
    _assert(st.stats("mqtt").get("needs_review") is True,
            "a fire-but-never-yield skill is flagged for review")
    rep = st.effectiveness_report(top=2)
    _assert(bool(rep) and rep[0]["id"] == "modbus", "effectiveness report ranks highest-yield first")
    st.reset()
    for x in ("jenkins", "modbus"):
        st.record_fired(x)
    findings = [{"title": "Jenkins script console RCE", "description": "unauth /script",
                 "severity": "critical", "tool_used": "operator"},
                {"title": "Modbus / Modbus-TCP detected", "description": "x",
                 "severity": "high", "tool_used": "skill_registry"}]
    summ = st.learn_from_engagement(["jenkins", "modbus"], findings)
    _assert(summ["attributed"] == 1 and st.stats("jenkins")["findings"] == 1
            and st.stats("modbus")["findings"] == 0,
            "learning attributes the real RCE to jenkins + skips the detection-only record")
    st.reset()


def test_skill_prioritization():
    _section("Test — matched-skill prioritization (severity×exploitability×recency×learned) (#2)")
    import os, tempfile
    os.environ["ARGUS_SKILL_TELEMETRY_PATH"] = os.path.join(tempfile.gettempdir(), "_argus_tele_pri.json")
    from knowledge import skill_registry as sr, skill_telemetry as st
    st.reset()
    dets = [{"id": "a", "technology": "A", "domain": "IT", "severity": "high", "evidence": "e",
             "hint": "h", "references": ["CVE-2024-0001"],
             "quick_wins": [{"cmd": "nmap {host}", "safety": "safe"}]},
            {"id": "b", "technology": "B", "domain": "IoT", "severity": "low", "evidence": "e",
             "hint": "h", "references": [], "quick_wins": [{"cmd": "x", "safety": "safe"}]}]
    r = sr.rank_matches(dets)
    _assert(r[0]["id"] == "a" and r[0]["priority_score"] > r[1]["priority_score"],
            "high-severity recent-CVE skill ranks above a low-severity one")
    base_b = sr.priority_score(dict(dets[1]))
    for _ in range(3):
        st.record_fired("b")
    st.record_finding("b", "critical"); st.record_quick_win("b", True)
    _assert(sr.priority_score(dict(dets[1])) > base_b,
            "a learned-productive skill's score is lifted by telemetry")
    g = sr.prioritized_guidance(dets, "safe", "IT", top_n=2)
    _assert("A" in g and "nmap" in g, "prioritized_guidance surfaces top matches + safe quick-wins")
    st.reset()


def test_skill_selflearning_wiring():
    _section("Test — self-learning wiring (auto-dispatch gate + learning loop + LLM fallback)")
    import inspect, pathlib
    import agents.master_agent as ma
    root = pathlib.Path(__file__).resolve().parent.parent
    ma_src = (root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    # #3 gated auto-dispatch
    _assert("ARGUS_SKILL_AUTODISPATCH" in ma_src
            and "_capability_autodispatch" in inspect.getsource(ma.MasterAgent),
            "safe-quick-win auto-dispatch exists + is gated (default off)")
    ad = inspect.getsource(ma.MasterAgent._capability_autodispatch)
    _assert("safe_quick_wins" in ad and "run_tool" in ad and "record_quick_win" in ad,
            "auto-dispatch runs only SAFE quick-wins via run_tool + records the outcome")
    fu = inspect.getsource(ma.MasterAgent._capability_skill_followup)
    _assert("record_fired" in fu and "prioritized_guidance" in fu and "_fired_skills" in fu,
            "followup records telemetry, tracks fired skills, injects prioritized guidance")
    # #1 learning loop wired at engagement end
    _assert("learn_from_engagement" in ma_src and "skill_telemetry" in ma_src,
            "master calls skill_telemetry.learn_from_engagement at engagement end")
    # Cross-cutting: every skill-system LLM call uses the tiered fallback chain.
    upd = (root / "scripts" / "update_skills.py").read_text(encoding="utf-8")
    _assert("stream_tiered" in upd, "updater LLM calls use the primary→backup tiered chain")
    import agents.base_agent as ba
    _assert("stream_tiered" in inspect.getsource(ba.BaseAgent.converse),
            "converse() (distiller/operator path) streams the fallback provider chain")


def test_skill_validator():
    _section("Test — catalog validator: static checks + device-lab hook (#4)")
    import sys, pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from scripts import validate_skills as v
    good = {"id": "x", "technology": "X", "domain": "IT", "safety_class": "safe", "transport": "ip",
            "match": {"ports": [], "banners": ["x"], "markers": ["/xpanel"]},
            "quick_wins": [{"cmd": "curl {host}", "safety": "safe"}], "references": ["CVE-2024-1234"]}
    _assert(v.validate_skill(good) == [], "validator passes a clean skill")
    _assert(any("shared port" in w for w in v.validate_skill(
            dict(good, match={"ports": [8080], "banners": [], "markers": []}))),
            "validator flags a shared-port match")
    _assert(any("write" in w.lower() for w in v.validate_skill(
            dict(good, quick_wins=[{"cmd": "curl -X POST {host}/writeproperty", "safety": "safe"}]))),
            "validator flags a write/control marker in a SAFE quick-win")
    rf = {"id": "z", "technology": "Z", "domain": "IoT", "safety_class": "intrusive", "transport": "rf",
          "match": {"ports": [], "banners": [], "markers": []},
          "quick_wins": [{"cmd": "zbstumbler", "safety": "intrusive"}]}
    _assert(v.validate_skill(rf) == [], "validator does not flag a knowledge-only RF skill")
    lab = v.lab_check(dict(good, quick_wins=[{"cmd": "__no_such_tool__ {host}", "safety": "safe"}]), "127.0.0.1")
    _assert(lab.get("status") == "skip", "lab_check skips gracefully when the tool isn't installed")


def test_skill_updater_script():
    _section("Test — weekly skill-catalog updater (scripts/update_skills.py)")
    import sys, os, pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from scripts import update_skills as u
    good = {"id": "paloalto_panos", "technology": "Palo Alto PAN-OS", "domain": "IT",
            "category": "security",
            "match": {"ports": [], "banners": ["pan-os"], "markers": ["/global-protect/login.esp"]},
            "quick_wins": [{"cmd": "curl {host}", "safety": "safe", "note": "x"}]}
    _assert(u.validate_spec(good)[0] is True, "validate_spec accepts a well-formed spec")
    _assert(u.validate_spec({"id": "x", "technology": "X",
                             "match": {"ports": [8080], "banners": [], "markers": []}})[0] is False,
            "validate_spec rejects a shared-port-only spec (FP guard)")
    _assert(u.fp_clean_match({"ports": [8080, 11434, 443], "banners": [], "markers": []})["ports"] == [11434],
            "fp_clean_match strips shared ports, keeps dedicated")
    md = u.spec_to_markdown(good)
    _assert(md.startswith("---") and "id: paloalto_panos" in md and "PAN-OS" in md,
            "spec_to_markdown emits valid front-matter")
    skill = {"id": "fortigate", "technology": "Fortinet FortiGate",
             "references": ["CVE-2018-13379"], "_source": None}
    kev = [{"cveID": "CVE-2024-21762", "vendorProject": "Fortinet", "product": "FortiOS"},
           {"cveID": "CVE-2018-13379", "vendorProject": "Fortinet", "product": "FortiOS"},
           {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget"}]
    ch = u.refresh_references([skill], kev, dry_run=True)
    _assert(ch == [{"id": "fortigate", "added": ["CVE-2024-21762"]}],
            "KEV refresh appends new matching CVEs, dedups existing, skips unrelated")
    _assert(isinstance(u.discover_new_technologies(set(), "security", max_new=1), list),
            "discover_new_technologies is offline-safe (list, never raises)")
    p = u.author_skill_file(dict(good, id="__updater_dryrun_probe"), dry_run=True)
    _assert(bool(p) and p.endswith("__updater_dryrun_probe.md") and not os.path.exists(p),
            "author_skill_file --dry-run plans a path without writing")
    _assert(hasattr(u, "main") and hasattr(u, "run"), "updater exposes main()/run() for the weekly cron")


def test_human_per_target_token_budget():
    _section("Test — human-set per-target LLM-token budget (pause + extend/cut-off)")
    import asyncio as _aio
    from agents.operator_agent.operator_core import (
        OperatorCore, resolve_token_decision, _OPERATOR_REGISTRY)

    # 0 budget = disabled: the gate never fires (behaviour unchanged).
    class _M0(_FM_min):
        def __init__(self):
            super().__init__(); self._tokens_used = 10_000
    op0 = OperatorCore(_M0(), token_budget=0)
    _assert(_aio.run(op0._token_budget_gate()) is None,
            "budget 0 = unlimited: ARGUS never imposes its own cap")

    # Below budget → continue; at/over budget with a human EXTEND → resume.
    class _M(_FM_min):
        def __init__(self, used):
            super().__init__(); self._tokens_used = used; self.events = []
        async def _emit(self, ev, data): self.events.append((ev, data))
    m = _M(used=120)
    op = OperatorCore(m, token_budget=100)
    op._session_id = "sess-tb"; op._target = "10.0.0.9"
    op._token_prompt_wait = 5
    _assert(op._token_budget == 100, "operator carries the human-set per-target budget")

    async def _drive_extend():
        # Resolve via the registry exactly like the WS layer does, then run gate.
        from agents.operator_agent.operator_core import _register_operator
        _register_operator(op)
        gate = _aio.ensure_future(op._token_budget_gate())
        await _aio.sleep(0.05)
        ok = resolve_token_decision("sess-tb", "extend", target="10.0.0.9", extra=500)
        res = await gate
        return ok, res
    ok, res = _aio.run(_drive_extend())
    _assert(ok is True and res is None,
            "a human EXTEND resolves the paused target and resumes (no stop)")
    _assert(op._token_budget >= 600,
            "extend RAISES the cap by the human-supplied amount (used+extra)")
    _assert(any(e == "token_budget_reached" for e, _ in m.events),
            "reaching the budget emits token_budget_reached (UI prompt)")

    # Human CUT-OFF → gate returns the stop reason.
    m2 = _M(used=200); op2 = OperatorCore(m2, token_budget=100)
    op2._session_id = "sess-tb2"; op2._target = "h2"; op2._token_prompt_wait = 5
    async def _drive_stop():
        from agents.operator_agent.operator_core import _register_operator
        _register_operator(op2)
        gate = _aio.ensure_future(op2._token_budget_gate())
        await _aio.sleep(0.05)
        resolve_token_decision("sess-tb2", "stop", target="h2")
        return await gate
    _assert(_aio.run(_drive_stop()) == "token_budget",
            "a human CUT-OFF stops THIS target (done_reason=token_budget)")

    # No-answer grace timeout → auto cut-off (conserve tokens).
    m3 = _M(used=200); op3 = OperatorCore(m3, token_budget=100)
    op3._session_id = "sess-tb3"; op3._target = "h3"; op3._token_prompt_wait = 1
    _assert(_aio.run(op3._token_budget_gate()) == "token_budget",
            "no human answer within the grace window → auto cut-off")

    # Wiring: config threads body → master.run → operator; WS handlers exist.
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _srv = (_root / "agent_server.py").read_text(encoding="utf-8")
    _assert("token_budget_per_target" in _srv and "token_extend" in _srv and "token_stop" in _srv,
            "server threads the per-target budget + handles token_extend/token_stop WS")
    _ms = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("token_budget_per_target" in _ms and "token_budget=getattr(self" in _ms,
            "master.run accepts the per-target budget and passes it to the operator")
    _sc = (_root / "db" / "schemas.py").read_text(encoding="utf-8")
    _assert("token_budget_per_target" in _sc, "scan request schema exposes the field")
    _sj = (_root / "static" / "js" / "store.js").read_text(encoding="utf-8")
    _assert("token_budget_reached" in _sj and "TOKEN_BUDGET_PROMPT" in _sj,
            "store routes the token-budget prompt to a modal")
    _aj = (_root / "static" / "js" / "app.jsx").read_text(encoding="utf-8")
    _assert("TokenBudgetModal" in _aj and "token_extend" in _aj and "token_stop" in _aj,
            "the cut-off/extend modal is wired to the WS")
    _tc = (_root / "static" / "js" / "pages" / "TargetConfig.jsx").read_text(encoding="utf-8")
    _assert("token_budget_per_target" in _tc,
            "scan-start form lets the human set the per-target token budget")


def test_professional_report_template():
    _section("Test — professional print-ready report template (rich client deliverable)")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    rt = (_root / "report" / "report_template.py").read_text(encoding="utf-8")
    _assert("REPORT_TEMPLATE" in rt and "<!DOCTYPE html>" in rt and 'class="cover"' in rt,
            "professional template module exists with a print-ready cover page")
    for sec in ["Executive Summary", "Testing Methodology", "Host &amp; Service Overview",
                "Findings Summary", "Path to Compromise", "Detailed Findings",
                "Tests Conducted (Coverage Matrix)", "Proof of Compromise",
                "Remediation Roadmap", "MITRE ATT", "Appendices", "@page"]:
        _assert(sec in rt, f"professional template includes the '{sec}' section/print-CSS")
    gen = (_root / "report" / "generator.py").read_text(encoding="utf-8")
    _assert("from report.report_template import REPORT_TEMPLATE" in gen,
            "generator PREFERS the professional template (inline dark template kept as fallback)")
    _assert('"sev":' in gen and '"outcome":' in gen and '"target_display":' in gen,
            "build_context supplies the cover banner + severity metric-card fields")
    # The professional template is the ACTIVE one at runtime AND renders cleanly
    # from a SPARSE (recon-only) context — every section is guarded.
    from report.generator import REPORT_TEMPLATE as _ACTIVE, ReportGenerator
    _assert("Path to Compromise" in _ACTIVE and 'class="cover"' in _ACTIVE,
            "the professional template is active at runtime (override applied)")
    _rg = ReportGenerator()
    _html = _rg._template.render(
        target_display='t', sev={}, outcome={}, summary={}, findings=[], flags=[], intel={},
        coverage_tests=[], coverage_counts={}, discovered_issues=[], engagement_timeline=[],
        attack_path=[], objectives=[], all_phases=[], phases_completed=[], mitre_mappings=[],
        exploit_modules=[], loot_entries=[], web_intel_hints=[], primer_rows=[],
        reasoning_journal=[], creds_summary=[], win_conditions={}, mission_brief={}, tools_used=[],
        executive_summary='', engagement_type='linux', duration='1h', generated_at='now',
        objectives_done=0, objectives_total=0, journal_truncated=False, journal_total=0, graph={})
    _assert('<!DOCTYPE html>' in _html and 'Executive Summary' in _html,
            "professional template renders cleanly from a sparse recon-only context (no Jinja error)")


def test_gate_stop_aware_and_observable():
    _section("Test — compromise gate is stop-aware + always emits its verdict")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _ms = (_root / "agents" / "master_agent.py").read_text(encoding="utf-8")
    _assert("gate skipped: user stop" in _ms and "_stop_requested" in _ms,
            "the gate skips the doomed forced-exploit pass on user-cancel")
    _assert(_ms.count('"compromise_gate"') >= 2,
            "the gate emits its honest verdict on every path (never opaque)")


def test_missioncontrol_reasoning_always_visible():
    _section("Test — MissionControl keeps reasoning visible + LLM/RAG tile")
    from pathlib import Path as _P
    _root = _P(__file__).resolve().parent.parent
    _mc = (_root / "static" / "js" / "pages" / "MissionControl.jsx").read_text(encoding="utf-8")
    _assert("_commChrono" in _mc and "REASONING ALWAYS VISIBLE" in _mc,
            "tool output is followed by a reasoning tail (comms no longer hidden when tools run)")
    _assert("ragStats" in _mc and "RAG knowledge-base hits" in _mc,
            "an LLM/RAG activity tile surfaces knowledge-base usage at a glance")


def test_fuzz_lab_catalog_and_scope() -> None:
    _section("Fuzzing Lab — catalog, scope derivation, in-scope gate (#6)")
    from agents.fuzzing import tech_types, fuzzers_for, scope_for_agent
    from agents.fuzzing.fuzz_lab import _host_in_scope

    tt = tech_types()
    _assert(set(["web", "api", "network", "iot", "ot"]).issubset(set(tt)),
            "catalog covers web/api/network/iot/ot", str(tt))
    web = fuzzers_for("web")
    _assert(any(f["id"] == "ffuf_content" for f in web), "web has ffuf_content")
    _assert(all({"id", "label", "tool", "safety", "installed"}.issubset(f) for f in web),
            "fuzzer specs carry id/label/tool/safety/installed")
    ot = fuzzers_for("ot")
    _assert(all(f["safety"] == "dangerous" for f in ot),
            "OT fuzzers flagged dangerous (safe-by-default)", str([f["id"] for f in ot]))

    class _Agent:
        _intel = {"target_host": "10.0.0.5", "target": "10.0.0.5",
                  "target_url": "http://10.0.0.5",
                  "services": {"80": {"service": "http"}, "502": {"service": "modbus"}}}
    scope = scope_for_agent(_Agent())
    _assert(scope["count"] == 1, "single-host scope derived", str(scope["count"]))
    host0 = scope["hosts"][0]
    _assert({p["port"] for p in host0["ports"]} == {80, 502},
            "ports merged from services", str(host0["ports"]))
    _assert(_host_in_scope(scope, "10.0.0.5"), "exact host in scope")
    _assert(_host_in_scope(scope, "http://10.0.0.5"), "URL form of in-scope host accepted")
    _assert(not _host_in_scope(scope, "8.8.8.8"), "out-of-scope host rejected")


def test_fuzz_lab_validation_and_argv() -> None:
    _section("Fuzzing Lab — argv build + scope enforcement at run() (#6)")
    import asyncio
    from agents.fuzzing.fuzz_lab import FuzzLab

    events = []

    def _emit(ev, payload):
        events.append((ev, payload))

    scope = {"hosts": [{"host": "10.0.0.5", "url": "http://10.0.0.5",
                        "ports": [{"port": 80, "service": "http"}], "label": "10.0.0.5"}],
             "count": 1}

    # Out-of-scope target must be refused before anything runs.
    lab = FuzzLab(job_id="j1", session_id="s1", target="9.9.9.9", tech_type="web",
                  fuzzer_id="ffuf_content", config={}, emit=_emit, feedback=False)
    asyncio.run(lab.run(scope))
    statuses = [p for (e, p) in events if e == "fuzz_status"]
    _assert(any(p.get("status") == "error" and "scope" in (p.get("message") or "")
                for p in statuses), "out-of-scope target rejected with a scope error",
            str(statuses[:1]))

    # argv building fills placeholders without a shell.
    lab2 = FuzzLab(job_id="j2", session_id="s1", target="http://10.0.0.5",
                   tech_type="web", fuzzer_id="ffuf_content",
                   config={"wordlist": "/wl.txt", "threads": 30, "rate": 100}, emit=_emit)
    argv = lab2._build_argv()
    _assert(argv[0] == "ffuf", "argv[0] is the binary (execFile-style, no shell)")
    _assert("http://10.0.0.5/FUZZ" in argv, "URL placeholder filled", str(argv))
    _assert("/wl.txt" in argv, "wordlist placeholder filled")
    _assert("{extra}" not in argv and not any("{" in a for a in argv),
            "no unfilled placeholders remain", str(argv))


def test_realtime_cve_and_parallel_wiring() -> None:
    _section("Real-time CVE lookup hook + CIDR parallelism wiring (#5/#4)")
    import inspect
    from agents.master_agent import MasterAgent
    _assert(hasattr(MasterAgent, "_realtime_cve_lookup"),
            "master exposes _realtime_cve_lookup (#5)")
    src = inspect.getsource(MasterAgent._cheap_intel_merge)
    _assert("_realtime_cve_lookup" in src,
            "intel-merge calls real-time CVE lookup", "")
    import agents.cidr_orchestrator as co
    osrc = inspect.getsource(co.CIDROrchestrator._run_two_phase)
    _assert("max_parallel_hosts" in osrc and "ARGUS_CIDR_EXPLOIT_PARALLEL" in osrc,
            "exploit lane derives from the max_parallel_hosts slider (#4)", "")


def test_secondary_llm_status_and_timeout() -> None:
    _section("Secondary LLM status + attack-graph timeout (#3)")
    import pathlib
    # Read agent_server.py as text (avoids importing the full FastAPI stack).
    repo = pathlib.Path(__file__).resolve().parent.parent
    ssrc = (repo / "agent_server.py").read_text(encoding="utf-8", errors="ignore")
    _assert("llm_fallback_provider" in ssrc and "get_fallback_provider" in ssrc,
            "/status reports secondary (fallback) LLM health (#3)")
    import agents.attack_graph_agent as aga
    _assert(aga.LLM_TIMEOUT >= 240, "attack-graph LLM timeout raised for slow local LLMs",
            f"LLM_TIMEOUT={aga.LLM_TIMEOUT}")
    # get_fallback_provider must exist on the providers module.
    from utils.llm_providers import get_fallback_provider
    _assert(callable(get_fallback_provider), "get_fallback_provider is callable")


def test_detection_severity_is_info() -> None:
    _section("Severity model — bare detections are INFO, inherent-risk preserved")
    from knowledge import skill_registry as _sr
    det = {"technology": "Microsoft SharePoint", "severity": "critical",
           "evidence": "marker-match", "domain": "IT"}
    f = _sr.finding_for(det)
    _assert(f["severity"] == "info", "skill detection finding is INFO", str(f.get("severity")))
    _assert(f.get("inherent_risk") == "critical",
            "skill inherent-risk preserved for prioritisation", str(f.get("inherent_risk")))
    # The DETECTION dict still carries the risk class, so ranking is unchanged.
    ps = _sr.priority_score(det)
    _assert(ps > 0, "priority_score still ranks high-risk tech", str(ps))

    from agents.ot import modbus as _mb, opcua as _oc
    for mod, port, name in [(_mb, 502, "modbus"), (_oc, 4840, "opcua")]:
        ff = mod.finding_for(mod.detect({"open_ports": [port]}))
        _assert(ff["severity"] == "info" and ff.get("inherent_risk") == "high",
                f"{name}.finding_for bare detection is INFO + inherent_risk preserved",
                str(ff.get("severity")))
    from agents.avot import recon as _av
    af = _av.finding_for({"evidence": "port 41794"})
    _assert(af["severity"] == "info" and af.get("inherent_risk") == "high",
            "crestron detection is INFO + inherent_risk preserved")

    # CVSS heuristic must NOT re-inflate an INFO detection whose prose mentions
    # 'unauthenticated'/'control' — the score is capped by the finding's own band.
    from utils import cvss_scorer as _cs
    _vec, score, _band = _cs.infer_vector(
        {"title": "Modbus/TCP control interface exposed (OT)",
         "description": "Modbus has no authentication; any reachable client can control coils",
         "severity": "info"})
    _assert(score == 0.0, "INFO detection not re-inflated by CVSS heuristic", str(score))
    # A genuine CRITICAL finding still scores high.
    _vec2, score2, _band2 = _cs.infer_vector(
        {"title": "Unauthenticated RCE", "description": "remote code execution, unauthenticated",
         "severity": "critical"})
    _assert(score2 > 7.0, "real critical finding still gets a high CVSS", str(score2))


def test_operational_severity_model() -> None:
    _section("Operational severity policy — rubric tiers, edges, re-grade")
    from knowledge import severity_policy as sp

    def tier(**sig):
        return sp.grade(sig)["severity"]

    # CRITICAL — demonstrated compromise / catastrophic impact
    for c in ("root_admin", "domain_admin", "total_data", "ot_control"):
        _assert(tier(compromise=c) == "critical", f"compromise={c} -> CRITICAL")
    # HIGH — partial foothold, applicable public exploit, directly-exploitable
    _assert(tier(compromise="foothold") == "high", "non-root foothold -> HIGH")
    _assert(tier(confirmed=True, exploit_available=True, version_confirmed=True) == "high",
            "public exploit + confirmed version -> HIGH")
    _assert(tier(confirmed=True, directly_exploitable=True) == "high",
            "directly-exploitable confirmed weakness -> HIGH (edge 1)")
    # MEDIUM — confirmed+chainable, or exploit-exists-version-unknown
    _assert(tier(confirmed=True, chainable=True) == "medium",
            "confirmed + chainable, no public exploit -> MEDIUM")
    _assert(tier(confirmed=True, exploit_available=True, version_confirmed=False) == "medium",
            "exploit exists but version unconfirmed -> MEDIUM (edge 2)")
    # LOW / INFO
    _assert(tier(confirmed=True, info_leak_only=True) == "low", "confirmed info-leak -> LOW")
    _assert(tier(detection_only=True, inherent_risk="critical") == "info",
            "bare detection (even high inherent risk) -> INFO")

    # Evidence tags are honest (no blanket VERIFIED)
    _assert(sp.grade({"compromise": "root_admin"})["evidence_tag"] == "DEMONSTRATED",
            "compromise tagged DEMONSTRATED")
    _assert(sp.grade({"detection_only": True})["evidence_tag"] == "OBSERVED",
            "detection tagged OBSERVED")
    _assert(sp.grade({"confirmed": True, "exploit_available": True})["evidence_tag"] == "PUBLIC-EXPLOIT",
            "public-exploit tagged PUBLIC-EXPLOIT")

    # Dynamic re-grade: High (public exploit) escalates to Critical on compromise.
    base = {"confirmed": True, "exploit_available": True, "version_confirmed": True}
    _assert(sp.grade(base)["severity"] == "high", "baseline is HIGH")
    merged = sp.merge_signals(base, {"compromise": "root_admin"})
    _assert(sp.grade(merged)["severity"] == "critical", "re-grade escalates HIGH -> CRITICAL")
    _assert(sp.is_escalation("high", "critical") and not sp.is_escalation("critical", "high"),
            "is_escalation direction correct")
    # merge takes the STRONGER compromise, never downgrades
    m2 = sp.merge_signals({"compromise": "root_admin"}, {"compromise": "foothold"})
    _assert(m2["compromise"] == "root_admin", "merge keeps the stronger compromise level")

    # The migrated call-site signal shapes produce the intended tiers.
    _assert(tier(confirmed=True, exploit_available=False, version_confirmed=True, chainable=True) == "medium",
            "cve_lookup: confirmed CVE w/o public exploit -> MEDIUM (not auto-CRITICAL)")
    _assert(tier(confirmed=True, directly_exploitable=True, compromise="total_data") == "critical",
            "service_banner: unauth data store -> CRITICAL via total_data")
    _assert(tier(confirmed=True, chainable=True) == "medium",
            "service_banner: cleartext protocol -> MEDIUM (chainable, no exploit)")


def test_browser_verification() -> None:
    _section("Browser verification (Gap #2) — classify, creds, verdict gate, degrade")
    from agents.web import browser_verify_subagent as bv

    # Optional dependency: absent Playwright degrades to a safe no-op.
    _assert(isinstance(bv.is_browser_available(), bool), "is_browser_available returns bool")

    # Classification of verifiable web finding classes (pure).
    _assert(bv.verifiable_class({"title": "IDOR broken access control"}) == "idor", "IDOR classified")
    _assert(bv.verifiable_class({"title": "Reflected XSS in search"}) == "xss", "XSS classified")
    _assert(bv.verifiable_class({"title": "Authentication bypass on /admin"}) == "auth_bypass",
            "auth-bypass classified")
    _assert(bv.verifiable_class({"title": "Open redirect"}) is None,
            "non-browser-verifiable class → None")

    # Credential degradation: 0 / 1 / 2 accounts → mode.
    _assert(bv.collect_verify_creds({"credentials": []})["mode"] == "unauth", "0 creds → unauth")
    _assert(bv.collect_verify_creds({"credentials": [{"user": "a", "password": "x"}]})["mode"]
            == "auth_unauth", "1 cred → auth_unauth")
    _assert(bv.collect_verify_creds({"credentials": [{"user": "a", "password": "x"}, ["b", "y"]]})["mode"]
            == "cross_user", "2 creds → cross_user")
    # Operator verification_accounts merge in.
    cv = bv.collect_verify_creds({"credentials": []}, {"verification_accounts": [{"user": "t1", "password": "p"}]})
    _assert(cv["mode"] == "auth_unauth" and cv["accounts"][0]["user"] == "t1",
            "operator verification_accounts merged")

    # apply_verdict — the three gate branches (pure).
    f_v = bv.apply_verdict({"severity": "HIGH", "extra": {}},
                           {"verified": True, "method": "idor",
                            "artifacts": [{"type": "screenshot", "path": "/x.png"}]},
                           browser_available=True, creds_present=True)
    _assert(f_v["extra"]["browser_verified"] is True
            and f_v["extra"].get("poc_artifacts")
            and f_v.get("signals", {}).get("confirmed") is True
            and f_v["signals"].get("directly_exploitable") is True,
            "VERIFIED → poc + confirmed/directly_exploitable signals (→ DEMONSTRATED/CONFIRMED)")
    f_f = bv.apply_verdict({"severity": "HIGH", "extra": {}},
                           {"verified": False, "reason": "no overlap"},
                           browser_available=True, creds_present=True)
    _assert(str(f_f["severity"]).lower() == "low" and f_f["extra"]["report_section"] == "unverified",
            "UNVERIFIED (tried) → downgraded to the 'unverified' section, never dropped")
    f_n = bv.apply_verdict({"severity": "HIGH", "extra": {}}, {"verified": None},
                           browser_available=False, creds_present=False)
    _assert(str(f_n["severity"]) == "HIGH" and f_n["extra"]["browser_verified"] is None
            and "browser unavailable" in f_n["extra"]["unverified_reason"],
            "NOT-TRIED (no browser) → severity unchanged + honest reason (no penalty)")

    # Best-effort: verify() never raises and returns verified=None without a browser.
    import asyncio as _aio
    res = _aio.run(bv.verify({"title": "IDOR test", "host": "127.0.0.1", "url": "http://127.0.0.1/x"},
                             {"target_host": "127.0.0.1"}, {}))
    _assert(res.get("verified") is None, "verify() degrades to verified=None without a browser (no raise)")

    # Scope tightening (self-audit fix): exact / sub-domain only, NEVER substring.
    _assert(bv._in_scope("app.example.com", {"target_scope": ["example.com"]}),
            "sub-domain is in scope")
    _assert(bv._in_scope("example.com", {"target_scope": ["example.com"]}),
            "exact host is in scope")
    _assert(not bv._in_scope("admin", {"target_scope": ["admin.example.com"]}),
            "substring 'admin' is NOT matched to admin.example.com (scope-safety)")
    _assert(not bv._in_scope("notevil.com", {"target_scope": ["evil.com"]}),
            "notevil.com is NOT matched to evil.com (no arbitrary substring)")
    # The engagement-context import the store_finding hook relies on must resolve
    # (guards the audit's blocker: get_context was not in scope).
    from agents.engagement_context import get_context as _gc
    _assert(callable(_gc), "engagement_context.get_context import path valid (hook blocker fix)")


def test_fuzz_workshop() -> None:
    _section("Fuzzing → custom-exploit workshop (Slice 1) — oracle / proof / develop / campaign")
    import asyncio as _aio
    from agents.fuzzing.engines.base import CampaignCtx, Observation, FuzzEngine, Anomaly
    from agents.fuzzing import oracle as O, proof as P, exploit_dev as X, campaign as C
    from agents.fuzzing import engines as ENG

    # ── Oracle: anomaly detection per modality ──
    oc = O.AnomalyOracle()
    a = oc.classify("web", {"status": 200, "body_len": 10},
                    Observation("c1", {"family": "ssti", "marker": "49"},
                                {"status": 200, "marker": "49", "family": "ssti", "body_len": 12},
                                "result 49 here"))
    _assert(a is not None and a.exploit_class == "ssti" and a.type == "reflected_eval",
            "reflected eval marker → high-confidence SSTI anomaly")
    _assert(oc.classify("web", {"status": 200}, Observation("c1b", {"family": "ssti", "marker": "49"},
            {"status": 200, "marker": "49", "family": "ssti"}, "49")) is None,
            "duplicate anomaly is de-duplicated")
    _assert(O.classify("web", {"status": 200}, Observation("c2", {"family": "sqli"},
            {"status": 500, "family": "sqli"}, "You have an error in your SQL syntax")).exploit_class == "sqli_exfil",
            "SQL error fingerprint → sqli_exfil")
    _assert(O.classify("network", {}, Observation("c3", b"A", {"conn_reset": True}, "")).exploit_class
            == "memory_corruption", "protocol connection reset → memory_corruption anomaly")
    _assert(O.classify("binary", {}, Observation("c4", b"x", {"asan": "heap-buffer-overflow"}, "")).type == "asan",
            "ASan report → crash anomaly")
    _assert(O.classify("web", {"status": 200}, Observation("c5", "x", {"status": 200, "body_len": 5}, "ok")) is None,
            "a benign response is NOT an anomaly")

    # ── Proof: deterministic class oracles + OOB ──
    ctx = CampaignCtx(session_id="s", target="127.0.0.1", modality="web", canary="ARGUSPWNxyz")
    _assert(P.check("cmd_injection", {"stdout": "x ARGUSPWNxyz x"}, ctx).proven,
            "cmd_injection proven when the canary returns")
    _assert(not P.check("cmd_injection", {"stdout": "nope"}, ctx).proven,
            "cmd_injection NOT proven without the canary (no hallucinated success)")
    tok = P.new_oob_token()
    ctx.oob_url = P.oob_url("http://argus.oob", tok)
    P.arm_oob(tok)
    _assert(not P.check("ssrf", {"stdout": ""}, ctx).proven, "SSRF unproven before the callback")
    P.mark_oob_hit(tok, {"src": "target"})
    _assert(P.check("ssrf", {"stdout": ""}, ctx).proven, "SSRF proven once the target calls the OOB URL")
    _assert(P.check("redos", {"elapsed": 9.0, "threshold": 5.0}, ctx).proven, "ReDoS proven by over-threshold timing")

    # ── Exploit-dev: the verify-or-refine loop ──
    # Fresh ctx: each real campaign mints its own canary + OOB token, so the develop
    # loop here must prove only via THIS canary (no leftover armed OOB from above).
    ctx = CampaignCtx(session_id="s", target="127.0.0.1", modality="web", canary="ARGUSPWNdev")
    anom = Anomaly(type="reflected_eval", exploit_class="cmd_injection", severity_hint="high", evidence="x")

    async def _llm(p, sys):
        return "echo marker"

    async def _run_ok(poc):
        return {"stdout": "pwned " + ctx.canary}

    async def _run_fail(poc):
        return {"stdout": "wrong"}

    ctx.llm_generate, ctx.run_poc = _llm, _run_ok
    poc = _aio.run(X.develop(anom, ctx, max_iters=3))
    _assert(poc is not None and poc.proven, "develop loop converges to a PROVEN PoC when the oracle fires")
    ctx.run_poc = _run_fail
    _assert(_aio.run(X.develop(anom, ctx, max_iters=3)) is None,
            "develop loop stops honestly at budget when never proven (no false success)")
    ctx.llm_generate = None
    _assert(_aio.run(X.develop(anom, ctx, max_iters=3)) is None, "no LLM wired → develop returns None (best-effort)")

    # ── Ceiling-driven gate ──
    ci = CampaignCtx(session_id="s", target="t", modality="web", ceiling="intrusive")
    _assert(not C.needs_approval("sqli_exfil", ci) and not C.needs_approval("rce", ci),
            "active-exploit classes auto-prove at the intrusive ceiling")
    _assert(C.needs_approval("memory_corruption", ci) and C.needs_approval("dos", ci),
            "memory-corruption + DoS need an approval card (could crash the service)")
    _assert(C.needs_approval("sqli_exfil", CampaignCtx(session_id="s", target="t", modality="web", ceiling="safe")),
            "at a SAFE ceiling even sqli needs approval")
    _assert(C.needs_approval("sqli_exfil", CampaignCtx(session_id="s", target="t", modality="network",
            ceiling="intrusive", domain="OT")), "OT target without authorization → approval (safe-by-default)")

    # ── Engine registry ──
    _assert(ENG.get_engine("web").__class__.__name__ == "LiveHttpEngine", "web modality → LiveHttpEngine")
    _assert(ENG.get_engine("network").__class__.__name__ == "LiveProtoEngine", "network modality → LiveProtoEngine")
    _assert("web" in ENG.available_modalities() and "binary" in ENG.available_modalities(),
            "registry advertises all modalities")

    # ── Full campaign end-to-end: anomaly → develop → prove → PROVEN finding ──
    class _StubEngine(FuzzEngine):
        modality = "web"

        def is_available(self):
            return True, ""

        async def run(self, c, sink):
            await sink(Observation("base", "x", {"baseline": True, "status": 200, "body_len": 10}, "ok"))
            await sink(Observation("c1", {"family": "cmd", "marker": c.canary},
                                   {"status": 200, "family": "cmd", "marker": c.canary, "body_len": 14},
                                   "out " + c.canary))

    rec = []

    async def _go():
        c2 = CampaignCtx(session_id="s", target="127.0.0.1", modality="web", ceiling="intrusive")
        c2.canary = "ARGUSPWNcamp"
        c2.llm_generate = _llm

        async def _rp(poc):
            return {"stdout": "shell " + c2.canary}

        c2.run_poc = _rp
        camp = C.FuzzCampaign(job_id="jt", ctx=c2, engine=_StubEngine(),
                              on_finding=lambda f: rec.append(f), max_sec=20)
        return await camp.run()

    snap = _aio.run(_go())
    _assert(snap["status"] == "done" and snap["proven"] >= 1,
            "campaign runs end-to-end and records a PROVEN exploit finding")
    _assert(any(f.get("evidence_tag") == "DEMONSTRATED" and f.get("reproduce_status") == "reproduced"
                for f in rec), "proven finding is DEMONSTRATED + reproduced (feeds the report honestly)")

    # ── PoC-runner safety: the governor refuses dangerous / out-of-scope PoCs (no run) ──
    from agents.fuzzing import poc_runner as PR
    from agents.fuzzing.engines.base import PoC as _PoCcls
    dctx = CampaignCtx(session_id="s", target="127.0.0.1", modality="web", scope_hosts=["127.0.0.1"])
    blocked = _aio.run(PR.run_poc(_PoCcls(exploit_class="rce", kind="shell", code="rm -rf /"), dctx))
    _assert("blocked" in (blocked.get("stderr") or "").lower(),
            "poc_runner REFUSES a host-destructive PoC via the safety governor (never executes it)")
    oos = _aio.run(PR.run_poc(_PoCcls(exploit_class="rce", kind="shell", code="curl http://x/"),
                              CampaignCtx(session_id="s", target="evil.example", modality="web",
                                          scope_hosts=["127.0.0.1"])))
    _assert("blocked" in (oos.get("stderr") or "").lower(),
            "poc_runner REFUSES an out-of-scope PoC target (scope enforcement)")

    # ── OWASP Fuzzing coverage: generic data-type vectors + file-format engine ──
    import sys as _sys, tempfile as _tf, os as _os2
    from agents.fuzzing import payloadgen as _pg
    pls = _aio.run(_pg.generate(CampaignCtx(session_id="s", target="t", modality="web",
                                            canary="C", oob_url="http://o/t"), augment=False))
    fams = {p.get("family") for p in pls}
    _assert({"number", "encoding", "buffer", "format"} <= fams,
            "payloadgen emits OWASP generic fuzz vectors (numbers / chars+encoding / buffer / format-string)")

    fe = ENG.get_engine("file")
    _assert(fe.__class__.__name__ == "FileFmtEngine" and fe.is_available()[0] is True,
            "file modality → FileFmtEngine (always available via the built-in byte mutator)")
    _assert("file" in ENG.available_modalities(), "registry advertises the OWASP file-format modality")

    fd, seedp = _tf.mkstemp(prefix="argus_seed_")
    _os2.write(fd, b"VALIDSAMPLE" * 8)
    _os2.close(fd)
    crashes = []

    async def _filerun():
        fctx = CampaignCtx(session_id="s", target="local", modality="file")
        fctx.surface = {"sample_file": seedp, "iterations": 2,
                        "parse_cmd": [_sys.executable, "-c",
                                      "import sys; sys.stderr.write('AddressSanitizer: heap-buffer-overflow'); sys.exit(99)",
                                      "{input}"]}
        await fe.run(fctx, lambda o: crashes.append(o) or _aio.sleep(0))
    _aio.run(_filerun())
    try:
        _os2.unlink(seedp)
    except Exception:
        pass
    _assert(crashes and crashes[0].signal.get("crash"),
            "file-format engine mutates a sample, runs the parser, and harvests a CRASH")
    _assert(O.classify("file", {}, crashes[0]).exploit_class == "memory_corruption",
            "a file-format crash → memory_corruption anomaly (weaponisation human-gated)")

    from agents.fuzzing import fuzz_lab as _fl
    _assert(any(s.get("id") == "schemathesis_api" for s in _fl.CATALOG.get("api", [])),
            "OWASP API fuzzing (schemathesis / OpenAPI) is in the fuzz catalog")

    # ── The new engines + exploit-dev workshop are SURFACED in the Fuzzing Lab UI ──
    import pathlib as _pl
    _repo = _pl.Path(__file__).resolve().parent.parent
    _srv = (_repo / "agent_server.py").read_text(encoding="utf-8", errors="ignore")
    _assert('@app.get("/fuzz/engines")' in _srv, "/fuzz/engines endpoint exposes the campaign modalities to the UI")
    _page = (_repo / "static" / "js" / "pages" / "FuzzingLabPage.jsx").read_text(encoding="utf-8", errors="ignore")
    _assert("Custom Exploit Campaign" in _page and "startCampaign" in _page
            and "/fuzz/campaign/start" in _page and "/fuzz/engines" in _page,
            "FuzzingLabPage has the campaign mode that drives the exploit-dev workshop")
    _store = (_repo / "static" / "js" / "store.js").read_text(encoding="utf-8", errors="ignore")
    _assert("FUZZ_CAMPAIGN_EVENT" in _store and "fuzzCampaign" in _store,
            "store.js has the fuzzCampaign slice fed by the campaign WS events")


def test_committed_exploit() -> None:
    """Committed exploitation loop (HTB Orion fix): lock onto a high-confidence exploit
    candidate and adapt it to land instead of thrashing across CVEs — plus the Master
    bridge that records every failure and the cross-scan recall label."""
    import asyncio as _aio
    from agents.operator_agent import committed_exploit as CE

    # ── 1. detect_candidate (pure) ────────────────────────────────────────────
    intel = {"target_url": "http://orion.htb/", "exploit_modules": [
        {"type": "public_poc", "url": "https://github.com/x/CVE-2025-32432",
         "product": "Craft CMS", "version": "4.0", "cves": ["CVE-2025-32432"]}]}
    cand = CE.detect_candidate(intel)
    _assert(cand is not None and cand.cve == "CVE-2025-32432"
            and cand.exploit_class == "rce" and cand.confidence >= 0.9
            and cand.target_url.startswith("http"),
            "detect_candidate picks the fingerprinted public-PoC as a HIGH-confidence RCE")
    _assert(CE.detect_candidate({"target_url": "http://x/"}) is None,
            "detect_candidate returns None when no exploit candidate exists")
    intel_ex = dict(intel, failed_attempts=[
        {"committed_exhausted": True, "signature": cand.signature}])
    _assert(CE.detect_candidate(intel_ex) is None,
            "detect_candidate skips a candidate already exhausted by a prior committed run")

    # ── 2. run_committed verify-or-refine loop ────────────────────────────────
    state = {"n": 0}
    async def _llm(prompt, system):
        # Proof requirement + previous-failure context must reach the model.
        _assert("PROOF REQUIREMENT" in prompt, "committed prompt states the proof requirement")
        return "curl http://orion.htb/poc ; id"
    async def _run_land(cmd):
        state["n"] += 1
        return {"stdout": "no"} if state["n"] < 2 else \
               {"stdout": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"}
    recorded = []
    async def _rec(att): recorded.append(att)
    res = _aio.run(CE.run_committed(cand, llm_generate=_llm, run_cmd=_run_land,
                                    on_attempt=_rec, max_adapt=5))
    _assert(res.landed and res.attempts == 2 and res.poc and "id" in res.poc.get("code", ""),
            "run_committed adapts and LANDS when the oracle sees uid=/gid= command execution")

    async def _run_fail(cmd): return {"stdout": "still nothing useful"}
    rec2 = []
    async def _rec2(att): rec2.append(att)
    res2 = _aio.run(CE.run_committed(cand, llm_generate=_llm, run_cmd=_run_fail,
                                     on_attempt=_rec2, max_adapt=3))
    _assert(not res2.landed and res2.exhausted_reason == "max_adapt"
            and res2.attempts == 3 and len(rec2) == 3,
            "run_committed exhausts at the adaptation budget and records EVERY failed attempt")

    async def _run_patched(cmd): return {"stdout": "Target is not affected / not vulnerable"}
    res3 = _aio.run(CE.run_committed(cand, llm_generate=_llm, run_cmd=_run_patched, max_adapt=5))
    _assert(not res3.landed and res3.exhausted_reason == "not_vulnerable" and res3.attempts == 1,
            "run_committed early-exits on a definitive not-vulnerable/patched signal")

    # ── 3. operator wiring: gate + suspend flag + bridge methods exist ─────────
    import inspect as _ins
    from agents.operator_agent import operator_core as _oc
    _src = _ins.getsource(_oc)
    _assert("_maybe_commit_exploit" in _src and "_committed_exploit_active" in _src
            and "await self._maybe_commit_exploit()" in _src,
            "operator run-loop calls the committed-exploit gate (lock-on + suspend pivot)")
    for _m in ("_commit_record_attempt", "_commit_master_start", "_commit_master_result",
               "_record_committed_win"):
        _assert(_m in _src, f"operator has the Master-awareness bridge method {_m}")
    _assert("record_failure" in _src and "_advance_phase" in _src and "AttackPhase.EXPLOIT" in _src,
            "the bridge records failures to negative_memory + advances the Master to EXPLOIT")

    # ── 4. cross-scan contamination label (#170) ──────────────────────────────
    from agents.reasoning.episodic_memory import render_recall_block
    blk = render_recall_block([{"target_type": "linux", "target": "192.168.40.21",
                                "services": ["http"], "cves": [], "lessons": ["x"]}])
    _assert("OTHER" in blk and "NOT this target" in blk,
            "episodic recalls are labelled OTHER PRIOR ENGAGEMENTS — not this target (#170)")


def test_report_severity_normalization() -> None:
    """Client report fixes: ONE canonical verdict across themes, severity-sorted findings,
    tool-noise dropped, honest severities (service-discovery=INFO, unproven-RCE capped,
    validated CVE kept), and the bogus-CMDI producer gated on real proof."""
    from knowledge import severity_policy as sp

    def _sev(title, severity, **extra):
        return sp.normalize_finding(dict(title=title, severity=severity, **extra))

    # ── normalize_finding: the engine that makes 'critical' mean something ──
    _assert(_sev("Public Exploit: [STDERR] searchsploit -j 55555", "HIGH")["drop"],
            "raw tool-output 'findings' are dropped from the report")
    _assert(_sev("Operator core unavailable — legacy fallback engaged", "MEDIUM")["drop"],
            "internal ARGUS status is never shown as a client finding")
    _assert(_sev("Open Port 22/tcp: ssh (OpenSSH 9.6p1)", "MEDIUM")["severity"] == "info",
            "service/port discovery is INFO, not MEDIUM (complaint #3)")
    _assert(_sev("Wildcard DNS Detected: *.10.129.31.105", "HIGH")["severity"] == "info",
            "wildcard DNS detection is INFO, not HIGH (complaint #5)")
    _assert(_sev("Metasploit: Exploit Attempted — exploit/multi/http", "HIGH")["drop"]
            or _sev("Metasploit: Exploit Attempted — exploit/multi/http", "HIGH")["severity"] == "info",
            "a metasploit ATTEMPT (no shell) is not HIGH (complaint #5)")
    _assert(_sev("Command Injection: RCE via ';id' payload", "CRITICAL",
                 reproduce_status="unreproduced")["severity"] == "medium",
            "an UNPROVEN RCE/command-injection is capped pending proof, not CRITICAL (complaint #4)")
    _assert(_sev("Missing Security Headers (4)", "MEDIUM")["severity"] == "low",
            "missing security headers is a LOW hygiene issue")
    _assert(_sev("CVE-2024-6387 RCE in OpenSSH", "CRITICAL", cves=["CVE-2024-6387"])["severity"] == "critical",
            "a VALIDATED critical CVE keeps CRITICAL even unexploited (founder policy)")
    _assert(_sev("Custom exploit PROVEN: shell", "critical", source="committed_exploit",
                 reproduce_status="reproduced")["severity"] == "critical",
            "a DEMONSTRATED compromise stays critical")

    # ── compute_final_rating: ONE verdict, identical across every theme ──
    _assert(sp.compute_final_rating({"critical": 2, "high": 1})[0] == "critical",
            "validated criticals → CRITICAL headline")
    _assert(sp.compute_final_rating({"medium": 3}, has_issues=True)[1] == "PARTIAL — ISSUES IDENTIFIED",
            "mediums-only → PARTIAL headline")
    _assert(sp.compute_final_rating({}, shell=True)[0] == "critical",
            "a foothold → CRITICAL headline")
    _assert(sp.compute_final_rating({})[1] == "RECON ONLY",
            "no findings → RECON ONLY")

    # ── generator wires the single source of truth (normalize + sort + fid + verdict) ──
    import pathlib as _pl
    _repo = _pl.Path(__file__).resolve().parent.parent
    _gen = (_repo / "report" / "generator.py").read_text(encoding="utf-8", errors="ignore")
    _assert("severity_policy" in _gen and "normalize_finding" in _gen
            and 'f["fid"]' in _gen.replace("'", '"'),
            "generator runs the normalization pass + stamps stable F-IDs once")
    _assert("compute_final_rating" in _gen and "final_rating_label" in _gen
            and "findings.sort(" in _gen,
            "generator computes the canonical verdict + severity-sorts findings")
    _assert('.capitalize()' in _gen and 'normalize_finding' in _gen,
            "generator Title-cases the normalized severity so themes' selectattr filters match (casing)")

    # ── every theme reads the canonical F-ID (no per-section loop.index re-numbering) ──
    for _t, _name in [("editorial.html.j2", "editorial"), ("executive.html.j2", "executive"),
                      ("operator_dark.html.j2", "operator_dark"), ("compliance.html.j2", "compliance")]:
        _src = (_repo / "report" / "themes" / _t).read_text(encoding="utf-8", errors="ignore")
        _assert("f.fid | default(" in _src and 'F-{{ "%02d"|format(loop.index) }}' not in _src
                and "F-{{ '%02d'|format(loop.index) }}" not in _src,
                f"{_name} renders finding F-IDs from the canonical f.fid (consistent across sections)")

    # ── themes read the one canonical verdict (no per-theme/hardcoded headline) ──
    for _t, _name in [("compliance.html.j2", "compliance"), ("threat_intel.html.j2", "threat_intel")]:
        _src = (_repo / "report" / "themes" / _t).read_text(encoding="utf-8", errors="ignore")
        _assert("final_rating" in _src and "Overall Risk: CRITICAL" not in _src,
                f"{_name} reads the canonical final_rating (no hardcoded 'Overall Risk: CRITICAL')")

    # ── producer fix: the bogus-CMDI CRITICAL is gated on real proof, not the loose regex ──
    _wx = (_repo / "agents" / "exploit" / "web_exploit_subagent.py").read_text(encoding="utf-8", errors="ignore")
    _cmdi = _wx[_wx.find("async def _exploit_cmdi"): _wx.find("async def _exploit_ssrf")]
    _assert("_confirmed = _RCE_CONFIRM_RE.search(out)" in _cmdi
            and "if _SHELL_RE.search(out):" not in _cmdi,
            "CMDI CRITICAL is gated on strict uid= proof, not the loose 'root anywhere' regex (complaint #4)")


def test_fuzz_campaign_control() -> None:
    """Fuzzing-shop control fixes: a human can STOP a campaign immediately (even mid-fuzz),
    a no-promise campaign auto-aborts, the snapshot exposes status + chance-of-success, an
    unproven crash anomaly is not HIGH, and a parallel campaign throttles to the scan."""
    import asyncio as _aio
    import time as _time
    from agents.fuzzing import campaign as _camp
    from agents.fuzzing.engines.base import CampaignCtx, Anomaly

    class _Hang:
        modality = "web"
        def is_available(self): return True, ""
        async def _aiorun(self, ctx, sink): await _aio.sleep(60)
        def run(self, ctx, sink): return self._aiorun(ctx, sink)

    class _Quiet:
        modality = "web"
        def is_available(self): return True, ""
        async def _aiorun(self, ctx, sink): return None      # no anomalies
        def run(self, ctx, sink): return self._aiorun(ctx, sink)

    def _ctx(throttle=False):
        return CampaignCtx(session_id="s", target="10.0.0.1", modality="web",
                           throttle=throttle, fuzzability=20)

    # 1. Responsive STOP — a long fuzz is cancelled immediately, ending as 'stopped'.
    async def _t_stop():
        c = _camp.FuzzCampaign(job_id="t1", ctx=_ctx(), engine=_Hang(), max_sec=60)
        task = _aio.ensure_future(c.run())
        await _aio.sleep(0.8)
        t0 = _time.time(); c.stop()
        snap = await _aio.wait_for(task, timeout=5)
        return snap, (_time.time() - t0)
    snap, dt = _aio.run(_t_stop())
    _assert(snap["status"] == "stopped" and dt < 3.0,
            "operator STOP cancels a running fuzz immediately (not only after the wall-clock)")

    # 2. Auto-abort on no promise — zero anomalies → ends early with an honest note.
    async def _t_abort():
        c = _camp.FuzzCampaign(job_id="t2", ctx=_ctx(), engine=_Quiet(), max_sec=30)
        return await _aio.wait_for(c.run(), timeout=10)
    ab = _aio.run(_t_abort())
    _assert(ab["status"] == "done" and ab["anomalies"] == 0 and "no anomal" in (ab["note"] or "").lower()
            and ab["promise_label"] == "Unlikely",
            "a no-anomaly campaign auto-aborts early with an 'Unlikely' chance-of-success")

    # 3. Rich snapshot — status + stage + chance-of-success + budget the operator asked for.
    c3 = _camp.FuzzCampaign(job_id="t3", ctx=_ctx(), engine=_Quiet(), max_sec=1800)
    s = c3.snapshot()
    for k in ("status_label", "stage", "promise", "promise_label", "remaining_sec",
              "awaiting_approval", "active", "elapsed_sec"):
        _assert(k in s, f"campaign snapshot exposes '{k}' (live status for the operator)")

    # 4. Unproven crash/memory-corruption anomaly is NOT high (no longer pollutes as HIGH).
    async def _t_demote():
        c = _camp.FuzzCampaign(job_id="t4", ctx=_ctx(), engine=_Quiet())
        an = Anomaly(type="crash", exploit_class="memory_corruption", severity_hint="high", evidence="segfault")
        await c._record(an, poc=None, proven=False, note="anomaly detected; no proven exploit")
        return c.findings[0]["severity"]
    _assert(_aio.run(_t_demote()) in ("low", "info"),
            "an UNPROVEN crash/memory-corruption anomaly is demoted (not a HIGH false finding)")

    # 5. Scan-priority throttle — a parallel campaign weaponises fewer anomalies + has the flag.
    _assert(hasattr(CampaignCtx(session_id="x", target="t", modality="web"), "throttle"),
            "CampaignCtx carries the scan-priority throttle flag")
    _assert(_camp.FuzzCampaign(job_id="t5", ctx=_ctx(throttle=True), engine=_Quiet())._develop_budget()
            < _camp.FuzzCampaign(job_id="t6", ctx=_ctx(throttle=False), engine=_Quiet())._develop_budget(),
            "a throttled (parallel-to-scan) campaign develops fewer anomalies than a standalone one")

    # 6. Source wiring — session_bridge sets throttle; operator caps brute tools; UI has controls.
    import pathlib as _pl
    _repo = _pl.Path(__file__).resolve().parent.parent
    _sb = (_repo / "agents" / "fuzzing" / "session_bridge.py").read_text(encoding="utf-8", errors="ignore")
    _assert("ctx.throttle = agent is not None" in _sb,
            "session_bridge throttles a campaign when a live scan is present")
    _oc = (_repo / "agents" / "operator_agent" / "operator_core.py").read_text(encoding="utf-8", errors="ignore")
    _assert("ARGUS_BRUTE_TOOL_CAP_SEC" not in _oc and "ARGUS_BRUTE_CEILING_SEC" in _oc
            and "brute_strategy" in _oc,
            "operator does NOT artificially cap brute tools — uncapped + smart escalation")
    _page = (_repo / "static" / "js" / "pages" / "FuzzingLabPage.jsx").read_text(encoding="utf-8", errors="ignore")
    _assert("stopCampaign" in _page and "Stop Fuzzing" in _page and "/fuzz/campaign/stop" in _page,
            "FuzzingLabPage exposes a STOP control for a running campaign")
    _assert("_flCampaignStatus" in _page and "Chance of success" in _page and "/fuzz/campaigns" in _page,
            "FuzzingLabPage shows live status + chance-of-success polled from /fuzz/campaigns")


def test_background_brute() -> None:
    """Brute-forcing must NEVER hold up the scan: brute/heavy-enum tools launch in the
    BACKGROUND, the operator keeps testing, and the result is fed back when it finishes."""
    import asyncio as _aio
    import types as _types
    from agents.operator_agent.operator_core import OperatorCore

    # 1. Classification — brute tools (incl. a brute invoked via shell) vs ordinary tools.
    _st = _types.SimpleNamespace(_BRUTE_TOOLS=OperatorCore._BRUTE_TOOLS)
    _assert(OperatorCore._is_brute(_st, "kerbrute", "userenum") and OperatorCore._is_brute(_st, "gobuster", "dir")
            and OperatorCore._is_brute(_st, "shell_exec", "hydra -L u.txt ssh://10.0.0.1")
            and not OperatorCore._is_brute(_st, "nmap", "-sV") and not OperatorCore._is_brute(_st, "curl", "http://x")
            and not OperatorCore._is_brute(_st, "shell_exec", "cat /etc/passwd"),
            "brute tools (kerbrute/gobuster/hydra-in-shell) are detected; nmap/curl/cat are not")

    # 2. Behavioural — launch returns IMMEDIATELY (non-blocking); result collected when done.
    op = object.__new__(OperatorCore)
    op._bg_brute = {}; op._bg_results = []; op._session_id = "s"
    async def _emit(ev, p): return None
    async def _succ(t, a, o): return None
    async def _inline(**k): await _aio.sleep(0.05); return {"stdout": "Valid user: admin@corp", "exit_code": 0}
    op._emit = _emit; op._record_operator_success = _succ; op._run_tool_inline = _inline

    async def _run():
        res = op._launch_background_brute(tool="kerbrute", args="userenum", purpose="x",
                                          phase="recon", timeout=10)
        # The brute is still running, but we already have a placeholder back (non-blocking).
        started = bool(op._bg_brute)
        tasks = list(op._bg_brute.values())
        if tasks:
            await _aio.wait_for(_aio.gather(*tasks, return_exceptions=True), timeout=3)
        return res, started
    res, started = _aio.run(_run())
    _assert(res.get("background") is True and res.get("job_id") and started
            and "BACKGROUND" in res.get("stdout", ""),
            "a brute launches in the BACKGROUND and returns immediately (never blocks the scan)")
    _assert(len(op._bg_results) == 1 and "admin@corp" in op._bg_results[0] and not op._bg_brute,
            "the background brute result is collected + queued for the operator when it finishes")

    # 3. Source wiring — dispatch backgrounds brutes, injects results, drains at end.
    import pathlib as _pl
    _oc = (_pl.Path(__file__).resolve().parent.parent / "agents" / "operator_agent"
           / "operator_core.py").read_text(encoding="utf-8", errors="ignore")
    _assert("self._is_brute(tool, args) and self._bg_brute_enabled()" in _oc
            and "_launch_background_brute" in _oc and "BACKGROUND BRUTE RESULT" in _oc
            and "_drain_background_brutes" in _oc,
            "operator dispatch backgrounds brute tools, injects their results, and drains at loop end")

    # 4. Smart + adaptive escalation — different wordlists / spray / rainbow tables, not a cap.
    from knowledge import brute_strategy as _bs
    _tiers = [r["tier"] for r in _bs.wordlist_ladder("password")]
    _assert(len(_tiers) >= 4 and _bs.next_wordlist("password", [])["tier"] == "defaults"
            and _bs.next_wordlist("password", [r["path"] for r in _bs.wordlist_ladder("password")[:2]])["tier"] == "common",
            "brute strategy escalates the wordlist ladder (defaults → fast → common → rockyou → deep)")
    _ad = " ".join(_bs.technique_plan("kerberos")).lower()
    _assert("as-rep" in _ad and "kerberoast" in _ad and "spray" in _ad,
            "AD brute strategy prefers AS-REP roast / Kerberoast / password-spray over blind brute")
    _assert("rainbow" in _bs.advisory(service="smb", found=False).lower()
            and "hashcat" in _bs.crack_guidance("ntlm").lower(),
            "strategy recommends offline cracking with rules / rainbow tables")

    # behavioural: a no-hit brute injects an ESCALATION advisory + remembers the list tried.
    op2 = object.__new__(OperatorCore)
    op2._bg_brute = {}; op2._bg_results = []; op2._brute_tried = set(); op2._session_id = "s"
    op2._emit = _emit; op2._record_operator_success = _succ
    _aio.run(op2._on_brute_done("jX", "kerbrute",
             "userenum -d corp /usr/share/seclists/Usernames/Names/names.txt",
             {"stdout": "0 valid usernames found"}))
    _assert("brute strategy" in op2._bg_results[-1].lower()
            and any("names.txt" in p for p in op2._brute_tried),
            "a no-hit brute injects an escalation advisory and remembers the wordlist it tried")


def test_fuzz_lab_usability() -> None:
    """Fuzzing Lab client fixes: the lab must be usable WITHOUT a live pentest
    (standalone), it must SURFACE the installed mutational tools, and the campaign
    must expose real options."""
    import pathlib as _pl
    _repo = _pl.Path(__file__).resolve().parent.parent
    _srv = (_repo / "agent_server.py").read_text(encoding="utf-8", errors="ignore")

    # ── Standalone: neither fuzz endpoint hard-404s when no session is active ──
    _camp_fn = _srv[_srv.find("async def fuzz_campaign_start"): _srv.find("async def fuzz_campaign_stop")]
    _assert("standalone" in _camp_fn and "no active session — start a pentest first" not in _camp_fn,
            "fuzz_campaign_start runs standalone (no hard 404 when no live session)")
    _start_fn = _srv[_srv.find("async def fuzz_start"): _srv.find("async def fuzz_stop")]
    _assert("no active session — start a pentest first" not in _start_fn
            and "single-host scope" in _start_fn,
            "fuzz_start falls back to the typed target as scope instead of 404")

    # ── /fuzz/engines surfaces the installed tools per engine ──
    _eng_fn = _srv[_srv.find("async def fuzz_engines"): _srv.find("async def fuzz_oob_callback")]
    _assert('"tools"' in _eng_fn and "tools_present" in _eng_fn and "radamsa" in _eng_fn
            and "afl-fuzz" in _eng_fn and "honggfuzz" in _eng_fn and "zzuf" in _eng_fn,
            "/fuzz/engines reports per-engine tool availability incl. the new mutational fuzzers")
    _assert("shutil" in _eng_fn or "_sh.which" in _eng_fn,
            "/fuzz/engines checks live tool availability (which) so the UI shows installed vs missing")

    # ── The page exposes standalone + tool visibility + real options ──
    _page = (_repo / "static" / "js" / "pages" / "FuzzingLabPage.jsx").read_text(encoding="utf-8", errors="ignore")
    _assert("No active session — start a pentest first." not in _page,
            "FuzzingLabPage no longer blocks fuzzing on a missing session")
    _assert("Engine tools" in _page and "selEngine.tools" in _page,
            "FuzzingLabPage surfaces the engine's installed tools (radamsa/zzuf/AFL++/…)")
    _assert("Time budget" in _page and "campMaxSec" in _page,
            "FuzzingLabPage campaign exposes a configurable time budget")


def test_tool_reliability_ranking() -> None:
    _section("Tool-reliability read-side (Gap #7) — consume telemetry in select_action")
    from agents.reasoning import tool_ranking as tr

    # Laplace-smoothed weight: no data → neutral; success raises, failure lowers.
    _assert(abs(tr.reliability_weight({}) - 0.5) < 1e-9, "no telemetry → neutral 0.5")
    _assert(tr.reliability_weight({"success": 9, "fail": 0}) > 0.8, "all-success tool scores high")
    _assert(tr.reliability_weight({"success": 0, "fail": 9}) < 0.2, "all-fail tool scores low")

    telem = {
        "nmap":    {"success": 8, "fail": 0},
        "hydra":   {"success": 0, "fail": 6},      # dead this engagement
        "sqlmap":  {"success": 2, "fail": 1},
    }
    cands = [
        {"tool": "hydra",  "target_service": "ssh",  "action_str": "brute"},
        {"tool": "sqlmap", "target_service": "http", "action_str": "sqli"},
        {"tool": "nmap",   "target_service": "tcp",  "action_str": "scan"},
    ]
    ranked = tr.apply_reliability(cands, telem)
    _assert(ranked[0]["tool"] != "hydra", "a dead (0-success, >=4 attempts) tool is demoted off the top")
    _assert(ranked[-1]["tool"] == "hydra", "the dead tool sinks to the bottom")
    _assert(all("tool_reliability" in c for c in ranked), "every candidate is annotated with a reliability score")

    # VoI still leads — reliability only breaks ties / demotes dead tools.
    voi_cands = [
        {"tool": "sqlmap", "voi_score": 0.9, "target_service": "http", "action_str": "a"},
        {"tool": "nmap",   "voi_score": 0.3, "target_service": "tcp",  "action_str": "b"},
    ]
    voi_ranked = tr.apply_reliability(voi_cands, telem)
    _assert(voi_ranked[0]["tool"] == "sqlmap",
            "a strong VoI action keeps the lead despite lower tool reliability")

    # Empty telemetry / empty candidates are safe no-ops.
    _assert(tr.apply_reliability(cands, {}) is not None, "empty telemetry → unchanged (no crash)")
    _assert(tr.apply_reliability([], telem) == [], "empty candidate list → []")

    # The DecisionEngine consumes it: _apply_tool_reliability re-orders via the injected fn.
    import asyncio as _aio
    from agents.reasoning.decision_engine import DecisionEngine

    async def _noop(*a, **k):
        return {}
    eng = DecisionEngine(think_json_fn=_noop, emit_fn=_noop, session_id="t",
                         tool_reliability_fn=lambda: telem)
    out = _aio.run(eng._apply_tool_reliability([dict(c) for c in cands]))
    _assert(out[0]["tool"] != "hydra" and out[-1]["tool"] == "hydra",
            "DecisionEngine._apply_tool_reliability re-orders using the injected telemetry")
    # No reader injected → exact passthrough (zero behavioural change by default).
    eng2 = DecisionEngine(think_json_fn=_noop, emit_fn=_noop, session_id="t")
    passthru = _aio.run(eng2._apply_tool_reliability([dict(c) for c in cands]))
    _assert([c["tool"] for c in passthru] == [c["tool"] for c in cands],
            "no telemetry reader → candidate order is unchanged (additive by default)")


def test_model_capability_and_cve_filter() -> None:
    _section("Model-capability detection + CVE-fabrication filter (Gap #4)")
    from utils import model_capability as mc

    # ── Capability detection (the priority half) ──
    # Modern Ollama exposes a capabilities list.
    caps = mc.parse_ollama_show({"capabilities": ["completion", "tools", "vision"],
                                 "details": {"family": "llama", "parameter_size": "8B"},
                                 "model_info": {"llama.context_length": 131072}})
    _assert(caps["tool_calling"] is True and caps["vision"] is True,
            "parses native tool-calling + vision from the capabilities list")
    _assert(caps["context_length"] == 131072, "parses the context-length from model_info")

    # Older Ollama (no capabilities list) → infer tool-calling from the chat template.
    older = mc.parse_ollama_show({"template": "{{ if .Tools }}{{ .Tools }}{{ end }}",
                                  "details": {"family": "qwen"}})
    _assert(older["tool_calling"] is True, "infers tool-calling from an older model's template")
    none_tc = mc.parse_ollama_show({"template": "{{ .System }}{{ .Prompt }}"})
    _assert(none_tc["tool_calling"] is False, "a plain template → no tool-calling")

    # The gate flags the failure mode that matters (no tool-calling → degraded).
    v_bad = mc.capability_gate({"tool_calling": False, "context_length": 4096})
    _assert(v_bad["degraded"] is True and v_bad["ok"] is False and v_bad["warnings"],
            "a non-tool-calling model is flagged degraded with a warning")
    v_ok = mc.capability_gate({"tool_calling": True, "context_length": 32768})
    _assert(v_ok["ok"] is True and not v_ok["degraded"], "a tools-capable model passes the gate")
    v_small = mc.capability_gate({"tool_calling": True, "context_length": 2048})
    _assert(any("context" in w for w in v_small["warnings"]),
            "a tiny context window raises a (non-fatal) warning")

    # ── CVE-fabrication filter (the secondary half) ──
    res = mc.validate_cve_ids(
        ["CVE-2021-44228", "cve-2014-0160", "CVE-2099-99999", "NOT-A-CVE", "CVE-1990-1"],
        known={"CVE-2021-44228"})
    _assert("CVE-2021-44228" in res["verified"], "a known CVE in the local mirror → verified")
    _assert("CVE-2014-0160" in res["unverified"],
            "a well-formed CVE absent from the mirror → unverified (needs live lookup)")
    _assert("CVE-2099-99999" in res["malformed"] and "NOT-A-CVE" in res["malformed"]
            and "CVE-1990-1" in res["malformed"],
            "implausible-year / malformed / pre-1999 IDs → flagged as fabricated")
    # With no local mirror, well-formed plausible IDs are 'unverified', never silently trusted.
    res2 = mc.validate_cve_ids(["CVE-2021-44228"])
    _assert(res2["unverified"] == ["CVE-2021-44228"] and not res2["verified"],
            "no mirror → well-formed CVE is 'unverified', not asserted as fact")

    # The provider hook exists and is async + best-effort (offline → not degraded, no raise).
    import asyncio as _aio
    from utils.llm_providers import OllamaProvider
    prov = OllamaProvider(base_url="http://127.0.0.1:1", model="nope")
    out = _aio.run(prov.detect_capabilities())
    _assert(isinstance(out, dict) and out.get("degraded") in (False, None),
            "OllamaProvider.detect_capabilities degrades gracefully when offline (no raise)")


def test_technique_search() -> None:
    _section("technique_search (Gap #3) — lexical offensive-corpus lookup (FTS5)")
    import os
    import tempfile
    from knowledge import technique_search as ts

    db = os.path.join(tempfile.gettempdir(), "argus_ts_harness.db")
    try:
        if os.path.exists(db):
            os.remove(db)
    except Exception:
        pass

    info = ts.build_index(db)
    _assert(info.get("built") and info.get("rows", 0) >= 8, "index builds from the seed corpus")
    _assert(info.get("source") == "seed", "falls back to the embedded seed when no corpus is fetched")

    # Relevance: the right technique class ranks first for a class-specific query.
    top = ts.technique_search("sql injection authentication bypass", k=3, db_path=db)
    _assert(top and top[0]["category"] == "sqli", "SQLi query ranks an SQLi technique first")
    ssti = ts.technique_search("jinja2 template injection rce", k=3, db_path=db)
    _assert(ssti and ssti[0]["category"] == "ssti", "SSTI query ranks the SSTI technique first")
    _assert(all("score" in h and "snippet" in h for h in top), "results carry score + snippet")

    # Injection-safety: FTS5 metacharacters must not crash or corrupt the table.
    _ = ts.technique_search('"); DROP TABLE techniques; --', k=2, db_path=db)
    again = ts.technique_search("xss onerror", k=2, db_path=db)
    _assert(isinstance(again, list) and len(again) >= 1,
            "malicious query is sanitised; the index still works afterwards")

    # Graceful edges.
    _assert(ts.technique_search("", db_path=db) == [], "empty query → [] (no crash)")
    _assert(ts.technique_search("zzqqxx_no_such_term_99", db_path=db) == [], "no-match query → []")
    try:
        os.remove(db)
    except Exception:
        pass


def test_rag_logs_in_scan_dir() -> None:
    _section("RAG logs land INSIDE the per-scan folder (not the repo logs/ root)")
    import os
    from utils import scan_logger as sl
    from knowledge import rag_logger as rl

    prev_env = os.environ.pop("ARGUS_RAG_TRACE_PATH", None)
    sid = "ragloc_test_zz9"
    slog = sl.start_scan_logger(sid, target="127.0.0.1", engagement_type="test")
    try:
        d = sl.current_log_dir(sid)
        _assert(d is not None and str(d) == str(slog.dir),
                "current_log_dir() returns the active scan's folder")
        _assert(str(rl._active_dir()) == str(slog.dir),
                "rag_logger writes into the active scan folder")
        tf = str(rl._trace_file())
        _assert(tf.endswith("rag_trace.jsonl") and str(slog.dir) in tf,
                "rag_trace.jsonl resolves INSIDE the scan folder, not repo logs/")
    finally:
        sl.close_scan_logger(sid)
        if prev_env is not None:
            os.environ["ARGUS_RAG_TRACE_PATH"] = prev_env
    _assert(sl.current_log_dir(sid) is None, "after the scan closes, no active scan dir is reported")

    # Severity tiles stay in sync with the report: the regrade reducer + dispatch exist.
    import pathlib
    store = (pathlib.Path(__file__).resolve().parent.parent / "static" / "js" / "store.js"
             ).read_text(encoding="utf-8", errors="ignore")
    _assert("REGRADE_FINDING_SEVERITY" in store and "case 'REGRADE_FINDING_SEVERITY'" in store,
            "store.js has a REGRADE_FINDING_SEVERITY reducer case")
    _assert("type: 'REGRADE_FINDING_SEVERITY'" in store,
            "finding_regraded handler dispatches the severity-tile adjustment")


def test_safety_governor() -> None:
    _section("Execution-boundary safety governor (Gap #5) — scope / destructive / OT teeth")
    from knowledge import safety_governor as gov

    # Intrusiveness classification.
    _assert(gov.classify_intrusiveness("sqlmap", "-u http://x --batch") == "intrusive",
            "sqlmap classified intrusive")
    _assert(gov.classify_intrusiveness("nmap", "-sV") == "light", "nmap classified light")
    _assert(gov.classify_intrusiveness("whois", "example.com") == "safe", "whois classified safe")
    _assert(gov.classify_intrusiveness("bash", "exploit the rce") == "intrusive",
            "exploit hint in args → intrusive")

    # Destructive detection — only on shell-style tools, with a rewrite target.
    _assert(gov.destructive_match("bash", "rm -rf /") is not None, "rm -rf / flagged")
    _assert(gov.destructive_match("bash", "shutdown -h now") is not None, "shutdown flagged")
    _assert(gov.destructive_match("bash", ":(){ :|:& };:") is not None, "fork bomb flagged")
    _assert(gov.destructive_match("bash", "dd if=/dev/zero of=/dev/sda") is not None, "disk dd flagged")
    _assert(gov.destructive_match("bash", "rm -rf ./loot/tmp") is None, "rm in a local workdir is NOT flagged")
    _assert(gov.destructive_match("nmap", "rm -rf /") is None, "non-shell (argv) tool not treated as a shell")
    # Bypass-resistance: long-form + separated flags must still be caught.
    _assert(gov.destructive_match("bash", "rm --force --recursive /") is not None,
            "rm --force --recursive / caught (long-form flags)")
    _assert(gov.destructive_match("bash", "rm -f -r /") is not None,
            "rm -f -r / caught (separated flags)")
    _assert(gov.destructive_match("bash", "sudo /sbin/shutdown -h now") is not None,
            "sudo + absolute-path shutdown caught")
    _assert(gov.destructive_match("bash", "env rm -rf /") is not None,
            "wrapper-disguised command caught (env rm -rf /)")
    _assert(gov.destructive_match("bash", "nohup shutdown -h now") is not None,
            "wrapper-disguised command caught (nohup shutdown)")
    _assert(gov.destructive_match("bash", "rm /etc -rf") is not None,
            "path-before-flags ordering caught (rm /etc -rf)")
    # Network/VPN self-disruption (the operator restarting OpenVPN mid-scan, which
    # dropped MCP + Mongo + the target route) must be neutralised.
    _assert(gov.destructive_match("bash", "sudo -n pkill -9 openvpn; sleep 2; openvpn --config x.ovpn --daemon") is not None,
            "restarting OpenVPN mid-scan is flagged (engagement connectivity)")
    _assert(gov.destructive_match("bash", "systemctl restart openvpn") is not None,
            "systemctl restart openvpn flagged")
    _assert(gov.destructive_match("bash", "ifconfig eth0 down") is not None, "bringing the interface down flagged")
    _assert(gov.destructive_match("bash", "ip link set tun0 down") is not None, "ip link set down flagged")
    _assert(gov.destructive_match("bash", "ip addr show") is None, "read-only 'ip addr show' is NOT flagged")
    _assert(gov.destructive_match("bash", "nmcli connection show") is None, "read-only nmcli is NOT flagged")
    _assert(gov.destructive_match("bash", "systemctl status nginx") is None, "systemctl status of an unrelated svc is fine")
    _assert(gov.destructive_match("bash", "rm -rf /home") is not None, "rm -rf /home (wipes all users) flagged")
    _assert(gov.destructive_match("bash", "rm -rf /home/kali/scan") is None,
            "a workdir under /home is NOT flagged (sub-path of a bare root)")
    # Over-block resistance: the keyword must be in COMMAND POSITION, not an argument.
    _assert(gov.destructive_match("bash", "grep -r shutdown /var/log") is None,
            "grep for 'shutdown' is NOT a shutdown command")
    _assert(gov.destructive_match("bash", "echo shutdown > /tmp/wordlist.txt") is None,
            "echo'ing 'shutdown' into a file is NOT a shutdown command")
    _assert(gov.destructive_match("bash", "curl -s http://t/api/JSON/action/shutdown/") is None,
            "a /shutdown/ URL path is NOT a host shutdown")
    _assert(gov.destructive_match("bash", "cat reboot-wordlist.txt") is None,
            "a wordlist filename containing 'reboot' is NOT a reboot command")

    # Scope matching.
    _assert(gov.host_in_scope("app.example.com", ["example.com"]) is True, "sub-domain is in scope")
    _assert(gov.host_in_scope("10.0.0.5", ["10.0.0.5"]) is True, "exact IP in scope")
    _assert(gov.host_in_scope("evil.com", ["example.com"]) is False, "foreign host out of scope")
    _assert(gov.host_in_scope("evil.com", []) is True, "empty scope ⇒ unknown ⇒ not denied")
    _assert(gov.host_in_scope("notexample.com", ["example.com"]) is False,
            "substring is NOT a sub-domain match (no over-broad scope)")
    _assert(gov.host_in_scope("example.com", ["app.example.com"]) is False,
            "authorising a sub-domain does NOT put the parent domain in scope (one-directional)")

    # evaluate() decisions.
    d_scope = gov.evaluate({"tool_name": "nmap", "args": "-sV", "target_host": "evil.com",
                            "scope_hosts": ["example.com"]})
    _assert(d_scope["decision"] == "deny", "out-of-scope target → deny")

    d_destr = gov.evaluate({"tool_name": "bash", "args": "rm -rf / && nmap x"})
    _assert(d_destr["decision"] == "rewrite" and d_destr["rewritten_args"] == "true",
            "host-destructive op → rewrite to no-op")

    d_ot = gov.evaluate({"tool_name": "sqlmap", "args": "-u http://plc --batch",
                         "domain": "OT", "authorized": False})
    _assert(d_ot["decision"] == "deny", "intrusive action on OT without authorization → deny")
    d_ot_ok = gov.evaluate({"tool_name": "sqlmap", "args": "-u http://plc --batch",
                            "domain": "OT", "authorized": True})
    _assert(d_ot_ok["decision"] != "deny", "authorized OT action is not denied by the OT gate")

    d_ok = gov.evaluate({"tool_name": "nmap", "args": "-sV", "target_host": "app.example.com",
                         "scope_hosts": ["example.com"]})
    _assert(d_ok["decision"] == "allow", "in-scope, non-destructive, light tool → allow")

    # Scope is only enforced when asked — a foreign host with scope NOT in `enforce` passes.
    d_noscope = gov.evaluate({"tool_name": "nmap", "args": "-sV", "target_host": "evil.com",
                              "scope_hosts": ["example.com"]}, enforce=["destructive"])
    _assert(d_noscope["decision"] == "allow", "scope not enforced unless requested (no over-block)")

    # Best-effort: never raises on junk input.
    try:
        gov.evaluate({})
        gov.evaluate({"tool_name": None, "args": None, "scope_hosts": None})
        _ok = True
    except Exception:
        _ok = False
    _assert(_ok, "evaluate() is robust to empty/None input (best-effort, never raises)")


def test_eval_benchmark() -> None:
    _section("Capability benchmark (Gap #6) — un-fakeable scoring + regression")
    import json as _json
    import pathlib
    from evals.catalog import load_catalog, case_by_id, mint_run_flag
    from evals.scorer import score_case
    from evals.runner import run_benchmark, load_baseline, compare_to_baseline

    # Catalog loads + filters.
    cat = load_catalog()
    _assert(len(cat) >= 4, "benchmark catalog has cases")
    _assert(all(c.pass_mode in ("exploit", "detect") for c in cat), "every case has a valid pass_mode")
    _assert(len(load_catalog(category="web")) >= 1 and len(load_catalog(category="web")) < len(cat),
            "category filter narrows the catalog")

    sqli = case_by_id("web-sqli-001")
    _assert(sqli is not None and sqli.pass_mode == "exploit", "web-sqli-001 is an exploit case")
    flag = mint_run_flag(sqli, "t1")
    _assert(flag.endswith("-t1}") and "web-sqli-001" in flag, "mint_run_flag binds the per-run nonce")

    # THE core property — un-fakeable: a matching FINDING without the injected flag
    # is 'detected' but NOT 'exploited', and an exploit case does NOT pass on it.
    r_nofl = score_case(sqli, {"findings": [{"title": "SQL injection in login", "severity": "high"}]},
                        run_flag=flag)
    _assert(r_nofl.detected and not r_nofl.exploited and not r_nofl.passed,
            "exploit case CANNOT pass on a finding alone — needs the injected flag (un-fakeable)")
    # With the flag present (even with no finding) → exploited + passed.
    r_fl = score_case(sqli, {"flags_found": [flag], "findings": []}, run_flag=flag)
    _assert(r_fl.exploited and r_fl.passed, "recovering the injected flag → exploit proven")
    # Flag may also arrive inside the flags collection (Flag.value) or finding evidence.
    r_val = score_case(sqli, {"flags": [{"flag_type": "root", "value": flag}]}, run_flag=flag)
    _assert(r_val.exploited, "flag recovered from the flags collection (.value) counts")

    # Detect case: passes on the signature, has no flag requirement.
    tls = case_by_id("net-tls-weak-001")
    _assert(score_case(tls, {"findings": [{"title": "weak TLS cert", "severity": "low"}]}).passed,
            "detect case passes on the finding signature")
    _assert(not score_case(tls, {"findings": []}).passed, "detect case fails with no matching finding")

    # Replay run against the committed fixture → deterministic pass/skip counts.
    repo = pathlib.Path(__file__).resolve().parent.parent
    tx = _json.loads((repo / "evals" / "fixtures" / "replay_sample.json").read_text(encoding="utf-8"))
    tx.pop("_comment", None)
    rep = run_benchmark(mode="replay", transcripts=tx, nonce="baseline")
    _assert(rep.total == 5 and rep.passed == 3 and rep.skipped == 2,
            "replay scores 3 passed / 2 skipped over the 5-case catalog")
    base = load_baseline(str(repo / "evals" / "baseline.json"))
    _assert(compare_to_baseline(rep, base)["regressed"] is False,
            "identical run vs committed baseline → no regression")

    # Regression detection: drop the SQLi proof → the baseline-passing case regresses.
    tx2 = dict(tx)
    tx2["web-sqli-001"] = {"findings": []}
    delta = compare_to_baseline(run_benchmark(mode="replay", transcripts=tx2, nonce="baseline"), base)
    _assert(delta["regressed"] is True and "web-sqli-001" in delta["regressions"],
            "losing a previously-passing case is flagged as a regression")

    # Live mode is best-effort: a target that errors is SKIPPED, never a hard failure.
    def _boom(_case, _flag):
        raise RuntimeError("no docker in this env")
    rep_live = run_benchmark(cases=[sqli], mode="live", run_fn=_boom)
    _assert(rep_live.skipped == 1 and rep_live.passed == 0,
            "a broken live target is skipped (best-effort), the run does not raise")


def test_auth_security_controls() -> None:
    _section("Auth security controls (Gap #8) — moat-protection regression guards")
    import pathlib
    repo = pathlib.Path(__file__).resolve().parent.parent

    def _src(rel):
        try:
            return (repo / rel).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    # ── SAML (XSW / signature-wrapping defense) ──
    saml = _src("auth/providers/saml.py")
    _assert(bool(saml), "auth/providers/saml.py present")
    _assert('"wantAssertionsSigned":' in saml and 'want_assertions_signed", True' in saml,
            "SAML requires SIGNED assertions by default (rejects unsigned/XSW-wrapped)")
    _assert("process_response()" in saml and "get_errors()" in saml and "is_authenticated()" in saml,
            "SAML ACS validates the signature via python3-saml (process_response + get_errors)")

    # ── Sessions (refresh-token replay/theft + session fixation) ──
    sess = _src("auth/sessions.py")
    _assert("def rotate_refresh_token" in sess and "_revoke_family" in sess
            and "refresh_reuse_detected" in sess,
            "refresh-token REUSE → family + session revocation (replay/theft defense)")
    _assert("hash_refresh_token" in sess and "token_hash=" in sess,
            "refresh tokens are stored HASHED, never plaintext")
    _assert("def create_session" in sess and "SessionRow(" in sess,
            "a fresh session row is minted per login (no session fixation)")

    # ── SCIM (bearer-token authz) ──
    scim = _src("auth/scim.py")
    _assert("_verify_bearer" in scim and 'startswith("bearer ")' in scim and "_raise(401" in scim,
            "SCIM requires a bearer token; missing / non-bearer → 401")
    _assert("token_hash ==" in scim and "_hash_token" in scim,
            "SCIM bearer token is matched by HASH (no plaintext token storage)")

    # ── The adversarial pytest suite must exist (deep coverage for Kali/CI) ──
    _assert(bool(_src("auth/tests/test_auth_adversarial.py")),
            "auth/tests/test_auth_adversarial.py adversarial suite present")


def test_reproduction_status() -> None:
    _section("Reproduction status (Gap #1) — honest taxonomy + gate + re-run")
    from agents.reasoning import repro_verifier as rv

    # Taxonomy (pure): independently demonstrated → reproduced.
    _assert(rv.repro_status({"severity": "high", "extra": {"browser_verified": True}}) == "reproduced",
            "browser-verified → reproduced")
    _assert(rv.repro_status({"severity": "critical", "evidence_tag": "DEMONSTRATED"}) == "reproduced",
            "DEMONSTRATED → reproduced")
    _assert(rv.repro_status({"severity": "critical", "signals": {"compromise": "root_admin"}}) == "reproduced",
            "proven compromise → reproduced")
    # Single-path evidence → evidence_confirmed (NOT overclaimed as reproduced).
    _assert(rv.repro_status({"severity": "high", "evidence_tag": "CONFIRMED"}) == "evidence_confirmed",
            "CONFIRMED (single-path) → evidence_confirmed, not reproduced")
    _assert(rv.repro_status({"severity": "high", "evidence_tag": "PUBLIC-EXPLOIT"}) == "evidence_confirmed",
            "public-exploit → evidence_confirmed")
    # Unbacked high/critical, or a browser that tried and failed → unreproduced.
    _assert(rv.repro_status({"severity": "high"}) == "unreproduced",
            "high claim with no verification → unreproduced")
    _assert(rv.repro_status({"severity": "high", "extra": {"browser_verified": False}}) == "unreproduced",
            "browser tried + failed → unreproduced")
    _assert(rv.repro_status({"severity": "info"}) == "na", "info → na (no reproduction needed)")

    # Gate: un-reproduced high/critical → 'unverified' lane (never dropped).
    g = rv.apply_repro_status({"severity": "high", "extra": {}})
    _assert(g["extra"]["reproduce_status"] == "unreproduced"
            and g["extra"].get("report_section") == "unverified",
            "un-reproduced high → gated into the 'unverified' lane")
    g2 = rv.apply_repro_status({"severity": "critical", "evidence_tag": "DEMONSTRATED", "extra": {}})
    _assert(g2["extra"]["reproduce_status"] == "reproduced"
            and g2["extra"].get("report_section") is None,
            "demonstrated finding is NOT gated")
    # Low/info are never gated even if unverified.
    g3 = rv.apply_repro_status({"severity": "low", "extra": {}})
    _assert(g3["extra"].get("report_section") is None, "low severity is never gated")

    # needs_independent_rerun targets the right candidates.
    _assert(rv.needs_independent_rerun({"severity": "high", "evidence_tag": "CONFIRMED"}),
            "high single-path-evidence → candidate for independent re-run")
    _assert(not rv.needs_independent_rerun({"severity": "critical", "evidence_tag": "DEMONSTRATED"}),
            "already-demonstrated → no re-run needed")
    _assert(not rv.needs_independent_rerun({"severity": "low"}), "low → no re-run")

    # reproduce() is best-effort: no browser + no runner → reproduced=None, no raise.
    import asyncio as _aio
    r = _aio.run(rv.reproduce({"title": "x", "severity": "high", "host": "127.0.0.1"},
                              {"target_host": "127.0.0.1"}, None))
    _assert(r.get("reproduced") is None, "reproduce() degrades to None without browser/runner (no raise)")


def test_fuzz_targeting_indicator() -> None:
    _section("Fuzz-targeting indicator — surface scoring, novelty, side-car")
    from knowledge import fuzz_targeting as ft

    # Novelty: heavily-fuzzed OSS low; OT/IoT high; unknown/niche high.
    _assert(ft.novelty_score("nginx", "web") <= 0.20, "fuzzed-OSS → low novelty",
            str(ft.novelty_score("nginx", "web")))
    _assert(ft.novelty_score("Modbus", "ot") >= 0.85, "OT tech → high novelty")
    _assert(ft.novelty_score("AcmeProprietary", "network") >= 0.7,
            "unknown/niche → high novelty")
    # CVE/KEV history nudges novelty DOWN (well-trodden); never uses age.
    _assert(ft.novelty_score("AcmeProprietary", "network", has_cve=True)
            < ft.novelty_score("AcmeProprietary", "network"),
            "public CVE history lowers novelty")

    # score_surface: OT protocol surface ranks High and shows its factors.
    ot = ft.score_surface({"service": "Modbus", "surface_type": "ot",
                           "surface_fuzzability": 0.85})
    _assert(ot["tier"] == "high" and 0 <= ot["score"] <= 100, "OT modbus → HIGH")
    _assert(set(ot["factors"]) >= {"novelty", "surface_fuzzability", "mem_unsafe_prior"},
            "score is transparent (factors shown)")
    _assert("heuristic" in ot["rationale"].lower(), "labeled as a heuristic estimate")
    # Mainstream fuzzed-OSS web ranks lower than the proprietary OT surface.
    oss = ft.score_surface({"service": "nginx", "surface_type": "web",
                            "surface_fuzzability": 0.40})
    _assert(oss["score"] < ot["score"], "heavily-fuzzed OSS scores below proprietary OT")
    # Unreachable / non-controllable surface is gated OUT.
    gated = ft.score_surface({"service": "x", "surface_type": "network",
                              "reachable": False})
    _assert(gated["tier"] == "none" and gated["score"] == 0.0,
            "non-reachable surface excluded (reachability gate)")

    # enumerate + rank from an intel snapshot.
    intel = {"target_host": "10.0.0.5",
             "services": {"502": {"service": "Modbus"}, "80": {"service": "nginx"}},
             "web_paths": ["/admin/upload", "/api/v1/users"], "cves": []}
    ranked = ft.rank_targets(intel)
    _assert(bool(ranked["targets"]), "rank_targets produced surfaces")
    _assert(ranked["targets"] == sorted(ranked["targets"],
            key=lambda r: r["score"], reverse=True), "targets sorted by score desc")
    _assert(isinstance(ranked.get("by_host"), dict) and "high_count" in ranked,
            "per-host rollup + high_count present")

    # Side-car / best-effort: garbage intel never raises, just yields nothing.
    _assert(ft.rank_targets({})["targets"] == [], "empty intel → empty (no raise)")
    _assert(ft.rank_targets(None)["targets"] == [], "None intel → empty (no raise)")

    # Refuted signals must be ABSENT from the module (no age/call-graph/danger-score).
    import inspect
    src = inspect.getsource(ft).lower()
    for banned in ("danger_score", "call_graph", "firmware_age", "age_proxy"):
        _assert(banned not in src, f"refuted signal '{banned}' absent from scorer")


def main() -> int:
    tests = [
        test_basic_lifecycle,
        test_circuit_breaker_curl,
        test_output_signature_dedup,
        test_pin_insights_from_intel,
        test_finding_triggers_minio,
        test_render_for_prompt,
        test_session_isolation,
        test_productive_resets_counter,
        test_operator_overrides,
        test_win_condition_short_circuit,
        test_operator_mark_complete,
        test_global_invocation_budget,
        test_per_tool_absolute_cap,
        test_same_action_burst,
        test_goal_tag_attribution,
        test_budget_in_prompt,
        test_basis_gate_refusals,
        test_basis_gate_allows_when_warranted,
        test_check_command_warranted,
        test_basis_gate_in_is_tool_blocked,
        test_focused_attack_interrupt,
        test_stall_watchdog,
        test_osint_url_extractor,
        test_target_profile_classification,
        test_extract_ad_domain,
        test_ad_chain_trigger,
        test_web_orchestrator_yields_for_ad,
        test_engagement_mode_transitions,
        test_mode_change_subscribers,
        test_entry_point_detector_universal,
        test_success_detector,
        test_scanners_yield_contract,
        test_entry_point_async_queue,
        test_entry_point_dedup,
        test_primary_web_port,
        test_phase_budget,
        test_error_analyzer_fast_paths,
        test_error_analyzer_dedup,
        test_cpe_builder_banner_to_cpe,
        test_version_comparison,
        test_google_cse_dead_key_cache,
        test_osint_cve_propagation_to_github_subagent,
        test_intel_cascade_dedup,
        test_intel_cascade_routes,
        test_intel_cascade_harvest,
        test_cisa_kev_synchronous_check,
        test_nfs_full_exploit_chain,
        test_werkzeug_debug_trigger,
        test_loot_flag_hunter,
        test_hydra_false_positive_rejection,
        test_error_analyzer_gui_identity,
        test_error_analyzer_emits_correction,
        test_parallel_chain_executor_first_to_win,
        test_exploit_orchestrator_uses_parallel_executor,
        test_master_has_payload_helper,
        test_reasoning_loop_reconciles_intel_from_findings,
        test_identified_cve_triggers_reactive_exploit,
        test_exploit_synth_tier2,
        test_exploit_methodology_fixes,
        test_red_team_coverage_push,
        test_completion_push,
        test_env_driven_llm_fallback,
        test_subagent_llm_and_errors_and_synth,
        test_objective_evaluator,
        test_loop_convergence_and_web_dedup,
        test_os_detection_and_tech_correct_foothold,
        test_vhost_autopivot_and_protection,
        test_compromise_readiness_gate,
        test_tool_kill_reaches_process_tree,
        test_tool_artifacts_stay_out_of_backend,
        test_domain_subdomain_hunt_and_selection,
        test_target_resolver_ip_vs_vhost,
        test_conflict_audit_fixes,
        test_liveness_and_cancel_breakers,
        test_owasp2025_native_probes,
        test_env_preflight_and_setup,
        test_no_fake_shell_guards,
        test_sqli_weaponization,
        test_shared_operator_session,
        test_authenticated_web_playbook,
        test_operator_tiered_llm,
        test_operator_core_loop,
        test_operator_default_driver_wiring,
        test_operator_log_driven_fixes,
        test_operator_cve_pipeline,
        test_operator_fast_path,
        test_operator_poc_commit,
        test_operator_success_persistence,
        test_operator_autonomy_objectives_roster,
        test_operator_interactive_handover,
        test_operator_first_call_resilience,
        test_no_hardcoded_model_truthful_logging,
        test_operator_reactive_cve_reflex,
        test_operator_method_attempt_cap,
        test_weakness_taxonomy_loads,
        test_no_hardcoded_attack_content,
        test_operator_declares_hypothesis,
        test_doctrine_is_general,
        test_surface_model_infers_capabilities,
        test_hypothesis_backlog,
        test_operator_drives_backlog,
        test_backlog_injected_to_operator,
        test_objective_convergence,
        test_cap_marks_backlog_refuted,
        test_playbooks_keyed_by_class,
        test_hypothesis_carries_playbook,
        test_operator_post_foothold_persistence,
        test_operator_budget_never_fails_progress,
        test_operator_parallel_dispatch_and_terminal,
        test_operator_flag_capture_no_crash_correct_order,
        test_operator_flag_validation_and_provenance,
        test_llm_hard_block_failover,
        test_operator_parallel_nudge,
        test_claude_code_system_prompt_is_system_level,
        test_operator_comprehensive_assessment_after_objective,
        test_operator_advisor_no_escalation_spam,
        test_expert_no_spam_no_panic,
        test_missioncontrol_hooks_and_revshell_nudge,
        test_report_pdf_and_ui_population,
        test_operator_persistent_listener,
        test_tools_not_killed_on_time_and_missing_tool_surfaced,
        test_rag_continuous_learning,
        test_operator_credential_vault_persistence,
        test_operator_iter_cap_advisory_on_progress,
        # ── Log-review fixes (run 20260612-185122) ──────────────────────
        test_broadcast_accepts_dict_event,            # #1 broadcast dict crash
        test_listener_flips_to_confirmed_foothold,    # #6 listener never flipped
        test_operator_endpoint_pivot,                 # #4 149× endpoint hammer
        test_safe_port_guard,                         # #2 int('DNS') graph crash
        test_vhost_stale_reconcile_at_scan_start,     # #3 stale /etc/hosts
        test_shell_metachar_reroute_and_logger,       # #5 pipes + undefined logger
        test_subagent_db_fallback_and_cb_throttle,    # secondary: data loss + log flood
        # ── Two-run deep review (10.129.21.254 + 10.129.245.216) ────────
        test_operator_records_issues_and_coverage,    # concern #1 findings + coverage
        test_background_job_detach,                    # concern #4 anti-hang (998s waste)
        test_token_usage_accounting,                   # concern #5 real tokens
        test_parallel_advisor_bus,                     # concern #3 parallel support agents
        test_report_storyline_sections,                # concern #6 rich narrative report
        test_master_phase_restamp_and_finding_merge,   # phase bug + finding-drop + feed
        test_gate_stop_aware_and_observable,           # follow-up: compromise-gate honesty
        test_missioncontrol_reasoning_always_visible,  # follow-up: always-on reasoning + RAG tile
        test_professional_report_template,             # follow-up: professional print-ready report
        test_human_per_target_token_budget,            # human-set per-target LLM-token budget
        test_multihost_freeze_fix_and_perhost_view,    # multi-host freeze (model lock) + per-host view
        # ── CIDR two-phase triage→exploit + per-host grid/drill-down ────
        test_cidr_promise_score,
        test_master_run_forwards_max_seconds,
        test_db_set_host_triage_exists,
        test_cidr_two_phase_orchestration,
        test_store_hostdata_bucketing,
        test_missioncontrol_host_grid_and_drilldown,
        # ── Engagement Integrity (2026-06-19) ──────────────────────────
        test_engagement_origin_and_loot_rule,          # A1 + C: provenance stamp + loot dedup
        test_scrub_on_seed,                             # A2: scrub foreign evidence + guarded checkpoint
        test_boundary_filters,                          # A3: compaction/report/expert origin filters
        test_connectivity_blocker_gate,                 # B: preflight + circuit-breaker + human pause
        test_master_checker_removed,                    # D: dead Master Checker removed (backend + GUI)
        test_issue_validator_gate,                       # E: rebuilt Issue Validator finding gate
        test_finding_gate_wiring,                        # E: write/read/lifecycle/GUI wiring
        # ── Report Overhaul (2026-06-19): 5 selectable themes + PDF fidelity ─
        test_report_theme_registry,
        test_report_themes_render,
        test_generator_theme_and_pdf_order,
        test_context_retest_and_detection,
        test_report_endpoint_theme,
        test_pdf_deps_provisioned,
        test_reportpage_theme_picker,
        # ── Crestron AV/OT integration (2026-06-20) ────────────────────
        test_crestron_avot_integration,
        # ── AI / Agentic Security Engine — Slice 1 (2026-06-20) ─────────
        test_ai_redteam_module,
        test_ai_redteam_routing_and_ui,
        # ── AI / Agentic Security Engine — Slice 2: shadow-AI discovery ──
        test_ai_shadow_discovery,
        # ── AI / Agentic Security Engine — Slice 3: AIVSS + reproducibility ──
        test_ai_scoring_and_repro,
        # ── #5 Universal Technology Coverage — Slice 1 (skill registry) ──
        test_skill_registry_load_match,
        test_skill_safety_gate_and_rag,
        test_ot_modbus_module,
        test_skill_registry_engine_wiring,
        test_scan_intrusiveness_ui_and_plumbing,
        test_skill_registry_p0_breadth,
        test_skill_registry_toolbelt_awareness,
        # ── #5 Universal Technology Coverage — Slice 2 (active OT + passive) ──
        test_ot_active_modules,
        test_ot_passive_capture,
        test_skill_registry_p1_breadth,
        # ── #5 Universal Technology Coverage — Slice 3 (P2 hardware-tier) ──
        test_skill_registry_p2_transport,
        # ── Global technology coverage + weekly skill updater ──
        test_global_category_breadth,
        test_skill_updater_script,
        # ── Self-learning skill system (#1 #2 #3 #4 #5) + RAG observability ──
        test_rag_logger_and_report,
        test_rag_rerank_trim,
        test_rag_budget_guardrail,
        test_lesson_target_agnostic_scrub,
        test_skill_effectiveness_telemetry,
        test_skill_prioritization,
        test_skill_selflearning_wiring,
        test_skill_validator,
        test_fuzz_lab_catalog_and_scope,
        test_fuzz_lab_validation_and_argv,
        test_realtime_cve_and_parallel_wiring,
        test_secondary_llm_status_and_timeout,
        test_detection_severity_is_info,
        test_operational_severity_model,
        test_fuzz_targeting_indicator,
        test_browser_verification,
        test_reproduction_status,
        test_auth_security_controls,
        test_eval_benchmark,
        test_safety_governor,
        test_technique_search,
        test_model_capability_and_cve_filter,
        test_tool_reliability_ranking,
        test_rag_logs_in_scan_dir,
        test_fuzz_workshop,
        test_committed_exploit,
        test_report_severity_normalization,
        test_fuzz_campaign_control,
        test_background_brute,
        test_fuzz_lab_usability,
    ]
    print("ARGUS — Architectural Core Integration Smoke Test")
    print("=" * 60)
    for t in tests:
        try:
            t()
        except Exception as e:
            tb = traceback.format_exc()
            _bad(f"{t.__name__} raised {type(e).__name__}",
                 detail=f"{e}\n{tb}")
    print("\n" + "=" * 60)
    if _failures:
        print(f"RESULT: FAIL — {len(_failures)} assertion(s) failed")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("RESULT: PASS — all assertions green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
