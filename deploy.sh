#!/usr/bin/env bash
# =============================================================================
#  ARGUS deploy — sync the dev tree (v1) into the running Kali tree (v3) WITHOUT
#  clobbering runtime state (.env, credentials, logs, venv, node_modules, DB),
#  then VERIFY the fixes actually landed + byte-compile the critical modules so a
#  syntax error surfaces NOW, not 40 minutes into a scan.
#
#  Usage:
#    ./deploy.sh [SRC] [DEST]
#      SRC   ARGUS v1 source. Default: $ARGUS_SRC, else the first shared-folder
#            mount that looks like an ARGUS tree, else this script's own dir.
#      DEST  ARGUS v3 install. Default: $ARGUS_DEST, else
#            /home/kali/Desktop/KaliLinuxPlatform/v3
#    DRY=1 ./deploy.sh    # dry run — show what would change, copy nothing
# =============================================================================
set -euo pipefail

DEST="${2:-${ARGUS_DEST:-/home/kali/Desktop/KaliLinuxPlatform/v3}}"

# ── Resolve SRC ──────────────────────────────────────────────────────────────
SRC=""
if   [ -n "${1:-}" ];          then SRC="$1"
elif [ -n "${ARGUS_SRC:-}" ];  then SRC="$ARGUS_SRC"
else
  for cand in /media/sf_v1 /mnt/hgfs/v1 /media/sf_LLM/v1 /mnt/hgfs/LLM/v1 \
              /media/sf_Tools/LLM/v1 "$(cd "$(dirname "$0")" && pwd)"; do
    if [ -f "$cand/agent_server.py" ]; then SRC="$cand"; break; fi
  done
fi
: "${SRC:?Could not locate ARGUS v1 source — pass it as arg1 or set ARGUS_SRC}"

[ -f "$SRC/agent_server.py" ]  || { echo "ERR: '$SRC' is not an ARGUS tree (no agent_server.py)"; exit 1; }
command -v rsync >/dev/null    || { echo "ERR: rsync not installed (apt install rsync)"; exit 1; }
mkdir -p "$DEST"

echo "=============================================================="
echo "  ARGUS deploy"
echo "    SRC : $SRC"
echo "    DEST: $DEST"
echo "=============================================================="

RSYNC_FLAGS=(-a --info=stats1,progress2)
if [ "${DRY:-0}" = "1" ]; then RSYNC_FLAGS+=(--dry-run); echo "  (DRY RUN — nothing will be written)"; fi

# NEVER touch runtime state on the dest; never copy build/cache/log dirs.
EXCLUDES=(
  --exclude '.git/'          --exclude '__pycache__/'   --exclude '*.pyc'
  --exclude '.venv/'         --exclude 'venv/'          --exclude 'env/'
  --exclude 'node_modules/'
  --exclude '.env'           --exclude '*.env'          --exclude '.env.*'
  --exclude '*.db'           --exclude '*.sqlite'       --exclude '*.sqlite3'
  --exclude 'logs/'          --exclude 'Scan/'          --exclude 'scan_logs/'
  --exclude 'poc_artifacts/' --exclude 'loot/'          --exclude 'evidence/'
  --exclude '*.log'          --exclude '.DS_Store'
)

rsync "${RSYNC_FLAGS[@]}" "${EXCLUDES[@]}" "$SRC"/ "$DEST"/

echo
echo "── Post-deploy verification ──────────────────────────────────"
_ok=1
_check() {  # _check <file> <needle> <label>
  if grep -q -- "$2" "$DEST/$1" 2>/dev/null; then echo "  [OK]  $3"
  else echo "  [!!]  MISSING: $3   ($1)"; _ok=0; fi
}
_check utils/llm_providers.py            "_oauth_child_env"      "claude-code auth env-strip (kills the 401)"
_check utils/llm_providers.py            "CLAUDE_AUTH_PREAMBLE"  "system-level authorization preamble"
_check utils/llm_providers.py            "ENGAGEMENT CONTEXT"    "calm (de-jailbroken) authorization preamble — the Opus-refusal fix"
_check utils/llm_providers.py            "def apply_auth_framing" "authorization framing on EVERY provider (not just claude-code)"
_check utils/llm_providers.py            "def reframe_messages"  "neutral-language reframe helper (recovers Opus after a refusal)"
_check agents/base_agent.py              "reframe_messages(messages, _att)" "converse(): same-model reframe-retry before downgrading"
_check agents/base_agent.py              "_tk_reframe(messages, _att)"      "think(): refusal-body detection + reframe-retry"
_check agents/base_agent.py              "_stream_with_backup"   "subagent/planner backup failover"
_check report/generator.py               "_clean_finding_title"  "report title cleanup (no mid-word truncation)"
_check report/generator.py               "hosts —"               "compact multi-host cover title"
_check report/generator.py               "_sanitize_evidence"    "strip ANSI/tofu from evidence blocks"
_check report/themes/argus.html.j2       "counter(secnum"        "section numbers via CSS counter (no 03→05 gap)"
_check report/themes/__init__.py         "def is_builder_theme"  "only dark+light selectable as PDF"
_check report/argus_template/build_report.py "def build(theme"    "vendored dark/light report builder (verbatim)"
_check report/argus_template/data.py     "def apply"             "live-scan data adapter for the dark/light builder"
_check report/argus_template/render.py   "def render_html"       "builder render glue"
_check agents/master_agent.py            "_stop_phase_events"    "non-blocking deadline (tool keeps running)"
_check agents/operator_agent/operator_core.py "deferred_unreachable" "connectivity blocker defers host instead of freezing"
_check report/charts.py                  "_clean_label_glyphs"   "attack-path tofu-glyph strip"
_check agents/recon/dns_recon_subagent.py "_is_ip_target"        "wildcard-DNS false-positive fix"
_check knowledge/device_playbook.py      "def route_host"        "device-type router (suppress web sweep on OT/IoT)"
_check agents/exploit/hikvision_isapi.py "def encode_activation_password" "Hikvision activation-password encoder"
_check agents/exploit/follow_through.py  "def detect_followups"  "exploit follow-through (no host abandoned one step short)"
_check agents/reasoning/reasoning_loop.py "_followups_forced"    "reasoning loop consults follow-through before converging"
_check agents/master_agent.py            "device_playbook_route" "master web-gate wired to the device router"
_check agents/operator_agent/operator_core.py "_skill_advisory_block" "matched device/tech skills (quick-wins + CVEs) reach the operator brief — the skills→actor bridge"
_check agents/master_agent.py            "skill_advisory"        "prioritised skills routed to the LIVE operator channel (the dead _meta_advisory buffer is bypassed)"
[ -f "$DEST/knowledge/skills/iot/crestron_avcontrol.md" ] && echo "  [OK]  Crestron device playbook skill" || { echo "  [!!]  MISSING: Crestron device playbook skill"; _ok=0; }

if command -v python3 >/dev/null; then
  if (cd "$DEST" && python3 -m py_compile \
        utils/llm_providers.py agents/base_agent.py report/generator.py report/charts.py \
        agents/operator_agent/operator_core.py agents/operator_agent/committed_exploit.py \
        agents/recon/dns_recon_subagent.py 2>/tmp/argus_deploy_pyc.log); then
    echo "  [OK]  critical modules byte-compile cleanly"
  else
    echo "  [!!]  a deployed module FAILED to compile:"; sed 's/^/         /' /tmp/argus_deploy_pyc.log; _ok=0
  fi
fi

echo
if [ "$_ok" = "1" ]; then echo "  ✅ deploy verified."; else echo "  ⚠️  some checks FAILED — see above."; fi
echo
echo "Next:"
echo "  • If claude-code returns 401:  unset ANTHROPIC_API_KEY   (before launching; keep it unset)."
echo "  • Runtime state on DEST was left untouched: .env, logs/, Scan/, *.db, venv/, node_modules/."
echo "  • Start:  cd \"$DEST\" && python3 agent_server.py"
echo "  • Confirm the primary is live:  a fresh scan's scan.log has 0 'Failed to authenticate' lines"
echo "    and llm_calls.jsonl contains 'AUTHORIZATION CONTEXT'."
