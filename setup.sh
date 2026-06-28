#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  setup.sh — build (or repair) the ARGUS Python venv REPRODUCIBLY.
#
#  Why: the #1 source of confusing breakage is a venv rebuilt piecemeal instead
#  of from the pinned requirements.txt — you end up with a newer Starlette (the
#  TemplateResponse 500), a missing python-dotenv (.env silently ignored, wrong
#  LLM model), or a stray 'bson' shadowing pymongo (bson.errors crash). This
#  script does a CLEAN install of the pinned deps into an isolated venv and
#  VERIFIES the result so those failures can't reach runtime.
#
#  Usage (from the repo root):
#      bash setup.sh                      # create/refresh ./.venv and verify
#      ARGUS_VENV=~/argus bash setup.sh   # use a custom venv location
#      bash setup.sh --verify             # only verify an existing venv
#
#  Then:
#      source <venv>/bin/activate && python3 agent_server.py
# ─────────────────────────────────────────────────────────────────────────────
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${ARGUS_VENV:-$HERE/.venv}"
PY="$VENV/bin/python"

ok()   { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
info() { printf '\033[1;36m[*] %s\033[0m\n' "$*"; }
err()  { printf '\033[1;31m[!] %s\033[0m\n' "$*"; }

verify() {
    "$PY" - <<'PYEOF'
import importlib.util as u, sys
mods = ["dotenv","pymongo","motor","fastapi","starlette","uvicorn",
        "jinja2","httpx","pydantic","neo4j","chromadb","sentence_transformers"]
missing = [m for m in mods if u.find_spec(m) is None]
# WebSocket lib (uvicorn[standard] extra) — without it the live UI /ws/* 404s
if u.find_spec("websockets") is None and u.find_spec("wsproto") is None:
    missing.append("websockets (uvicorn[standard] extra)")
broken_bson = (u.find_spec("bson") is not None and u.find_spec("bson.errors") is None)
for m in missing:      print(f"  MISSING: {m}")
if broken_bson:        print("  BROKEN : standalone 'bson' shadows pymongo (no bson.errors)")
try:
    from bson.errors import InvalidId            # the exact import that crashed the server
    print("  OK     : bson.errors importable")
except Exception as e:
    print(f"  FAIL   : from bson.errors import InvalidId -> {e}")
    sys.exit(1)
sys.exit(1 if (missing or broken_bson) else 0)
PYEOF
}

# Non-fatal MongoDB reachability probe. agent_server.py needs a MongoDB SERVER
# on localhost:27017 (override via MONGO_URI) — it builds indexes at startup and
# crashes with "Connection refused" (Errno 111) if Mongo isn't running. The
# venv only provides the pymongo/motor CLIENTS, so warn early instead of letting
# it surface as a cryptic startup traceback. Uses bash /dev/tcp (no deps).
mongo_check() {
    local host=localhost port=27017
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then
        exec 3>&- 3<&- 2>/dev/null
        ok "MongoDB reachable on $host:$port"
    else
        err "MongoDB NOT reachable on $host:$port — agent_server.py will NOT boot."
        echo "      apt:    sudo apt install mongodb && sudo systemctl enable --now mongodb"
        echo "      docker: sudo docker run -d --name argus-mongo --restart unless-stopped -p 27017:27017 -v argus-mongo:/data/db mongo:6"
        echo "      (or set MONGO_URI=mongodb://<host>:27017 if Mongo lives elsewhere)"
    fi
}

# ── verify-only mode ─────────────────────────────────────────────────────────
if [ "${1:-}" = "--verify" ]; then
    [ -x "$PY" ] || { err "no venv at $VENV — run 'bash setup.sh' first"; exit 1; }
    info "Verifying venv at $VENV"
    if verify; then ok "venv OK"; else err "venv has problems (see above)"; exit 1; fi
    mongo_check
    exit 0
fi

# ── build ────────────────────────────────────────────────────────────────────
info "ARGUS venv → $VENV"
if [ ! -x "$PY" ]; then
    python3 -m venv "$VENV" \
        || { err "python3 -m venv failed — try: sudo apt install -y python3-venv python3-full"; exit 1; }
    ok "created venv"
fi

"$PY" -m pip install -q -U pip wheel setuptools 2>/dev/null || true

# Defensive: a previous pip mistake (or a tool's requirements) may have pulled
# the standalone 'bson', which shadows pymongo's bundled bson and crashes the
# server with "No module named 'bson.errors'". Remove it before installing.
if "$PY" -m pip show bson >/dev/null 2>&1; then
    "$PY" -m pip uninstall -y bson >/dev/null 2>&1 && info "removed stray 'bson' package"
fi

# weasyprint (styled PDF report export) needs Pango/Cairo/GDK-Pixbuf system libs.
# Best-effort apt; if it fails the report still exports a styled PDF via the
# browser print-to-PDF fallback, so this never blocks setup.
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
        libcairo2 libffi-dev >/dev/null 2>&1 \
        && info "weasyprint system libs (pango/cairo) installed" \
        || info "weasyprint system libs not installed (styled PDF falls back to browser print)"
fi

info "Installing pinned requirements (first run downloads ~1 GB of ML models)…"
if "$PY" -m pip install -r "$HERE/requirements.txt"; then
    ok "requirements installed"
else
    err "requirements install failed — see the errors above"; exit 1
fi

info "Verifying environment"
if verify; then
    ok "Environment verified — ARGUS is ready."
    mongo_check
    echo
    echo "    source \"$VENV/bin/activate\""
    echo "    python3 agent_server.py"
else
    err "Verification failed — fix the items above and re-run 'bash setup.sh'."; exit 1
fi
