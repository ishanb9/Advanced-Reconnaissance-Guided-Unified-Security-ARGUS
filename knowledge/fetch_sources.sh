#!/usr/bin/env bash
# fetch_sources.sh — clone (or update) the curated external knowledge sources
# into knowledge/data/external/ so build_kb.py can ingest them.
#
# Idempotent:
#   - First run  : clones every repo with --depth 1 (~3-5 GB total)
#   - Re-runs    : git pull on each repo (only diffs transfer)
#   - Per-repo failure does NOT stop the rest
#
# Usage:
#   bash knowledge/fetch_sources.sh                  # tier A + B
#   bash knowledge/fetch_sources.sh --full           # also include heavy CVE PoC hub
#   bash knowledge/fetch_sources.sh --tier-a-only    # only tier-A (smaller, faster)
#   bash knowledge/fetch_sources.sh --list           # print the repo list and exit
#
# After running, build / refresh the index:
#   python knowledge/build_kb.py
#
# Disk:
#   tier-A only : ~1.5 GB
#   tier-A + B  : ~3-5 GB
#   --full      : adds another 5-10 GB (trickest/cve)

set -uo pipefail

# Resolve the script's own dir, then the data/external/ destination.
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
DEST="${HERE}/data/external"
mkdir -p "${DEST}"

# ── Repo lists ─────────────────────────────────────────────────────────────
# Each line: "<dir-name> <git-url>"

TIER_A=(
    "hacktricks            https://github.com/HackTricks-wiki/hacktricks.git"
    "PayloadsAllTheThings  https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    "nuclei-templates      https://github.com/projectdiscovery/nuclei-templates.git"
    "atomic-red-team       https://github.com/redcanaryco/atomic-red-team.git"
    "gtfobins              https://github.com/GTFOBins/GTFOBins.github.io.git"
    "LOLBAS                https://github.com/LOLBAS-Project/LOLBAS.git"
    "wadcoms               https://github.com/WADComs/WADComs.github.io.git"
    "arsenal               https://github.com/Orange-Cyberdefense/arsenal.git"
    "InternalAllTheThings  https://github.com/swisskyrepo/InternalAllTheThings.git"
    "attack-stix-data      https://github.com/mitre-attack/attack-stix-data.git"
    "mitre-cti             https://github.com/mitre/cti.git"
)

TIER_B=(
    "wstg                  https://github.com/OWASP/wstg.git"
    "ASVS                  https://github.com/OWASP/ASVS.git"
    "CheatSheetSeries      https://github.com/OWASP/CheatSheetSeries.git"
    "pentest-book          https://github.com/six2dez/pentest-book.git"
    "Red-Teaming-Toolkit   https://github.com/infosecn1nja/Red-Teaming-Toolkit.git"
    "Awesome-Red-Teaming   https://github.com/yeyintminthuhtut/Awesome-Red-Teaming.git"
    "Awesome-Hacking       https://github.com/m4ll0k/Awesome-Hacking-Resources.git"
    "h4cker                https://github.com/The-Art-of-Hacking/h4cker.git"
    "pacu                  https://github.com/RhinoSecurityLabs/pacu.git"
    "CloudPentestCheats    https://github.com/dafthack/CloudPentestCheatsheets.git"
)

OPTIONAL_FULL=(
    "trickest-cve          https://github.com/trickest/cve.git"
)

# ── Argument parsing ───────────────────────────────────────────────────────

INCLUDE_TIER_A=1
INCLUDE_TIER_B=1
INCLUDE_FULL=0
LIST_ONLY=0

for arg in "$@"; do
    case "${arg}" in
        --full)         INCLUDE_FULL=1 ;;
        --tier-a-only)  INCLUDE_TIER_B=0 ;;
        --tier-b-only)  INCLUDE_TIER_A=0 ;;
        --list)         LIST_ONLY=1 ;;
        -h|--help)
            sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# *//'
            exit 0
            ;;
        *)
            echo "unknown flag: ${arg}" >&2
            echo "try --help" >&2
            exit 2
            ;;
    esac
done

# Build the active list
SOURCES=()
((INCLUDE_TIER_A)) && SOURCES+=("${TIER_A[@]}")
((INCLUDE_TIER_B)) && SOURCES+=("${TIER_B[@]}")
((INCLUDE_FULL))   && SOURCES+=("${OPTIONAL_FULL[@]}")

if ((LIST_ONLY)); then
    printf '%s\n' "${SOURCES[@]}"
    exit 0
fi

# ── Pre-flight ─────────────────────────────────────────────────────────────

if ! command -v git &>/dev/null; then
    echo "ERROR: git not found in PATH" >&2
    exit 1
fi

echo "═══ ARGUS knowledge sources ═══"
echo "destination : ${DEST}"
echo "repos       : ${#SOURCES[@]}"
echo

# ── Clone or update each repo ──────────────────────────────────────────────

OK=0
FAIL=0
SKIP=0

for entry in "${SOURCES[@]}"; do
    # Split into "dir url" — POSIX-friendly
    name="${entry%% *}"
    url="${entry##* }"
    target="${DEST}/${name}"

    if [[ -d "${target}/.git" ]]; then
        printf '  [pull]  %-22s ' "${name}"
        if ( cd "${target}" && git pull --depth 1 --quiet 2>&1 ) ; then
            printf '✓\n'; OK=$((OK+1))
        else
            printf '✗\n'; FAIL=$((FAIL+1))
        fi
    elif [[ -e "${target}" ]]; then
        printf '  [skip]  %-22s (path exists, not a git repo)\n' "${name}"
        SKIP=$((SKIP+1))
    else
        printf '  [clone] %-22s ' "${name}"
        if git clone --depth 1 --quiet "${url}" "${target}" 2>/dev/null ; then
            printf '✓\n'; OK=$((OK+1))
        else
            printf '✗\n'; FAIL=$((FAIL+1))
        fi
    fi
done

# ── Summary ────────────────────────────────────────────────────────────────

echo
echo "═══ Summary ═══"
echo "  ok      : ${OK}"
echo "  failed  : ${FAIL}"
echo "  skipped : ${SKIP}"

if command -v du &>/dev/null; then
    echo "  size    : $(du -sh "${DEST}" 2>/dev/null | awk '{print $1}')"
fi

echo
echo "Next: build / refresh the knowledge base"
echo "  python knowledge/build_kb.py"

# Exit non-zero only if EVERY repo failed (partial success is fine)
if [[ ${OK} -eq 0 && ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
