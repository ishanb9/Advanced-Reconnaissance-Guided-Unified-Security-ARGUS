# knowledge/skills — technology skill files (data-driven coverage)

Drop a Markdown file here to teach ARGUS a new technology. On the next engagement ARGUS
**auto-loads** every `*.md` under this tree, **matches** it against recon intel (records a
finding + injects safe quick-wins into the operator), and **ingests** the guidance body into
the RAG knowledge base for semantic recall. **No code change, no restart of the design.**

Coverage is *data*. Adding a technology = adding a file here. Technologies that need active
protocol-speaking or fuzzing get a code module under `agents/<domain>/` instead (e.g.
`agents/ot/modbus.py`, `agents/avot`, `agents/ai_red_team/discovery`) — both feed the same
capability registry.

## Layout

```
knowledge/skills/<domain>/<id>.md      domain ∈ { ot, iot, it }
```

## Front-matter schema (YAML) + guidance body (Markdown)

```markdown
---
id: modbus                      # unique kebab id
technology: "Modbus / Modbus-TCP"
domain: OT                      # OT | IoT | IT
safety_class: safe              # safe | intrusive | disruptive  (base class for plain detection)
severity: high                  # finding severity when exposed; OMIT ⇒ guidance-only (no finding)
life_safety: false              # true ⇒ never actuate (elevators / fire / egress / door-locks)
transport: ip                   # ip (default) | rf | can | l2 | serial — see "Hardware tiers" below
match:
  ports:   [502]                # ONLY technology-DEDICATED ports. Shared ports (80/443/8000/
                                # 8080/5000/3000/8888/…) are IGNORED for port-only matches by a
                                # code FP guard — rely on banners/markers for those.
  banners: ["modbus"]           # service/version banner substrings (lowercase)
  markers: ["mbap"]             # specific HTTP path / header / protocol markers
quick_wins:
  - { cmd: "nmap --script modbus-discover -p502 {host}", safety: safe, note: "read device id" }
  - { cmd: "<write coil>", safety: disruptive, note: "GATED — actuates the process" }
references: ["CVE-…", "ICSA-…"]
cpe: "cpe:2.3:…"                # optional
mitre: "T0846"                  # optional ATT&CK / ICS technique id
---
# Modbus guidance (this body is what goes to RAG)
Reachability = control. Read-only FC 0x01/0x03/0x2B by default; hard-gate writes…
```

## How the safety gate uses your file

The human picks a **scan-intrusiveness ceiling** (safe | intrusive | disruptive) in Target
Configuration. A `quick_win` with `safety: X` auto-surfaces to the operator only when `X` is at
or below the ceiling. **OT-domain targets are clamped to `safe`** unless the engagement is
explicitly authorized, and any `life_safety: true` action never auto-runs. Above-ceiling
quick-wins are shown as *"available — requires authorization,"* never executed automatically.

## Hardware tiers (`transport`)

Most skills are `transport: ip` — ARGUS reaches them over the network and matches them from recon.
The P2 RF/CAN/Layer-2/serial families (`transport: rf | can | l2 | serial`) need physical hardware
ARGUS does not have (SDR/HackRF/KillerBee/Ubertooth, SocketCAN/HWBridge, a SPAN port, or
Proxmark/ESPKey). Those skills are **knowledge**: ARGUS recognises the technology (often via an
IP-side gateway) and surfaces operator guidance + the right hardware-tool quick-wins, but does **not**
auto-execute them. The finding for a non-`ip` transport says which hardware bridge is required.

## Categories (`category`) + directory layout

Skills are grouped by an optional `category` and live in a matching directory. The covered verticals:
`ot` / `iot` / `it` (the original P0–P2 protocol set), plus `security` (firewalls/IDS/WAF/NAC/SIEM),
`network` (router/switch/LB OSes), `os` (Windows/Linux/macOS/ESXi/…), `webapp` (CMS/CI-CD/app-servers),
`scada` (HMI/SCADA software + historians), `home` (home-automation hubs), `marine` (yacht/ship bridge,
nav, satcom), and `aviation` (avionics, datalink, IFE/EFB). `domain` still drives the safety gate
(OT/IoT/IT); `category` is for grouping + reporting.

## Weekly updates

`scripts/update_skills.py` keeps this catalog current with global trends. Run it weekly:

```
# cron (Linux/Kali), Mondays 03:00
0 3 * * 1  cd /path/to/ARGUS && python3 -X utf8 scripts/update_skills.py >> /var/log/argus-skills.log 2>&1
# Windows Task Scheduler (weekly): program=python, arguments=-X utf8 scripts\update_skills.py
```

It runs two best-effort passes: (1) **CVE refresh** — pulls the CISA KEV catalog and appends newly
known-exploited CVEs to matching skills' `references:`; (2) **trend discovery** — asks the configured
LLM for trending technologies not yet covered and authors new, schema-valid, FP-safe skill files.
Every write is validated + shared-port-guarded before it lands; `--dry-run` previews, `--kev-only`
skips the LLM, and each run appends to `knowledge/skills/.update_log.jsonl`.

## Required fields

`id`, `technology`, and a `match` block are required; everything else is optional (a pure-RF/CAN/L2
skill may have an empty `match` — it then serves as RAG guidance + inventory rather than an active
match). Malformed files are skipped, not fatal.
