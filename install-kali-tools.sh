#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  install-kali-tools.sh — install the external tools ARGUS shells out to.
#
#  Source of truth: the MCP tool registry in mcp-server.js (356 binaries).
#  This script installs them via apt + go + pipx + git + downloads, then
#  VERIFIES every registry binary and prints exactly what is still missing
#  (those are the tools ARGUS will report "Tool not found" on).
#
#  Usage:
#      sudo bash install-kali-tools.sh           # full install + verify
#      bash      install-kali-tools.sh --verify  # just check what's present
#
#  Companion manifest: requirements-kali.txt   (Python deps: requirements.txt)
# ─────────────────────────────────────────────────────────────────────────────
set -u

VERIFY_ONLY=0
[[ "${1:-}" == "--verify" || "${1:-}" == "-v" ]] && VERIFY_ONLY=1

c_info()  { printf '\n\033[1;36m[*] %s\033[0m\n' "$*"; }
c_ok()    { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
c_warn()  { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }

# ── The complete ARGUS tool registry (mcp-server.js) — 356 binaries ──────────
REGISTRY_BINS="403fuzzer GodPotato PCredz PrintSpoofer SweetPotato adidnsdump aircrack-ng airgeddon airmon-ng altdns amass amicontained apktool arjun arp-scan arping arpspoof assetfinder atk6-alive6 aws awsrecon az bandit base58 base64 beef-xss beroot bettercap binwalk bloodhound-ce-python bloodhound-python botb bulk_extractor bully byp4xx cariddi cdk certipy certipy-ad cewl cewl-ng chameleon checksec chisel chntpw cloud_enum cloudbrute cloudsplaining coercer commix corsy crackmapexec credmaster crictl crosslinked crunch cryptcat cupp curl cutter cutycapt dalfox davtest deepce dig dirb dmitry dns2tcp dnschef dnsenum dnsmap dnsrecon dnsvalidator dnsx docker donpapi donut droopescan dsniff eaphammer emailharvester enum4linux enum4linux-ng enumerate-iam ettercap evil-winrm exiv2 eyewitness feroxbuster ffuf fierce file find fping freeze gau gcloud gcpbucketbrute gdb getcap ghidra gitleaks go-socks5 gobuster gospider gowitness gpp-decrypt graudit grype gsutil h8mail hakrawler hash-identifier hashcat hashid hcxdumptool hcxhashtool holehe host hostapd-wpe hping3 httprobe httpx hydra id ike-scan impacket-GetADUsers impacket-GetNPUsers impacket-GetUserSPNs impacket-addcomputer impacket-atexec impacket-dacledit impacket-dcomexec impacket-findDelegation impacket-getArch impacket-getPac impacket-getST impacket-getTGT impacket-lookupsid impacket-mssqlclient impacket-ntlmrelayx impacket-owneredit impacket-psexec impacket-rbcd impacket-rpcdump impacket-secretsdump impacket-services impacket-smbexec impacket-smbserver impacket-ticketer impacket-wmiexec inetsim invoke-obfuscation iodine jadx john joomscan jq jwt_tool katana kerberoast kerbrute kismet kube-bench kube-hunter kubeaudit kubectl kubesec kwp64 lazagne lazys3 lbd ldapdomaindump ldapsearch ligolo-ng linenum.sh linkfinder linpeas.sh linux-exploit-suggester linux-exploit-suggester-2 log4shell-scanner lsassy ltrace macchanger magescan maltego masscan massdns medusa mentalist metagoofil mimikatz mitm6 mitmdump mitmproxy mp64 msfconsole msfpc msfvenom nbtscan nc ncrack ndiff net-creds netdiscover netexec netsniff-ng ngrep nikto nmap nosqlmap nslookup nuclei nxc o365spray objdump onesixtyone openvas-scanner openvpn ophcrack pacu param-miner patator patchelf pdf-parser pdfid photon phuip-fpizda pipal pixiewps polenum popeye powershell-empire powerup pp64 pretender privesccheck prowler proxychains4 pspy64 pth-winexe puredns pwn pwncat pwndb pwndbg pwsh pypykatz python3 r2 rdesktop readelf reaver recon-ng responder retire revsocks rlwrap routersploit rpcclient rpivot rsmangler ruler s3scanner samdump2 scalpel scarecrow scout scp screen searchsploit seatbelt semgrep sendEmail setoolkit shellter sherlock shiro-exploit shodan shuffledns skipfish sliver sliver-server smbclient smbmap smtp-user-enum snmpcheck snmpget snmpwalk socat socialscan spiderfoot sprayhound spring4shell-scan sqlmap ssh sshdump sshpass sshuttle sslscan sslyze ssrfmap starkiller strace strings struts-pwn stunnel4 subfinder sudo swaks tcpdump tcpick tcpreplay testdisk testssl.sh theHarvester tmux tplmap traceroute trevorspray trivy trufflehog tshark udptunnel uname unicornscan unix-privesc-check upx urlcrazy veil vol wafw00f wapiti watson waybackurls wce weevely wes wfuzz whatweb whoami whois wifiphisher wifite windapsearch windows-exploit-suggester winpeas.exe winrm-cli wpscan xfreerdp xfreerdp3 xsstrike xxd yara ysoserial zenmap"

verify_registry() {
    c_info "Verifying ARGUS tool registry against PATH ..."
    local missing=() present=0 total=0
    for b in $REGISTRY_BINS; do
        total=$((total+1))
        if command -v "$b" >/dev/null 2>&1; then present=$((present+1)); else missing+=("$b"); fi
    done
    c_ok "$present / $total registry binaries present"
    if [ "${#missing[@]}" -gt 0 ]; then
        c_warn "${#missing[@]} MISSING — ARGUS will skip these (install from requirements-kali.txt NON-APT section):"
        printf '    %s\n' "${missing[@]}"
    else
        c_ok "Every registry tool is installed."
    fi
}

if [ "$VERIFY_ONLY" -eq 1 ]; then verify_registry; exit 0; fi

if [ "$(id -u)" -ne 0 ]; then
    c_warn "Run the install with sudo:  sudo bash install-kali-tools.sh"
    c_warn "(or just verify:            bash install-kali-tools.sh --verify)"
    exit 1
fi

# Resolve the invoking user's HOME so go/pipx land in a usable place.
REAL_USER="${SUDO_USER:-root}"

# ── 1. APT: repair state, runtime prereqs, then best-effort per-tool ─────────
APT_LOG=/tmp/argus-apt-install.log; : > "$APT_LOG"
export DEBIAN_FRONTEND=noninteractive
c_info "apt update"
apt-get update -y >>"$APT_LOG" 2>&1 || c_warn "apt update had errors (see $APT_LOG)"

# A fresh 'apt update' usually kicks off Kali's apt-daily timer, which grabs the
# dpkg lock — making EVERY subsequent install fail (the symptom seen on the first
# run, where all 130+ apt installs were skipped). Stop the timers, wait for the
# lock to clear, then repair any half-configured dpkg state before installing.
c_info "Repairing apt/dpkg state (lock wait + configure -a + fix-broken)"
systemctl stop apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service \
    apt-daily.service apt-daily-upgrade.service packagekit.service 2>/dev/null || true
for i in $(seq 1 12); do
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break
    c_warn "dpkg lock held (apt-daily/unattended-upgrades?) — waiting 10s ($i/12)"; sleep 10
done
dpkg --configure -a >>"$APT_LOG" 2>&1 || true
apt-get -f install -y >>"$APT_LOG" 2>&1 || true

# apti <pkg>: install ONE package, logging the real error (no silent 2>/dev/null,
# so a failure tells us *why* in $APT_LOG instead of a blind "apt-skip").
apti() { if apt-get install -y "$1" >>"$APT_LOG" 2>&1; then c_ok "apt: $1"; \
         else c_warn "apt-skip: $1"; fi; }

c_info "Runtime prerequisites"
for rp in nodejs npm golang-go python3 python3-pip python3-venv pipx git curl jq \
          default-jre-headless metasploit-framework seclists wordlists; do
    apti "$rp"
done

# The giant Kali meta-package (pulls most of the registry) is OFF by default —
# it is multi-GB. Enable with: sudo ARGUS_INSTALL_EVERYTHING=1 bash install-kali-tools.sh
if [ "${ARGUS_INSTALL_EVERYTHING:-0}" = "1" ]; then
    c_info "Installing kali-linux-everything meta-package (large, may take a while)"
    apti kali-linux-everything
fi

c_info "Best-effort apt for individual registry tools (skips any not in repo)"
APT_TOOLS="nmap masscan netdiscover arp-scan arping fping hping3 nbtscan unicornscan \
nikto gobuster droopescan joomscan dirb wfuzz ffuf whatweb wafw00f wapiti skipfish \
sqlmap commix davtest wpscan weevely cutycapt feroxbuster nuclei httpx katana gau \
waybackurls hakrawler gospider arjun amass subfinder dnsx dnsrecon dnsenum dnsmap \
fierce theharvester recon-ng spiderfoot dmitry whois trufflehog gitleaks sherlock \
sslscan sslyze testssl.sh ncrack exploitdb smbclient smbmap enum4linux enum4linux-ng \
crackmapexec netexec evil-winrm rpcclient polenum ldap-utils freerdp2-x11 freerdp3-x11 \
rdesktop sshpass hydra medusa john hashcat hashid hash-identifier patator cewl crunch \
cupp samdump2 chntpw ophcrack lazagne unix-privesc-check linux-exploit-suggester \
mimikatz aircrack-ng reaver bully pixiewps eaphammer kismet macchanger wifite \
tcpdump tshark ngrep ettercap-text-only bettercap dsniff responder mitmproxy hcxtools \
onesixtyone snmp swaks smtp-user-enum chisel socat ncat proxychains4 sshuttle iodine \
dns2tcp stunnel4 binwalk foremost strings gdb radare2 ghidra jadx apktool checksec \
exiv2 bulk-extractor scalpel testdisk volatility3 impacket-scripts kerberoast kerbrute \
ldapdomaindump mitm6 awscli azure-cli docker.io kubernetes-client trivy kube-hunter \
sliver powershell-empire beef-xss routersploit veil shellter yara semgrep ike-scan \
upx weevely droopescan magescan ltrace strace patchelf cutter pwndbg urlcrazy \
metagoofil maltego hostapd-wpe airgeddon wifiphisher dnschef net-creds pdf-parser pdfid donut"
for p in $APT_TOOLS; do
    apti "$p"
done
c_info "apt failures (if any) are logged to $APT_LOG — last lines:"
tail -n 4 "$APT_LOG" 2>/dev/null || true

# rockyou
if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null && c_ok "rockyou.txt unpacked"
fi

# ── 2. pipx: isolated Python tools (global bin dir so they land on PATH) ─────
c_info "pipx tools"
export PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
PIPX_TOOLS="impacket bloodhound certipy-ad coercer mitm6 lsassy \
ldapdomaindump trevorspray arjun holehe socialscan h8mail git-dumper"
for t in $PIPX_TOOLS; do
    pipx install "$t" >/dev/null 2>&1 && c_ok "pipx: $t" || c_warn "pipx-skip: $t"
done
# Tools not on PyPI under a plain name — install straight from the repo.
pipx_git() { pipx install "git+$1" >/dev/null 2>&1 && c_ok "pipx-git: ${1##*/}" \
             || c_warn "pipx-git-skip: ${1##*/}"; }
pipx_git https://github.com/Pennyw0rth/NetExec      # netexec / nxc (CME successor)
pipx_git https://github.com/0xZDH/o365spray
pipx ensurepath >/dev/null 2>&1 || true

# ── 3. Go tools (ProjectDiscovery + others); fall back if go missing ─────────
if command -v go >/dev/null 2>&1; then
    c_info "go tools → /usr/local/bin"
    export GOBIN=/usr/local/bin GOPATH="/root/go" GOFLAGS=-buildvcs=false
    go_get() { GOBIN=/usr/local/bin go install "$1" >/dev/null 2>&1 && c_ok "go: ${1%%@*}" || c_warn "go-skip: ${1%%@*}"; }
    go_get github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go_get github.com/ffuf/ffuf/v2@latest
    go_get github.com/projectdiscovery/httpx/cmd/httpx@latest
    go_get github.com/projectdiscovery/katana/cmd/katana@latest
    go_get github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go_get github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go_get github.com/hahwul/dalfox/v2@latest
    go_get github.com/lc/gau/v2/cmd/gau@latest
    go_get github.com/tomnomnom/waybackurls@latest
    go_get github.com/tomnomnom/assetfinder@latest
    go_get github.com/hakluke/hakrawler@latest
    go_get github.com/jaeles-project/gospider@latest
    go_get github.com/sensepost/gowitness@latest
    go_get github.com/haccer/subjack@latest      # A08 subdomain takeover (pending wiring)
else
    c_warn "go not found — skipping Go tools (apt install golang-go to enable)"
fi

# ── 4. git clones → /opt with PATH wrappers ──────────────────────────────────
c_info "git tools → /opt (+ /usr/local/bin wrappers)"
mkdir -p /opt
clone() { [ -d "$2" ] && return 0; git clone --depth 1 "$1" "$2" >/dev/null 2>&1 \
    && c_ok "git: $(basename "$2")" || c_warn "git-skip: $(basename "$2")"; }
wrap()  { printf '#!/usr/bin/env bash\nexec %s "$@"\n' "$2" > "/usr/local/bin/$1"; chmod +x "/usr/local/bin/$1"; }

clone https://github.com/epinna/tplmap          /opt/tplmap
[ -d /opt/tplmap ]   && wrap tplmap   "python3 /opt/tplmap/tplmap.py"
clone https://github.com/codingo/NoSQLMap       /opt/nosqlmap
[ -d /opt/nosqlmap ] && wrap nosqlmap "python3 /opt/nosqlmap/nosqlmap.py"
clone https://github.com/s0md3v/XSStrike        /opt/XSStrike
[ -d /opt/XSStrike ] && wrap xsstrike "python3 /opt/XSStrike/xsstrike.py"
clone https://github.com/s0md3v/Corsy           /opt/Corsy
[ -d /opt/Corsy ]    && wrap corsy    "python3 /opt/Corsy/corsy.py"
clone https://github.com/lobuhi/byp4xx          /opt/byp4xx
[ -d /opt/byp4xx ]   && wrap byp4xx   "python3 /opt/byp4xx/byp4xx.py"
clone https://github.com/ticarpi/jwt_tool       /opt/jwt_tool
[ -d /opt/jwt_tool ] && wrap jwt_tool "python3 /opt/jwt_tool/jwt_tool.py"
clone https://github.com/mazen160/struts-pwn    /opt/struts-pwn
[ -d /opt/struts-pwn ] && wrap struts-pwn "python3 /opt/struts-pwn/struts-pwn.py"
clone https://github.com/jondonas/linux-exploit-suggester-2 /opt/les2
[ -d /opt/les2 ] && wrap linux-exploit-suggester-2 "perl /opt/les2/linux-exploit-suggester-2.pl"
clone https://github.com/swisskyrepo/SSRFmap        /opt/ssrfmap
[ -d /opt/ssrfmap ] && { pip install -r /opt/ssrfmap/requirements.txt >/dev/null 2>&1 || true; \
    wrap ssrfmap "python3 /opt/ssrfmap/ssrfmap.py"; }
clone https://github.com/vladko312/SSTImap          /opt/sstimap
[ -d /opt/sstimap ] && { pip install -r /opt/sstimap/requirements.txt >/dev/null 2>&1 || true; \
    wrap sstimap "python3 /opt/sstimap/sstimap.py"; }
clone https://github.com/GerbenJavado/LinkFinder    /opt/LinkFinder
[ -d /opt/LinkFinder ] && { pip install -r /opt/LinkFinder/requirements.txt >/dev/null 2>&1 || true; \
    wrap linkfinder "python3 /opt/LinkFinder/linkfinder.py"; }

# ── 5. Downloads: PEASS-ng, pspy, ysoserial, suggesters ──────────────────────
c_info "binary downloads → /usr/local/bin"
dl() { curl -fsSL "$1" -o "$2" 2>/dev/null && chmod +x "$2" && c_ok "dl: $(basename "$2")" || c_warn "dl-skip: $(basename "$2")"; }
PE=https://github.com/peass-ng/PEASS-ng/releases/latest/download
dl "$PE/linpeas.sh"   /usr/local/bin/linpeas.sh
dl "$PE/winPEAS.bat"  /usr/local/bin/winpeas.exe   # PATH presence for the registry check
dl https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 /usr/local/bin/pspy64
# ysoserial (Java deserialization) — jar + wrapper
if curl -fsSL https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar \
        -o /opt/ysoserial.jar 2>/dev/null; then
    wrap ysoserial "java -jar /opt/ysoserial.jar"; c_ok "dl: ysoserial.jar"
else
    c_warn "dl-skip: ysoserial.jar"
fi

# ── 6. Final verification ────────────────────────────────────────────────────
verify_registry
c_info "Done. Re-run 'bash install-kali-tools.sh --verify' anytime to re-check."
c_warn "Windows-only privesc bins (GodPotato/PrintSpoofer/SweetPotato/Seatbelt/Watson) and a"
c_warn "few niche tools install on-demand; ARGUS skips any that remain missing."
