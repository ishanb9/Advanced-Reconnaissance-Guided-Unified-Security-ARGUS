/**
 * ARGUS — MCP Tool Server
 *
 * Comprehensive tool registry with 260+ Kali Linux security tools.
 * Receives requests from FastAPI agents, executes tools as child processes,
 * streams output as Server-Sent Events (SSE).
 *
 * Protocol (POST /):
 *   { "method": "tools/call",   "params": { "name": "nmap", "arguments": { "target": "10.0.0.1", "options": "-sV -p 80" } } }
 *   { "method": "tools/list",   "params": {} }
 *   { "method": "tools/stop",   "params": {} }
 *   { "method": "tools/check",  "params": { "name": "nmap" } }
 *
 * SSE stream events:
 *   data: {"type": "stdout", "data": "line\n"}
 *   data: {"type": "stderr", "data": "error\n"}
 *   data: {"type": "exit",   "code": 0}
 *   data: {"type": "error",  "message": "tool not found"}
 *   data: {"type": "info",   "message": "tool started, pid: 1234"}
 *
 * Start: sudo node mcp-server.js
 * Port:  3000
 */

const http      = require('http');
const { spawn } = require('child_process');
const { execSync } = require('child_process');
const PORT = 3000;

// ─────────────────────────────────────────────────────────────
//  TOOL REGISTRY — 134 Kali Linux security tools
// ─────────────────────────────────────────────────────────────
const TOOLS = {
  // ── Network Discovery & Scanning ─────────────────────────
  nmap:         { bin: 'nmap',           cat: 'network',   desc: 'Network port scanner, service/OS detection, NSE scripts' },
  masscan:      { bin: 'masscan',        cat: 'network',   desc: 'Extremely fast TCP port scanner' },
  netdiscover:  { bin: 'netdiscover',    cat: 'network',   desc: 'ARP network discovery tool' },
  'arp-scan':   { bin: 'arp-scan',       cat: 'network',   desc: 'ARP scanner for local network hosts' },
  arping:       { bin: 'arping',         cat: 'network',   desc: 'ARP/ICMP host discovery' },
  fping:        { bin: 'fping',          cat: 'network',   desc: 'Fast parallel ICMP pinger' },
  hping3:       { bin: 'hping3',         cat: 'network',   desc: 'TCP/IP packet assembler and analyzer' },
  traceroute:   { bin: 'traceroute',     cat: 'network',   desc: 'Trace IP packet route to host' },
  nbtscan:      { bin: 'nbtscan',        cat: 'network',   desc: 'NetBIOS name scanner' },
  unicornscan:  { bin: 'unicornscan',    cat: 'network',   desc: 'Asynchronous stateless TCP scanner' },
  ndiff:        { bin: 'ndiff',          cat: 'network',   desc: 'Compare nmap scan results' },
  zenmap:       { bin: 'zenmap',         cat: 'network',   desc: 'Nmap GUI frontend' },

  // ── Web Application Testing ───────────────────────────────
  nikto:        { bin: 'nikto',          cat: 'web',       desc: 'Web server vulnerability scanner' },
  gobuster:     { bin: 'gobuster',       cat: 'web',       desc: 'Dir/file/DNS/vhost/S3 brute-forcer' },
  droopescan:   { bin: 'droopescan',     cat: 'web',       desc: 'Drupal/SilverStripe/Joomla/WordPress vulnerability scanner' },
  joomscan:     { bin: 'joomscan',       cat: 'web',       desc: 'OWASP Joomla vulnerability scanner' },
  magescan:     { bin: 'magescan',       cat: 'web',       desc: 'Magento security scanner' },
  dirb:         { bin: 'dirb',           cat: 'web',       desc: 'Web content scanner with dictionary' },
  wfuzz:        { bin: 'wfuzz',          cat: 'web',       desc: 'Web fuzzer for parameters, dirs, auth' },
  ffuf:         { bin: 'ffuf',           cat: 'web',       desc: 'Fast web fuzzer written in Go' },
  whatweb:      { bin: 'whatweb',        cat: 'web',       desc: 'Web technology fingerprinter' },
  wafw00f:      { bin: 'wafw00f',        cat: 'web',       desc: 'WAF detection and fingerprinting' },
  wapiti:       { bin: 'wapiti',         cat: 'web',       desc: 'Web application vulnerability scanner (XSS, SQLi, etc.)' },
  skipfish:     { bin: 'skipfish',       cat: 'web',       desc: 'Recursive web application security recon' },
  sqlmap:       { bin: 'sqlmap',         cat: 'web',       desc: 'Automated SQL injection detection and exploitation' },
  commix:       { bin: 'commix',         cat: 'web',       desc: 'OS command injection exploitation' },
  davtest:      { bin: 'davtest',        cat: 'web',       desc: 'WebDAV server upload/execute tester' },
  wpscan:       { bin: 'wpscan',         cat: 'web',       desc: 'WordPress vulnerability scanner' },
  weevely:      { bin: 'weevely',        cat: 'web',       desc: 'PHP web shell management tool' },
  cutycapt:     { bin: 'cutycapt',       cat: 'web',       desc: 'Capture web page screenshots' },
  'dirbuster':  { bin: 'dirb',           cat: 'web',       desc: 'Multi-threaded web content brute-forcer' },
  curl:         { bin: 'curl',           cat: 'web',       desc: 'HTTP request tool for manual web testing' },

  // ── DNS & Subdomain Enumeration ───────────────────────────
  dnsrecon:     { bin: 'dnsrecon',       cat: 'dns',       desc: 'DNS enumeration: zone transfer, brute force, records' },
  dnsenum:      { bin: 'dnsenum',        cat: 'dns',       desc: 'DNS enumeration and zone transfer tool' },
  dnsmap:       { bin: 'dnsmap',         cat: 'dns',       desc: 'DNS subdomain brute-force tool' },
  dnschef:      { bin: 'dnschef',        cat: 'dns',       desc: 'Configurable DNS proxy and spoofer' },
  fierce:       { bin: 'fierce',         cat: 'dns',       desc: 'DNS reconnaissance and host discovery' },
  'bind9-host': { bin: 'host',           cat: 'dns',       desc: 'DNS lookup utility' },
  dig:          { bin: 'dig',            cat: 'dns',       desc: 'DNS lookup and query tool' },
  nslookup:     { bin: 'nslookup',       cat: 'dns',       desc: 'DNS name server lookup utility' },

  // ── OSINT ─────────────────────────────────────────────────
  amass:        { bin: 'amass',          cat: 'osint',     desc: 'In-depth attack surface mapping and OSINT' },
  theharvester: { bin: 'theHarvester',   cat: 'osint',     desc: 'Email/subdomain/name OSINT harvesting' },
  'recon-ng':   { bin: 'recon-ng',       cat: 'osint',     desc: 'Web reconnaissance framework with modules' },
  spiderfoot:   { bin: 'spiderfoot',     cat: 'osint',     desc: 'Automated OSINT collection framework' },
  dmitry:       { bin: 'dmitry',         cat: 'osint',     desc: 'Deepmagic information gathering tool' },
  shodan:       { bin: 'shodan',         cat: 'osint',     desc: 'Shodan CLI for internet-connected device search' },
  whois:        { bin: 'whois',          cat: 'osint',     desc: 'Domain/IP WHOIS information' },
  'bloodhound': { bin: 'bloodhound-python', cat: 'osint',  desc: 'Active Directory attack path finder' },
  maltego:      { bin: 'maltego',        cat: 'osint',     desc: 'Visual OSINT and link analysis' },
  'base58':     { bin: 'base58',         cat: 'osint',     desc: 'Base58 encode/decode utility' },

  // ── Vulnerability Assessment ──────────────────────────────
  searchsploit: { bin: 'searchsploit',   cat: 'vuln',      desc: 'ExploitDB offline search tool' },
  sslscan:      { bin: 'sslscan',        cat: 'vuln',      desc: 'Enumerate SSL/TLS ciphers and configurations' },
  sslyze:       { bin: 'sslyze',         cat: 'vuln',      desc: 'Fast SSL/TLS configuration analyzer' },
  testssl:      { bin: 'testssl.sh',     cat: 'vuln',      desc: 'Comprehensive SSL/TLS testing including cipher suites and CVEs', fallback: '/usr/bin/testssl.sh' },
  ncrack:       { bin: 'ncrack',         cat: 'vuln',      desc: 'High-speed network authentication cracker' },
  'openvas':    { bin: 'openvas-scanner', cat: 'vuln',     desc: 'OpenVAS vulnerability scanner' },

  // ── SMB / Windows / Active Directory ─────────────────────
  enum4linux:   { bin: 'enum4linux',     cat: 'smb',       desc: 'SMB/NetBIOS enumeration for Windows/Samba' },
  'enum4linux-ng': { bin: 'enum4linux-ng', cat: 'smb',     desc: 'Rewrite of enum4linux with extra features and JSON output' },
  smbmap:       { bin: 'smbmap',         cat: 'smb',       desc: 'SMB share permissions and file enumeration' },
  smbclient:    { bin: 'smbclient',      cat: 'smb',       desc: 'SMB client to list shares and transfer files' },
  rpcclient:    { bin: 'rpcclient',      cat: 'smb',       desc: 'MS-RPC client for Windows enumeration' },
  netexec:      { bin: 'netexec',        cat: 'smb',       desc: 'Swiss-army knife for pentesting AD/SMB/LDAP/WinRM' },
  crackmapexec: { bin: 'crackmapexec',   cat: 'smb',       desc: 'Network pentesting: SMB, LDAP, WinRM, MSSQL' },
  'evil-winrm': { bin: 'evil-winrm',     cat: 'smb',       desc: 'WinRM shell for pentesting Windows targets' },
  ldapsearch:   { bin: 'ldapsearch',     cat: 'smb',       desc: 'LDAP directory enumeration' },
  certipy:      { bin: 'certipy',        cat: 'smb',       desc: 'Active Directory certificate services abuse' },
  polenum:      { bin: 'polenum',        cat: 'smb',       desc: 'Extract password policy from Windows' },

  // ── Exploitation Frameworks ───────────────────────────────
  msfconsole:   { bin: 'msfconsole',     cat: 'exploit',   desc: 'Metasploit Framework interactive console' },
  msfvenom:     { bin: 'msfvenom',       cat: 'exploit',   desc: 'Metasploit standalone payload generator' },
  msfpc:        { bin: 'msfpc',          cat: 'exploit',   desc: 'MSFvenom payload creator (simplified)' },
  setoolkit:    { bin: 'setoolkit',      cat: 'exploit',   desc: 'Social Engineering Toolkit' },

  // ── Password Attacks ──────────────────────────────────────
  hydra:        { bin: 'hydra',          cat: 'password',  desc: 'Parallelized network login brute-forcer' },
  medusa:       { bin: 'medusa',         cat: 'password',  desc: 'Parallel modular brute-force tool' },
  patator:      { bin: 'patator',        cat: 'password',  desc: 'Multi-purpose brute-force tool' },
  hashcat:      { bin: 'hashcat',        cat: 'password',  desc: 'GPU-accelerated hash cracker' },
  john:         { bin: 'john',           cat: 'password',  desc: 'John the Ripper password cracker' },
  crunch:       { bin: 'crunch',         cat: 'password',  desc: 'Wordlist/dictionary generator' },
  cewl:         { bin: 'cewl',           cat: 'password',  desc: 'Custom wordlist generator from target website' },
  'hash-identifier': { bin: 'hash-identifier', cat: 'password', desc: 'Identify hash type from hash string' },
  hashid:       { bin: 'hashid',         cat: 'password',  desc: 'Hash type identifier' },
  ophcrack:     { bin: 'ophcrack',       cat: 'password',  desc: 'Windows password cracker using rainbow tables' },
  chntpw:       { bin: 'chntpw',         cat: 'password',  desc: 'NT/2000/XP/Vista/7 registry and SAM editor' },
  maskprocessor: { bin: 'mp64',          cat: 'password',  desc: 'Hashcat mask-based candidate generator' },
  rsmangler:    { bin: 'rsmangler',      cat: 'password',  desc: 'Wordlist mangler and permutator' },
  pipal:        { bin: 'pipal',          cat: 'password',  desc: 'Password frequency and pattern analyzer' },
  samdump2:     { bin: 'samdump2',       cat: 'password',  desc: 'Dump Windows NT/2k/XP password hashes' },
  'gpp-decrypt': { bin: 'gpp-decrypt',   cat: 'password',  desc: 'Decrypt GPP passwords from Groups.xml' },

  // ── Privilege Escalation & Post-Exploitation ──────────────
  linpeas:      { bin: 'linpeas.sh',     cat: 'privesc',   desc: 'Linux Privilege Escalation Awesome Script', fallback: '/usr/share/peass/linpeas.sh' },
  linenum:      { bin: 'linenum.sh',     cat: 'privesc',   desc: 'LinEnum — detailed Linux enumeration script', fallback: '/usr/share/linenum/LinEnum.sh' },
  winpeas:      { bin: 'winpeas.exe',    cat: 'privesc',   desc: 'Windows Privilege Escalation Awesome Script', fallback: '/usr/share/peass/winpeas.exe' },
  'unix-privesc-check': { bin: 'unix-privesc-check', cat: 'privesc', desc: 'Automated Unix privilege escalation checker' },
  mimikatz:     { bin: 'mimikatz',       cat: 'privesc',   desc: 'Windows credential extraction and manipulation' },
  wce:          { bin: 'wce',            cat: 'privesc',   desc: 'Windows Credential Editor - dump plaintext passwords' },
  powershell:   { bin: 'pwsh',           cat: 'privesc',   desc: 'PowerShell cross-platform for post-exploitation' },
  // System commands used by privesc agent
  find:         { bin: 'find',           cat: 'privesc',   desc: 'File system search (SUID, writable, capabilities)' },
  uname:        { bin: 'uname',          cat: 'privesc',   desc: 'Print kernel and system information' },
  whoami:       { bin: 'whoami',         cat: 'privesc',   desc: 'Print current user identity' },
  id:           { bin: 'id',             cat: 'privesc',   desc: 'Print user and group IDs' },
  getcap:       { bin: 'getcap',         cat: 'privesc',   desc: 'Get file capabilities (Linux privesc vector)' },
  sudo:         { bin: 'sudo',           cat: 'privesc',   desc: 'Check sudo privileges and misconfigurations' },

  // ── Wireless Attacks ──────────────────────────────────────
  'airmon-ng':  { bin: 'airmon-ng',      cat: 'wireless',  desc: 'Enable/disable monitor mode on wireless interfaces' },
  'aircrack-ng': { bin: 'aircrack-ng',   cat: 'wireless',  desc: 'WEP/WPA/WPA2 WiFi network cracker' },
  kismet:        { bin: 'kismet',        cat: 'wireless',  desc: 'Wireless network detector and sniffer' },
  reaver:        { bin: 'reaver',        cat: 'wireless',  desc: 'WPS PIN brute-force attack' },
  bully:         { bin: 'bully',         cat: 'wireless',  desc: 'Alternative WPS brute-force implementation' },
  wifite:        { bin: 'wifite',        cat: 'wireless',  desc: 'Automated wireless security auditor' },
  macchanger:    { bin: 'macchanger',    cat: 'wireless',  desc: 'MAC address spoofing and randomization' },

  // ── Network Traffic Analysis & MITM ──────────────────────
  arpspoof:     { bin: 'arpspoof',       cat: 'traffic',   desc: 'ARP cache poisoning for MITM attacks' },
  tshark:       { bin: 'tshark',         cat: 'traffic',   desc: 'Network protocol analyzer (CLI Wireshark)' },
  tcpdump:      { bin: 'tcpdump',        cat: 'traffic',   desc: 'Packet capture and analysis' },
  ettercap:     { bin: 'ettercap',       cat: 'traffic',   desc: 'MITM attacks, sniffing, ARP poisoning' },
  mitmproxy:    { bin: 'mitmproxy',      cat: 'traffic',   desc: 'Interactive TLS-capable HTTP proxy' },
  dsniff:       { bin: 'dsniff',         cat: 'traffic',   desc: 'Network sniffing toolkit (urlsnarf, msgsnarf)' },
  ngrep:        { bin: 'ngrep',          cat: 'traffic',   desc: 'Network-layer grep - pattern match on packets' },
  tcpreplay:    { bin: 'tcpreplay',      cat: 'traffic',   desc: 'Replay captured network traffic' },
  'netsniff-ng': { bin: 'netsniff-ng',   cat: 'traffic',   desc: 'High-performance Linux network analyzer' },
  responder:    { bin: 'responder',      cat: 'traffic',   desc: 'LLMNR/NBT-NS/MDNS poisoning and credential capture' },

  // ── SNMP ──────────────────────────────────────────────────
  snmpwalk:     { bin: 'snmpwalk',       cat: 'snmp',      desc: 'Walk SNMP MIB tree for information' },
  snmpget:      { bin: 'snmpget',        cat: 'snmp',      desc: 'Get specific SNMP OID value' },
  snmpcheck:    { bin: 'snmpcheck',      cat: 'snmp',      desc: 'SNMP enumeration tool' },
  onesixtyone: { bin: 'onesixtyone',     cat: 'snmp',      desc: 'Fast SNMP community string scanner' },

  // ── Email & Communication ─────────────────────────────────
  swaks:        { bin: 'swaks',          cat: 'email',     desc: 'Swiss Army Knife for SMTP testing' },
  'smtp-user-enum': { bin: 'smtp-user-enum', cat: 'email', desc: 'SMTP VRFY/EXPN/RCPT user enumeration' },
  sendemail:    { bin: 'sendEmail',      cat: 'email',     desc: 'Send email from command line' },

  // ── VPN & Tunneling ───────────────────────────────────────
  openvpn:      { bin: 'openvpn',        cat: 'tunnel',    desc: 'VPN client and server' },
  iodine:       { bin: 'iodine',         cat: 'tunnel',    desc: 'IPv4-over-DNS tunnel for bypassing firewalls' },
  dns2tcp:      { bin: 'dns2tcp',        cat: 'tunnel',    desc: 'TCP relay over DNS for data exfiltration' },
  socat:        { bin: 'socat',          cat: 'tunnel',    desc: 'Multipurpose relay and PTY shell tool' },
  netcat:       { bin: 'nc',             cat: 'tunnel',    desc: 'TCP/UDP connection, port scanning, file transfer' },
  stunnel:      { bin: 'stunnel4',       cat: 'tunnel',    desc: 'SSL/TLS tunnel for plain protocols' },
  cryptcat:     { bin: 'cryptcat',       cat: 'tunnel',    desc: 'Encrypted netcat with twofish cipher' },
  proxychains4: { bin: 'proxychains4',   cat: 'tunnel',    desc: 'Route connections through proxy chains' },

  // ── Forensics & Reverse Engineering ──────────────────────
  binwalk:      { bin: 'binwalk',        cat: 'forensics', desc: 'Firmware/binary analysis and extraction' },
  radare2:      { bin: 'r2',             cat: 'forensics', desc: 'Open-source reverse engineering framework' },
  'bulk-extractor': { bin: 'bulk_extractor', cat: 'forensics', desc: 'High-performance digital forensics scanner' },
  'pdf-parser': { bin: 'pdf-parser',     cat: 'forensics', desc: 'Parse and analyze PDF structure' },
  pdfid:        { bin: 'pdfid',          cat: 'forensics', desc: 'Identify malicious PDF elements' },
  scalpel:      { bin: 'scalpel',        cat: 'forensics', desc: 'Fast file carver for recovery' },
  testdisk:     { bin: 'testdisk',       cat: 'forensics', desc: 'Partition and filesystem recovery' },
  exiv2:        { bin: 'exiv2',          cat: 'forensics', desc: 'Image EXIF metadata viewer and editor' },

  // ── Payload Generation ────────────────────────────────────
  upx:          { bin: 'upx',            cat: 'payload',   desc: 'Executable packer for AV evasion' },

  // ── Other Pentesting Tools ────────────────────────────────
  'ike-scan':   { bin: 'ike-scan',       cat: 'misc',      desc: 'IKE/IPsec VPN endpoint scanner' },
  'thc-ipv6':   { bin: 'atk6-alive6',   cat: 'misc',      desc: 'IPv6 attack and reconnaissance toolkit' },
  inetsim:      { bin: 'inetsim',        cat: 'misc',      desc: 'Internet service simulation for malware analysis' },
  'lbd':        { bin: 'lbd',            cat: 'misc',      desc: 'Load balancing detector' },
  tcpick:       { bin: 'tcpick',         cat: 'misc',      desc: 'TCP stream sniffer and connection tracker' },
  udptunnel:    { bin: 'udptunnel',      cat: 'misc',      desc: 'Tunnel TCP connections over UDP' },

  // ── Web (Extended) ────────────────────────────────────────
  nuclei:       { bin: 'nuclei',         cat: 'web',       desc: 'Fast template-based vulnerability scanner (1000s of CVE/misconfig templates)' },
  feroxbuster:  { bin: 'feroxbuster',    cat: 'web',       desc: 'Fast, recursive content discovery tool written in Rust' },
  hakrawler:    { bin: 'hakrawler',      cat: 'web',       desc: 'Fast web crawler for endpoints, JS files, subdomains' },
  gospider:     { bin: 'gospider',       cat: 'web',       desc: 'Fast web spider with JavaScript parsing' },
  katana:       { bin: 'katana',         cat: 'web',       desc: 'Next-generation crawling and spidering framework' },
  gau:          { bin: 'gau',            cat: 'web',       desc: 'Fetch known URLs from Wayback Machine, OTX, Common Crawl' },
  dalfox:       { bin: 'dalfox',         cat: 'web',       desc: 'Fast parameter analysis and XSS scanning tool' },
  xsstrike:     { bin: 'xsstrike',       cat: 'web',       desc: 'Advanced XSS detection and exploitation suite' },
  nosqlmap:     { bin: 'nosqlmap',       cat: 'web',       desc: 'Automated NoSQL (MongoDB/Redis/CouchDB) injection tool' },
  tplmap:       { bin: 'tplmap',         cat: 'web',       desc: 'Server-Side Template Injection (SSTI) detection and exploitation' },
  ssrfmap:      { bin: 'ssrfmap',        cat: 'web',       desc: 'Automatic SSRF fuzzer and exploitation tool' },
  corsy:        { bin: 'corsy',          cat: 'web',       desc: 'CORS misconfiguration scanner' },
  arjun:        { bin: 'arjun',          cat: 'web',       desc: 'HTTP parameter discovery suite' },
  'jwt-tool':   { bin: 'jwt_tool',       cat: 'web',       desc: 'JWT analysis, manipulation, and exploitation toolkit' },
  'param-miner': { bin: 'param-miner',  cat: 'web',       desc: 'Web cache poisoning and hidden parameter discovery' },
  '403fuzzer':  { bin: '403fuzzer',      cat: 'web',       desc: '403/401 bypass fuzzer with various header and path techniques' },
  cariddi:      { bin: 'cariddi',        cat: 'web',       desc: 'Web crawler with secret/endpoint/URL discovery' },
  waybackurls:  { bin: 'waybackurls',   cat: 'web',       desc: 'Fetch URLs from Wayback Machine for a domain' },
  httprobe:     { bin: 'httprobe',       cat: 'web',       desc: 'Probe a list of hosts for HTTP/HTTPS servers' },
  httpx:        { bin: 'httpx',          cat: 'web',       desc: 'Fast multi-purpose HTTP toolkit for probing and fingerprinting' },
  'retire':     { bin: 'retire',         cat: 'web',       desc: 'Detect JS libraries with known CVEs (retire.js)' },
  'linkfinder': { bin: 'linkfinder',     cat: 'web',       desc: 'Discover endpoints and JS file URLs via regex analysis' },
  'byp4xx':     { bin: 'byp4xx',         cat: 'web',       desc: '40x HTTP bypass tool using various techniques' },

  // ── DNS & Subdomain (Extended) ────────────────────────────
  subfinder:    { bin: 'subfinder',      cat: 'dns',       desc: 'Fast passive subdomain enumeration tool' },
  assetfinder:  { bin: 'assetfinder',   cat: 'dns',       desc: 'Find domains and subdomains from certificate transparency' },
  dnsx:         { bin: 'dnsx',           cat: 'dns',       desc: 'Fast DNS toolkit for bulk resolution and record queries' },
  shuffledns:   { bin: 'shuffledns',    cat: 'dns',       desc: 'Mass DNS resolver with wildcard filtering' },
  puredns:      { bin: 'puredns',        cat: 'dns',       desc: 'Reliable DNS brute-forcing and resolving at scale' },
  altdns:       { bin: 'altdns',         cat: 'dns',       desc: 'Subdomain alteration wordlist and permutation generator' },
  'dnsvalidator': { bin: 'dnsvalidator', cat: 'dns',       desc: 'Validate DNS resolver lists for reliability' },
  massdns:      { bin: 'massdns',        cat: 'dns',       desc: 'High-performance DNS stub resolver for bulk lookups' },

  // ── OSINT (Extended) ──────────────────────────────────────
  sherlock:     { bin: 'sherlock',       cat: 'osint',     desc: 'Hunt usernames across 300+ social networks' },
  holehe:       { bin: 'holehe',         cat: 'osint',     desc: 'Check if email is registered on 120+ websites' },
  socialscan:   { bin: 'socialscan',     cat: 'osint',     desc: 'Accurate username and email availability checker' },
  crosslinked:  { bin: 'crosslinked',    cat: 'osint',     desc: 'LinkedIn recon and username generation' },
  emailharvester: { bin: 'emailharvester', cat: 'osint',   desc: 'Email address harvester from web sources' },
  urlcrazy:     { bin: 'urlcrazy',       cat: 'osint',     desc: 'Generate and test domain typos for phishing recon' },
  trufflehog:   { bin: 'trufflehog',    cat: 'osint',     desc: 'Scan git repos, S3, GCS, Docker images for secrets/credentials' },
  gitleaks:     { bin: 'gitleaks',       cat: 'osint',     desc: 'Detect secrets and hardcoded credentials in git history' },
  'h8mail':     { bin: 'h8mail',         cat: 'osint',     desc: 'Email OSINT and breach data correlation tool' },
  'pwndb':      { bin: 'pwndb',          cat: 'osint',     desc: 'Search pwndb for leaked credentials by email/domain' },
  metagoofil:   { bin: 'metagoofil',    cat: 'osint',     desc: 'Metadata extractor from public documents (Google dorking)' },
  eyewitness:   { bin: 'eyewitness',    cat: 'osint',     desc: 'Screenshot web apps, VNC, RDP for quick visual recon' },
  gowitness:    { bin: 'gowitness',      cat: 'osint',     desc: 'Web screenshot utility using Chrome headless' },
  photon:       { bin: 'photon',         cat: 'osint',     desc: 'Fast web crawler for OSINT: URLs, emails, secrets, endpoints' },

  // ── Active Directory (Extended) ───────────────────────────
  kerbrute:     { bin: 'kerbrute',       cat: 'ad',        desc: 'Kerberos brute-force, password spray, user enumeration' },
  'impacket-secretsdump': { bin: 'impacket-secretsdump', cat: 'ad', desc: 'Dump SAM/NTDS/LSA secrets remotely (DCSync, PTH)' },
  'impacket-psexec':   { bin: 'impacket-psexec',   cat: 'ad', desc: 'Execute commands on Windows via SMB (like PsExec)' },
  'impacket-wmiexec':  { bin: 'impacket-wmiexec',  cat: 'ad', desc: 'Semi-interactive shell via WMI without file upload' },
  'impacket-smbexec':  { bin: 'impacket-smbexec',  cat: 'ad', desc: 'SMB-based command execution with service creation' },
  'impacket-atexec':   { bin: 'impacket-atexec',   cat: 'ad', desc: 'Remote task scheduler execution via ATSVC' },
  'impacket-dcomexec': { bin: 'impacket-dcomexec', cat: 'ad', desc: 'DCOM-based remote command execution' },
  'impacket-ntlmrelayx': { bin: 'impacket-ntlmrelayx', cat: 'ad', desc: 'NTLM relay attack tool — capture and relay auth' },
  'impacket-GetNPUsers': { bin: 'impacket-GetNPUsers', cat: 'ad', desc: 'AS-REP roasting — get TGTs for users without pre-auth' },
  'impacket-GetUserSPNs': { bin: 'impacket-GetUserSPNs', cat: 'ad', desc: 'Kerberoasting — request TGS tickets for service accounts' },
  'impacket-ticketer': { bin: 'impacket-ticketer', cat: 'ad', desc: 'Create Golden/Silver Kerberos tickets' },
  'impacket-lookupsid': { bin: 'impacket-lookupsid', cat: 'ad', desc: 'Remote SID enumeration via SMB' },
  'impacket-smbserver': { bin: 'impacket-smbserver', cat: 'ad', desc: 'Simple SMB server for file transfer and credential capture' },
  'impacket-addcomputer': { bin: 'impacket-addcomputer', cat: 'ad', desc: 'Add computer accounts to AD (for RBCD attacks)' },
  'impacket-dacledit':  { bin: 'impacket-dacledit', cat: 'ad', desc: 'Read/write AD DACL ACE entries for privilege escalation' },
  'impacket-findDelegation': { bin: 'impacket-findDelegation', cat: 'ad', desc: 'Find Kerberos delegation configurations in AD' },
  ldapdomaindump:  { bin: 'ldapdomaindump', cat: 'ad',    desc: 'LDAP domain information dumper — users, groups, GPOs, trusts' },
  windapsearch:    { bin: 'windapsearch', cat: 'ad',       desc: 'Python LDAP enumeration: users, computers, admins, SPNs' },
  adidnsdump:      { bin: 'adidnsdump',   cat: 'ad',       desc: 'Enumerate Active Directory integrated DNS zones' },
  coercer:         { bin: 'coercer',      cat: 'ad',       desc: 'Coerce Windows auth via 12+ MS-RPC protocols (PetitPotam, etc.)' },
  mitm6:           { bin: 'mitm6',        cat: 'ad',       desc: 'IPv6 MITM attacks — DHCPv6 + DNS takeover for NTLM capture' },
  pretender:       { bin: 'pretender',    cat: 'ad',       desc: 'LLMNR/NBNS/mDNS/DHCPv6 spoofing for credential capture' },
  donpapi:         { bin: 'donpapi',      cat: 'ad',       desc: 'Remotely dump DPAPI secrets: browser creds, WiFi passwords, vaults' },
  lsassy:          { bin: 'lsassy',       cat: 'ad',       desc: 'Remote LSASS dump via various methods (procdump, nanodump, etc.)' },
  pypykatz:        { bin: 'pypykatz',     cat: 'ad',       desc: 'Mimikatz in pure Python — LSASS, registry, minidump parsing' },
  'kerberoast':    { bin: 'kerberoast',   cat: 'ad',       desc: 'PowerShell-based Kerberoast toolkit' },

  // ── Cloud Security ────────────────────────────────────────
  gsutil:          { bin: 'gsutil',       cat: 'cloud',    desc: 'Google Cloud Storage CLI — enumerate and access GCS buckets' },
  'aws':           { bin: 'aws',          cat: 'cloud',    desc: 'AWS CLI — enumerate and exploit AWS services (S3, EC2, IAM, Lambda)' },
  'az':            { bin: 'az',           cat: 'cloud',    desc: 'Azure CLI — enumerate Azure resources, storage, VMs, AD' },
  'gcloud':        { bin: 'gcloud',       cat: 'cloud',    desc: 'Google Cloud CLI — GCS, GCE, GKE, IAM enumeration' },
  pacu:            { bin: 'pacu',         cat: 'cloud',    desc: 'AWS exploitation framework — IAM privesc, data exfil, persistence' },
  prowler:         { bin: 'prowler',      cat: 'cloud',    desc: 'AWS/Azure/GCP security assessment and compliance tool' },
  scoutsuite:      { bin: 'scout',        cat: 'cloud',    desc: 'Multi-cloud (AWS/Azure/GCP/OCI) security auditing' },
  s3scanner:       { bin: 's3scanner',    cat: 'cloud',    desc: 'Enumerate open S3 buckets and dump contents' },
  'cloud-enum':    { bin: 'cloud_enum',   cat: 'cloud',    desc: 'Multi-cloud resource enumeration (AWS, Azure, GCP)' },
  cloudbrute:      { bin: 'cloudbrute',   cat: 'cloud',    desc: 'Cloud resource brute-force (storage, apps) across providers' },
  'lazys3':        { bin: 'lazys3',       cat: 'cloud',    desc: 'S3 bucket enumeration via various naming permutations' },
  'gcpbucketbrute': { bin: 'gcpbucketbrute', cat: 'cloud', desc: 'Enumerate Google Cloud Storage buckets' },
  'awsrecon':      { bin: 'awsrecon',     cat: 'cloud',    desc: 'Comprehensive AWS environment reconnaissance' },
  'cloudsplaining': { bin: 'cloudsplaining', cat: 'cloud', desc: 'AWS IAM policy analysis for privilege escalation paths' },
  'enumerate-iam': { bin: 'enumerate-iam', cat: 'cloud',   desc: 'Enumerate IAM permissions for current AWS credentials' },

  // ── Container & Kubernetes ────────────────────────────────
  kubectl:         { bin: 'kubectl',      cat: 'container', desc: 'Kubernetes CLI — manage clusters, pods, services, secrets' },
  'kube-hunter':   { bin: 'kube-hunter',  cat: 'container', desc: 'Kubernetes penetration testing tool' },
  'kube-bench':    { bin: 'kube-bench',   cat: 'container', desc: 'CIS Kubernetes benchmark security checker' },
  trivy:           { bin: 'trivy',        cat: 'container', desc: 'Container/IaC/repo vulnerability and secret scanner' },
  grype:           { bin: 'grype',        cat: 'container', desc: 'Container and filesystem vulnerability scanner' },
  docker:          { bin: 'docker',       cat: 'container', desc: 'Docker CLI — list containers, inspect mounts, exec, privesc' },
  amicontained:    { bin: 'amicontained', cat: 'container', desc: 'Container introspection — capabilities, seccomp, namespaces' },
  deepce:          { bin: 'deepce',       cat: 'container', desc: 'Docker privilege escalation and container escape tool' },
  'cdk':           { bin: 'cdk',          cat: 'container', desc: 'Container/Kubernetes penetration testing toolkit' },
  'botb':          { bin: 'botb',         cat: 'container', desc: 'Break Out The Box — container escape techniques' },
  'kubeaudit':     { bin: 'kubeaudit',    cat: 'container', desc: 'Kubernetes cluster security auditor' },
  'kubesec':       { bin: 'kubesec',      cat: 'container', desc: 'Kubernetes resource security risk analysis' },
  'popeye':        { bin: 'popeye',       cat: 'container', desc: 'Kubernetes cluster sanitizer and misconfiguration finder' },
  'crictl':        { bin: 'crictl',       cat: 'container', desc: 'CLI for CRI-compatible container runtimes (containerd, CRI-O)' },

  // ── C2 & Post-Exploitation Frameworks ────────────────────
  pwncat:          { bin: 'pwncat',       cat: 'c2',        desc: 'Advanced reverse/bind shell handler with post-exploitation' },
  sliver:          { bin: 'sliver',       cat: 'c2',        desc: 'Modern cross-platform C2 framework (HTTP/DNS/mTLS/WireGuard)' },
  'sliver-server': { bin: 'sliver-server', cat: 'c2',      desc: 'Sliver C2 server daemon' },
  'empire':        { bin: 'powershell-empire', cat: 'c2',   desc: 'PowerShell/.NET post-exploitation framework' },
  'starkiller':    { bin: 'starkiller',   cat: 'c2',        desc: 'GUI frontend for PowerShell Empire C2' },
  metasploit:      { bin: 'msfconsole',   cat: 'c2',        desc: 'Metasploit Framework (alias for msfconsole)' },
  beef:            { bin: 'beef-xss',     cat: 'c2',        desc: 'Browser Exploitation Framework — XSS-driven browser control' },
  routersploit:    { bin: 'routersploit', cat: 'c2',        desc: 'Router and embedded device exploitation framework' },

  // ── Tunneling & Pivoting (Extended) ──────────────────────
  chisel:          { bin: 'chisel',       cat: 'tunnel',    desc: 'Fast TCP/UDP tunnel over HTTP with SOCKS5 support' },
  'ligolo-ng':     { bin: 'ligolo-ng',    cat: 'tunnel',    desc: 'Tunneling tool using TUN interface for transparent pivoting' },
  sshuttle:        { bin: 'sshuttle',     cat: 'tunnel',    desc: 'Transparent SSH-based proxy (no root on remote required)' },
  'go-socks5':     { bin: 'go-socks5',    cat: 'tunnel',    desc: 'Simple SOCKS5 proxy server' },
  phuip:           { bin: 'phuip-fpizda', cat: 'tunnel',    desc: 'HTTP request smuggling attack tool' },
  rpivot:          { bin: 'rpivot',       cat: 'tunnel',    desc: 'Reverse SOCKS proxy for internal network pivoting' },
  revsocks:        { bin: 'revsocks',     cat: 'tunnel',    desc: 'Reverse SOCKS5 tunnel for firewall egress' },

  // ── Privilege Escalation (Extended) ──────────────────────
  pspy:            { bin: 'pspy64',       cat: 'privesc',   desc: 'Unprivileged Linux process snooping — catch cron/event processes', fallback: '/usr/local/bin/pspy64' },
  'linux-exploit-suggester': { bin: 'linux-exploit-suggester', cat: 'privesc', desc: 'Suggest kernel exploits based on kernel version', fallback: '/usr/share/linux-exploit-suggester/linux-exploit-suggester.sh' },
  'linux-exploit-suggester-2': { bin: 'linux-exploit-suggester-2', cat: 'privesc', desc: 'Next-gen kernel exploit suggester', fallback: '/usr/share/linux-exploit-suggester/linux-exploit-suggester-2.pl' },
  wesng:           { bin: 'wes',          cat: 'privesc',   desc: 'Windows Exploit Suggester Next Generation (systeminfo-based)' },
  'windows-exploit-suggester': { bin: 'windows-exploit-suggester', cat: 'privesc', desc: 'Map systeminfo output to known Windows exploits' },
  beroot:          { bin: 'beroot',       cat: 'privesc',   desc: 'Post-exploitation privesc checker for Linux/Windows/Mac' },
  'privesccheck':  { bin: 'privesccheck', cat: 'privesc',   desc: 'PowerShell privilege escalation checks for Windows' },
  seatbelt:        { bin: 'seatbelt',     cat: 'privesc',   desc: 'C# security-oriented host survey for post-exploitation' },
  'watson':        { bin: 'watson',       cat: 'privesc',   desc: 'Enumerate missing patches for Windows privilege escalation' },
  'powerup':       { bin: 'powerup',      cat: 'privesc',   desc: 'PowerShell script to find Windows privesc vectors' },
  'sweetpotato':   { bin: 'SweetPotato',  cat: 'privesc',   desc: 'Windows token privilege escalation (Potato family)' },
  'godpotato':     { bin: 'GodPotato',    cat: 'privesc',   desc: 'Universal Windows privesc via SeImpersonatePrivilege' },
  'printspoofer':  { bin: 'PrintSpoofer', cat: 'privesc',   desc: 'Windows privesc via PrintSpoofer / SeImpersonatePrivilege' },

  // ── Password Attacks (Extended) ───────────────────────────
  lazagne:         { bin: 'lazagne',      cat: 'password',  desc: 'Recover stored credentials from 65+ applications locally' },
  'sprayhound':    { bin: 'sprayhound',   cat: 'password',  desc: 'BloodHound-aware Kerberos password spraying (avoids lockouts)' },
  credmaster:      { bin: 'credmaster',   cat: 'password',  desc: 'Pluggable AWS-based password spraying across O365/ADFS/Okta' },
  ruler:           { bin: 'ruler',        cat: 'password',  desc: 'Interact with Exchange/Outlook for persistence and spraying' },
  'o365spray':     { bin: 'o365spray',    cat: 'password',  desc: 'Microsoft O365 user enumeration and password spraying' },
  'trevorspray':   { bin: 'trevorspray',  cat: 'password',  desc: 'Smart O365/AD password spraying with jitter and lockout avoidance' },
  'cupp':          { bin: 'cupp',         cat: 'password',  desc: 'Common User Passwords Profiler — personalized wordlist generator' },
  'mentalist':     { bin: 'mentalist',    cat: 'password',  desc: 'GUI wordlist generator for targeted password attacks' },
  'kwprocessor':   { bin: 'kwp64',        cat: 'password',  desc: 'Keyboard-walk password generator for hashcat' },
  'princeprocessor': { bin: 'pp64',       cat: 'password',  desc: 'PRINCE algorithm password candidate generator' },

  // ── Network Traffic & MITM (Extended) ────────────────────
  bettercap:       { bin: 'bettercap',    cat: 'traffic',   desc: 'Swiss-army knife for network attacks (ARP, DNS, BLE, WiFi, MITM)' },
  pcredz:          { bin: 'PCredz',       cat: 'traffic',   desc: 'Extract credentials from pcap or live interface (FTP, SMTP, LDAP, etc.)' },
  'net-creds':     { bin: 'net-creds',    cat: 'traffic',   desc: 'Sniff credentials from network traffic passively' },
  hcxtools:        { bin: 'hcxhashtool',  cat: 'traffic',   desc: 'Convert PMKID/handshake captures for hashcat cracking' },
  hcxdumptool:     { bin: 'hcxdumptool', cat: 'traffic',   desc: 'Capture PMKID and handshakes from 802.11 networks' },
  'mitmdump':      { bin: 'mitmdump',     cat: 'traffic',   desc: 'mitmproxy command-line version for scriptable HTTP interception' },
  'sshdump':       { bin: 'sshdump',      cat: 'traffic',   desc: 'Capture SSH traffic via remote capture over SSH' },

  // ── Wireless (Extended) ───────────────────────────────────
  wifiphisher:     { bin: 'wifiphisher',  cat: 'wireless',  desc: 'Automated evil twin attack and WPA credential phishing' },
  'hostapd-wpe':   { bin: 'hostapd-wpe', cat: 'wireless',  desc: 'WPA Enterprise attack AP — capture MSCHAPv2 credentials' },
  eaphammer:       { bin: 'eaphammer',    cat: 'wireless',  desc: 'Targeted evil twin attacks against WPA2-Enterprise networks' },
  'airgeddon':     { bin: 'airgeddon',    cat: 'wireless',  desc: 'Multi-use bash script for WiFi auditing and attacks' },
  'pixiewps':      { bin: 'pixiewps',     cat: 'wireless',  desc: 'Offline WPS pixie dust attack tool' },

  // ── Reverse Engineering (Extended) ────────────────────────
  gdb:             { bin: 'gdb',          cat: 'forensics', desc: 'GNU Debugger for binary analysis and exploit dev' },
  pwndbg:          { bin: 'pwndbg',       cat: 'forensics', desc: 'GDB plugin for heap/stack/ROP analysis during exploitation' },
  checksec:        { bin: 'checksec',     cat: 'forensics', desc: 'Check binary security features: NX, ASLR, PIE, RELRO, canary' },
  objdump:         { bin: 'objdump',      cat: 'forensics', desc: 'Disassemble and inspect ELF/PE binary sections' },
  strings:         { bin: 'strings',      cat: 'forensics', desc: 'Extract printable strings from binary files' },
  strace:          { bin: 'strace',       cat: 'forensics', desc: 'Trace system calls and signals of a process' },
  ltrace:          { bin: 'ltrace',       cat: 'forensics', desc: 'Trace library calls of a running process' },
  'file':          { bin: 'file',         cat: 'forensics', desc: 'Determine file type from magic bytes' },
  readelf:         { bin: 'readelf',      cat: 'forensics', desc: 'Display information about ELF binary files' },
  patchelf:        { bin: 'patchelf',     cat: 'forensics', desc: 'Modify ELF binary interpreter and RPATH' },
  'xxd':           { bin: 'xxd',          cat: 'forensics', desc: 'Hex dump and reverse hex dump of binary files' },
  'ghidra':        { bin: 'ghidra',       cat: 'forensics', desc: 'NSA reverse engineering framework (headless mode for scripts)' },
  'cutter':        { bin: 'cutter',       cat: 'forensics', desc: 'GUI reverse engineering platform powered by rizin' },
  'apktool':       { bin: 'apktool',      cat: 'forensics', desc: 'Android APK reverse engineering and repackaging' },
  'jadx':          { bin: 'jadx',         cat: 'forensics', desc: 'Dex to Java decompiler for Android APK analysis' },
  'volatility3':   { bin: 'vol',          cat: 'forensics', desc: 'Memory forensics framework for Windows/Linux/Mac analysis' },

  // ── Evasion & Payload Obfuscation ────────────────────────
  veil:            { bin: 'veil',         cat: 'evasion',   desc: 'AV-evasion payload generation framework (Ordnance, Evasion)' },
  shellter:        { bin: 'shellter',     cat: 'evasion',   desc: 'PE backdooring and AV-evasion via polymorphic injection' },
  'donut':         { bin: 'donut',        cat: 'evasion',   desc: 'Position-independent shellcode generator from EXE/DLL/.NET' },
  'freeze':        { bin: 'freeze',       cat: 'evasion',   desc: 'Payload toolkit for bypassing EDR with frozen strings and syscalls' },
  'scarecrow':     { bin: 'scarecrow',    cat: 'evasion',   desc: 'EDR-evasion payload creation tool (DLL sideloading, stomping)' },
  chameleon:       { bin: 'chameleon',    cat: 'evasion',   desc: 'PowerShell obfuscation and AMSI bypass tool' },
  'invoke-obfuscation': { bin: 'invoke-obfuscation', cat: 'evasion', desc: 'PowerShell obfuscation framework with multiple techniques' },

  // ── Exploitation (Extended) ───────────────────────────────
  'ysoserial':     { bin: 'ysoserial',    cat: 'exploit',   desc: 'Java deserialization exploit generation tool' },
  'ysoserial.net': { bin: 'ysoserial',    cat: 'exploit',   desc: '.NET deserialization exploitation framework' },
  'log4shell-scan': { bin: 'log4shell-scanner', cat: 'exploit', desc: 'Scan for Log4Shell (CVE-2021-44228) vulnerable endpoints' },
  'spring4shell-scan': { bin: 'spring4shell-scan', cat: 'exploit', desc: 'Scan for Spring4Shell (CVE-2022-22965) vulnerable apps' },
  'shiro-exploit': { bin: 'shiro-exploit', cat: 'exploit',  desc: 'Apache Shiro deserialization exploitation (CVE-2016-4437)' },
  'struts-pwn':    { bin: 'struts-pwn',   cat: 'exploit',   desc: 'Apache Struts RCE exploitation (S2-045, S2-052, etc.)' },

  // ── Misc (Extended) ───────────────────────────────────────
  'rlwrap':        { bin: 'rlwrap',       cat: 'misc',      desc: 'Readline wrapper for upgrading dumb reverse shells' },
  tmux:            { bin: 'tmux',         cat: 'misc',      desc: 'Terminal multiplexer for managing multiple shell sessions' },
  'screen':        { bin: 'screen',       cat: 'misc',      desc: 'Terminal multiplexer for persistent sessions' },
  jq:              { bin: 'jq',           cat: 'misc',      desc: 'Command-line JSON processor and query tool' },
  'base64':        { bin: 'base64',       cat: 'misc',      desc: 'Base64 encode/decode for payload delivery and obfuscation' },
  python3:         { bin: 'python3',      cat: 'misc',      desc: 'Python3 interpreter for custom scripts and one-liners' },
  'pwntools':      { bin: 'pwn',          cat: 'misc',      desc: 'CTF exploitation framework (cyclic, shellcraft, asm, disasm)' },
  'semgrep':       { bin: 'semgrep',      cat: 'misc',      desc: 'Static analysis for finding security bugs in source code' },
  'graudit':       { bin: 'graudit',      cat: 'misc',      desc: 'Grep-based source code audit tool for common vulnerabilities' },
  'bandit':        { bin: 'bandit',       cat: 'misc',      desc: 'Python source code security issue finder' },
  'yara':          { bin: 'yara',         cat: 'misc',      desc: 'Pattern matching for malware identification and threat hunting' },
  'cewl-ng':       { bin: 'cewl-ng',      cat: 'misc',      desc: 'Enhanced version of CeWL web wordlist generator' },
};

// ─────────────────────────────────────────────────────────────
//  ACTIVE PROCESS TRACKING
// ─────────────────────────────────────────────────────────────
const activeProcs = new Set();

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────

function sse(res, type, data) {
  if (res.writableEnded) return;
  const payload = type === 'exit'
    ? JSON.stringify({ type: 'exit', code: data })
    : JSON.stringify({ type, data: String(data) });
  res.write(`data: ${payload}\n\n`);
}

function sseMsg(res, type, message) {
  if (res.writableEnded) return;
  res.write(`data: ${JSON.stringify({ type, message })}\n\n`);
}

function parseArgs(optionsStr) {
  if (!optionsStr || !optionsStr.trim()) return [];
  const args  = [];
  const regex = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|(\S+)/g;
  let match;
  while ((match = regex.exec(optionsStr)) !== null) {
    args.push(match[1] !== undefined ? match[1] : match[2] !== undefined ? match[2] : match[3]);
  }
  return args;
}

function resolveBin(toolName) {
  const t = TOOLS[toolName];
  if (!t) return null;
  if (t.fallback) {
    try {
      const fs = require('fs');
      fs.accessSync(t.fallback, fs.constants.X_OK);
      return t.fallback;
    } catch (_) {}
  }
  return t.bin;
}

function checkToolAvailable(toolName) {
  const bin = resolveBin(toolName);
  if (!bin) return { available: false, reason: 'not in registry' };
  try {
    execSync(`which ${bin} 2>/dev/null || command -v ${bin} 2>/dev/null`, { stdio: 'pipe' });
    return { available: true, bin };
  } catch (_) {
    return { available: false, reason: `binary '${bin}' not found in PATH`, installHint: `apt install ${toolName} -y` };
  }
}

// ─────────────────────────────────────────────────────────────
//  TOOL EXECUTION
// ─────────────────────────────────────────────────────────────

function executeTool(toolName, target, options, res) {
  const tool = TOOLS[toolName];
  if (!tool) {
    sseMsg(res, 'error', `Unknown tool: ${toolName}. Check /tools/list for available tools.`);
    sse(res, 'exit', 1);
    res.end();
    return;
  }

  const bin  = resolveBin(toolName);
  const args = parseArgs(options);

  console.log(`[MCP] EXEC  tool=${toolName}  bin=${bin}  target=${target || '(none)'}  args="${args.join(' ')}"`);
  sseMsg(res, 'info', `Starting ${toolName} (${bin}) | pid pending`);

  let proc;
  try {
    proc = spawn(bin, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      env:   { ...process.env, TERM: 'xterm-256color', HOME: process.env.HOME || '/root' },
    });
  } catch (err) {
    sseMsg(res, 'error', `Failed to spawn ${bin}: ${err.message}`);
    sse(res, 'exit', 1);
    res.end();
    return;
  }

  activeProcs.add(proc);
  sseMsg(res, 'info', `${toolName} started, pid: ${proc.pid}`);

  proc.stdout.on('data', chunk => {
    chunk.toString().split('\n').forEach(line => {
      if (line) sse(res, 'stdout', line);
    });
  });

  proc.stderr.on('data', chunk => {
    chunk.toString().split('\n').forEach(line => {
      if (line) sse(res, 'stderr', line);
    });
  });

  proc.on('error', err => {
    activeProcs.delete(proc);
    if (err.code === 'ENOENT') {
      sseMsg(res, 'error', `Tool not found: '${bin}'. Install: apt install ${toolName} -y`);
    } else {
      sseMsg(res, 'error', `Process error: ${err.message}`);
    }
    sse(res, 'exit', 1);
    if (!res.writableEnded) res.end();
  });

  proc.on('close', code => {
    activeProcs.delete(proc);
    console.log(`[MCP] DONE  tool=${toolName}  pid=${proc.pid}  exit=${code}`);
    sse(res, 'exit', code ?? 0);
    if (!res.writableEnded) res.end();
  });

  res.on('close', () => {
    if (proc && !proc.killed) {
      proc.kill('SIGTERM');
      setTimeout(() => { try { proc.kill('SIGKILL'); } catch (_) {} }, 2000);
      activeProcs.delete(proc);
      console.log(`[MCP] KILL  tool=${toolName}  pid=${proc.pid} (client disconnected)`);
    }
  });
}

// ─────────────────────────────────────────────────────────────
//  HTTP SERVER
// ─────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── GET /health ─────────────────────────────────────────
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', tools: Object.keys(TOOLS).length, active: activeProcs.size }));
    return;
  }

  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Use POST /' }));
    return;
  }

  let body = '';
  req.on('data', chunk => { body += chunk; });
  req.on('end', () => {
    let payload;
    try { payload = JSON.parse(body); }
    catch (_) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
      return;
    }

    const method = payload.method || '';
    const params = payload.params || {};

    // ── tools/list ─────────────────────────────────────────
    if (method === 'tools/list') {
      const list = Object.entries(TOOLS).map(([name, t]) => ({
        name,
        description: t.desc,
        category:    t.cat,
        binary:      t.bin,
        inputSchema: {
          type:       'object',
          properties: {
            target:  { type: 'string', description: 'Target IP, hostname, URL, or domain' },
            options: { type: 'string', description: 'Full command-line arguments string' },
          },
        },
      }));
      // Group by category
      const byCategory = {};
      list.forEach(t => { (byCategory[t.category] = byCategory[t.category] || []).push(t); });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tools: list, by_category: byCategory, total: list.length }));
      return;
    }

    // ── tools/check ────────────────────────────────────────
    if (method === 'tools/check') {
      const name = params.name || '';
      const result = checkToolAvailable(name);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tool: name, ...result }));
      return;
    }

    // ── tools/stop ─────────────────────────────────────────
    if (method === 'tools/stop') {
      let killed = 0;
      for (const proc of activeProcs) {
        try { proc.kill('SIGTERM'); killed++; } catch (_) {}
      }
      setTimeout(() => {
        for (const proc of activeProcs) { try { proc.kill('SIGKILL'); } catch (_) {} }
        activeProcs.clear();
      }, 2000);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ stopped: killed, message: `Sent SIGTERM to ${killed} processes` }));
      return;
    }

    // ── tools/call ─────────────────────────────────────────
    if (method === 'tools/call') {
      const toolName = params.name || '';
      const args     = params.arguments || {};
      const target   = args.target  || '';
      const options  = args.options || '';

      if (!toolName) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'params.name is required' }));
        return;
      }

      res.writeHead(200, {
        'Content-Type':      'text/event-stream',
        'Cache-Control':     'no-cache',
        'Connection':        'keep-alive',
        'X-Accel-Buffering': 'no',
      });

      executeTool(toolName, target, options, res);
      return;
    }

    // ── Unknown ─────────────────────────────────────────────
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: `Unknown method: ${method}`,
      supported: ['tools/list', 'tools/call', 'tools/check', 'tools/stop'],
    }));
  });
});

server.listen(PORT, '0.0.0.0', () => {
  const cats = {};
  Object.values(TOOLS).forEach(t => { cats[t.cat] = (cats[t.cat] || 0) + 1; });

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║   ARGUS — MCP Tool Server                            ║');
  console.log(`║   Listening on  http://0.0.0.0:${PORT}                 ║`);
  console.log(`║   Tools registered: ${Object.keys(TOOLS).length}                         ║`);
  console.log('╚══════════════════════════════════════════════════════╝\n');
  Object.entries(cats).sort().forEach(([cat, n]) => {
    console.log(`  [${cat.padEnd(10)}] ${n} tools`);
  });
  console.log('\n  Endpoints: POST / (tools/list | tools/call | tools/check | tools/stop)');
  console.log('             GET  /health\n');
  console.log('  Note: Run with sudo for tools requiring root (nmap -O, masscan, etc.)\n');
});

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[ERROR] Port ${PORT} in use. Kill it: sudo fuser -k ${PORT}/tcp`);
  } else {
    console.error('[ERROR]', err.message);
  }
  process.exit(1);
});
