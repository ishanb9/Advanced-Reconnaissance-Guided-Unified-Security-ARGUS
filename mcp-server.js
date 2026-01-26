#!/usr/bin/env node

const http = require('http');
const { spawn } = require('child_process');

// Complete list of all 217 Kali tools
const KALI_TOOLS = [
  'airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng', 'wifite', 'reaver', 'kismet',
  'giskismet', 'fern-wifi-cracker', 'wifi-honey', 'asleap', 'eapmd5pass', 'mdk3', 'mdk4',
  'iw', 'iwconfig', '0trace', 'nmap', 'nikto', 'whatweb', 'theharvester', 'metagoofil', 
  'recon-ng', 'maltego', 'enum4linux', 'smtp-user-enum', 'snmpcheck', 'ace-voip', 'amap', 
  'apache-users', 'arp-scan', 'dmitry', 'dnsenum', 'dnsmap', 'dnsrecon', 'dnstracer', 
  'fierce', 'hping3', 'intrace', 'lbd', 'masscan', 'netdiscover', 'ncat', 'unicornscan', 
  'wafw00f', 'whois', 'urlcrazy', 'ndiff', 'bed', 'cisco-auditing-tool', 
  'cisco-global-exploiter', 'cisco-ocs', 'cisco-torch', 'dotdotpwn', 'gvmd', 'sfuzz', 
  'sidguesser', 'skipfish', 'uniscan', 'unix-privesc-check', 'spike', 'ftester', 
  'burpsuite', 'commix', 'sqlmap', 'wpscan', 'joomscan', 'dirbuster', 'dirb', 'gobuster',
  'wfuzz', 'ffuf', 'zaproxy', 'paros', 'webscarab', 'webshells', 'webacoo', 
  'jsql-injection', 'xsser', 'cadaver', 'plecost', 'laudanum', 'sqlninja', 'sqlsus', 
  'sqldict', 'sqsh', 'oscanner', 'tnscmd10g', 'hydra', 'john', 'johnny', 'hashcat', 
  'hashcat-utils', 'hash-identifier', 'medusa', 'ncrack', 'ophcrack', 'rainbowcrack', 
  'rcracki-mt', 'truecrack', 'crunch', 'cewl', 'rsmangler', 'pipal', 'cmospwd', 'chntpw',
  'radare2', 'ghidra', 'gdb', 'ollydbg', 'edb-debugger', 'jad', 'dex2jar', 'javasnoop', 
  'apktool', 'metasploit-framework', 'armitage', 'beef-xss', 'set', 'crackmapexec', 
  'powersploit', 'mimikatz', 'nishang', 'exploitdb', 'searchsploit', 'shellnoob', 
  'ropper', 'msfpc', 'jboss-autopwn', 'framework2', 'wireshark', 'tcpdump', 'ettercap', 
  'bettercap', 'responder', 'dsniff', 'dnschef', 'fiked', 'hamster-sidejack', 'hexinject', 
  'rebind', 'sniffjoke', 'sslsplit', 'mitmproxy', 'cdpsnarf', 'weevely', 'cymothoa', 
  'dbd', 'sbd', 'wce', 'pwnat', 'cryptcat', 'autopsy', 'binwalk', 'bulk-extractor', 
  'chkrootkit', 'foremost', 'pdfid', 'pdf-parser', 'sleuthkit', 'volatility', 'ddrescue', 
  'dumpzilla', 'dradis', 'faraday', 'magictree', 'eyewitness', 'enumiax', 'iaxflood', 
  'inviteflood', 'ohrwurm', 'protos-sip', 'rtpbreak', 'rtpflood', 'rtpinsertsound', 
  'rtpmixsound', 'sipp', 'siparmyknife', 'voiphopper', 'libfindrtp', 'blueranger', 
  'bluesnarfer', 'redfang', 'spooftooph', 'btscanner', 'thc-ssl-dos', 'slowhttptest', 
  't50', 'thc-pptp-bruter', 'ip', 'ifconfig', 'route', 'netstat', 'ss', 'arp', 'iptables', 
  'fragroute', 'fragrouter', 'multimac', 'sctpscan', 'exe2hexbat', 'hyperion', 'pack', 
  'padbuster', 'gpp-decrypt', 'hotpatch', 'sakis3g', 'twofi', 'ncat-w32', 'unicorn-magic',
  'mfterm', 'nipper-ng', 'sslyze', 'tlssled', 'xspy'
];

console.log('═'.repeat(80));
console.log('🚀 MCP Server Starting...');
console.log('═'.repeat(80));

const httpServer = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method === 'POST') {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk.toString();
    });

    req.on('end', () => {
      try {
        const request = JSON.parse(body);

        // ============================================================
        // METHOD 1: Tools List
        // ============================================================
        if (request.method === 'tools/list') {
          const tools = KALI_TOOLS.map(tool => ({
            name: tool,
            description: `Execute ${tool} command`
          }));

          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ tools }));
          console.log(`✓ Tools list requested (${tools.length} tools)`);
          return;  // CRITICAL: Return here to prevent fall-through
        }

        // ============================================================
        // METHOD 2: Tool Execution
        // ============================================================
        if (request.method === 'tools/call') {
          const { name, arguments: args } = request.params;
          
          if (!KALI_TOOLS.includes(name)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: `Unknown tool: ${name}` }));
            return;  // CRITICAL: Return here
          }
          
          // Set headers ONCE at the beginning
          res.writeHead(200, {
            'Content-Type': 'text/event-stream; charset=utf-8',
            'Cache-Control': 'no-cache, no-transform',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
          });

          const target = args.target || '';
          const options = args.options || '';
          const command = `${name} ${options} ${target}`.trim();

          console.log('\n' + '─'.repeat(80));
          console.log(`[TOOL] ${name}`);
          console.log(`[CMD] ${command}`);
          console.log('─'.repeat(80));

          // Send start event
          res.write(`data: ${JSON.stringify({ type: 'start', command })}\n\n`);

          console.log('[SPAWN] Creating process...');
          
          // Spawn process
          const proc = spawn('bash', ['-c', command], {
            detached: false,
            stdio: ['ignore', 'pipe', 'pipe']
          });
          
          console.log(`[SPAWN] Process created - PID: ${proc.pid}`);

          let outputLines = 0;
          let stderrLines = 0;
          let processExited = false;

          // Keep-alive heartbeat
          const heartbeat = setInterval(() => {
            if (!processExited) {
              res.write(': heartbeat\n\n');
            }
          }, 2000);

          // Process events
          proc.once('spawn', () => {
            console.log('[EVENT] spawn - Process successfully spawned');
          });

          proc.on('error', (error) => {
            processExited = true;
            clearInterval(heartbeat);
            console.error(`[EVENT] error - ${error.message}`);
            
            res.write(`data: ${JSON.stringify({ 
              type: 'error', 
              message: `Spawn error: ${error.message}` 
            })}\n\n`);
            res.end();
          });

          proc.on('close', (code, signal) => {
            processExited = true;
            clearInterval(heartbeat);
            
            console.log('─'.repeat(80));
            console.log(`[EVENT] close - Code: ${code}, Signal: ${signal}`);
            console.log(`[STATS] STDOUT: ${outputLines}, STDERR: ${stderrLines}`);
            console.log('─'.repeat(80));
            
            if (code === 0) {
              res.write(`data: ${JSON.stringify({ 
                type: 'output', 
                data: `[SUCCESS] Completed (${outputLines} lines)` 
              })}\n\n`);
              res.write(`data: ${JSON.stringify({ type: 'complete' })}\n\n`);
            } else if (signal) {
              res.write(`data: ${JSON.stringify({ 
                type: 'error', 
                message: `Process killed by signal: ${signal}`
              })}\n\n`);
            } else {
              res.write(`data: ${JSON.stringify({ 
                type: 'error', 
                code,
                message: `Command failed with exit code ${code}`
              })}\n\n`);
            }
            
            res.end();
          });

          // STDOUT
          proc.stdout.on('data', (data) => {
            const text = data.toString();
            console.log(`[STDOUT] ${text.trim()}`);
            
            text.split('\n').forEach(line => {
              if (line.trim()) {
                res.write(`data: ${JSON.stringify({ type: 'output', data: line })}\n\n`);
                outputLines++;
              }
            });
          });

          // STDERR
          proc.stderr.on('data', (data) => {
            const text = data.toString();
            console.error(`[STDERR] ${text.trim()}`);
            
            text.split('\n').forEach(line => {
              if (line.trim()) {
                res.write(`data: ${JSON.stringify({ type: 'output', data: `[STDERR] ${line}` })}\n\n`);
                stderrLines++;
              }
            });
          });

	  // Proper disconnect detection using response finished event
          let clientDisconnected = false;
          
          res.on('close', () => {
            if (!clientDisconnected) {
              clientDisconnected = true;
              clearInterval(heartbeat);
              
              console.log('[CLIENT] Response connection closed');
              
              if (!processExited && !proc.killed) {
                console.log('[KILL] Sending SIGTERM to orphaned process...');
                proc.kill('SIGTERM');
              }
            }
          });

          return;  // CRITICAL: Return to prevent fall-through
        }

        // ============================================================
        // METHOD 3: Unknown
        // ============================================================
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unknown method: ' + request.method }));

      } catch (error) {
        console.error('[ERROR]', error.message);
        
        // Only write headers if they haven't been sent
        if (!res.headersSent) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
        }
        res.end(JSON.stringify({ error: error.message }));
      }
    });

  } else {
    res.writeHead(405);
    res.end('Method not allowed');
  }
});

httpServer.listen(3000, () => {
  console.log('✅ MCP HTTP Server: http://localhost:3000');
  console.log(`✅ Tools Available: ${KALI_TOOLS.length}`);
  console.log('✅ Status: Ready');
  console.log('═'.repeat(80));
});
