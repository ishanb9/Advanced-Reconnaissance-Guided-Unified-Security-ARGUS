#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify, Response
from flask_cors import CORS
import requests
import json
import time
import re
import subprocess
import netifaces
import urllib3

app = Flask(__name__)
CORS(app)

MCP_URL = "http://localhost:3000"
OLLAMA_URL = "http://192.168.0.100:11434"
MODEL_NAME = "gpt-oss:120b-cloud"

conversation_history = []

# ============================================================================
# NETWORK DETECTION & SYSTEM INTROSPECTION
# ============================================================================

def get_system_context():
    """Get complete system context - network interfaces, routing, etc."""
    context = {
        'interfaces': {},
        'routes': {},
        'local_networks': [],
        'default_gateway': None,
        'hostname': None
    }
    
    try:
        # Get hostname
        context['hostname'] = subprocess.check_output(['hostname']).decode().strip()
        
        # Get all network interfaces
        for iface in netifaces.interfaces():
            if iface == 'lo':
                continue
                
            addrs = netifaces.ifaddresses(iface)
            iface_info = {
                'name': iface,
                'ipv4': None,
                'netmask': None,
                'network': None,
                'mac': None,
                'status': 'unknown'
            }
            
            # Get IPv4 info
            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                iface_info['ipv4'] = ipv4.get('addr')
                iface_info['netmask'] = ipv4.get('netmask')
                
                if iface_info['ipv4'] and iface_info['netmask']:
                    import ipaddress
                    network = ipaddress.IPv4Network(f"{iface_info['ipv4']}/{iface_info['netmask']}", strict=False)
                    iface_info['network'] = str(network)
                    context['local_networks'].append(str(network))
            
            # Get MAC address
            if netifaces.AF_LINK in addrs:
                iface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr')
            
            # Check if interface is up
            try:
                result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
                if 'UP' in result.stdout:
                    iface_info['status'] = 'up'
                else:
                    iface_info['status'] = 'down'
            except:
                pass
            
            context['interfaces'][iface] = iface_info
        
        # Get default gateway
        gws = netifaces.gateways()
        if 'default' in gws and netifaces.AF_INET in gws['default']:
            context['default_gateway'] = gws['default'][netifaces.AF_INET][0]
    
    except Exception as e:
        print(f"[SYSTEM CONTEXT ERROR] {e}")
    
    return context

def explain_network_context():
    """Generate human-readable explanation of network context"""
    ctx = get_system_context()
    
    explanation = f"System: {ctx['hostname']}\n\n"
    explanation += "Network Interfaces:\n"
    
    for name, info in ctx['interfaces'].items():
        explanation += f"  • {name}: "
        if info['ipv4']:
            explanation += f"{info['ipv4']}/{info['netmask']} (network: {info['network']}) - {info['status'].upper()}"
        else:
            explanation += f"No IPv4 - {info['status'].upper()}"
        explanation += "\n"
    
    explanation += f"\nDefault Gateway: {ctx['default_gateway']}\n"
    explanation += f"Local Networks: {', '.join(ctx['local_networks'])}\n"
    
    return explanation

# ============================================================================
# INTELLIGENT LLM QUERY PROCESSOR
# ============================================================================

@app.route('/api/analyze', methods=['POST'])
def analyze_query():
    """Let LLM analyze the query and explain reasoning BEFORE execution"""
    global conversation_history 
    data = request.json
    user_message = data.get('message', '')
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    
    print(f"\n{'='*80}")
    print(f"[USER QUERY] {user_message}")
    print(f"{'='*80}")
    
    # Get system context
    system_context = get_system_context()
    network_explanation = explain_network_context()
    
    print(f"\n[SYSTEM CONTEXT]\n{network_explanation}")
    
    # Build conversation summary from history
    conversation_summary = ""
    if conversation_history:
        conversation_summary = "\n\nPREVIOUS CONVERSATION CONTEXT:\n"
        # Include last 10 exchanges (20 messages)
        recent_history = conversation_history[-20:]
        
        for msg in recent_history:
            role = msg['role'].upper()
            content = msg['content'][:200]  # Truncate long messages
            conversation_summary += f"\n{role}: {content}\n"
        
        conversation_summary += "\nUse this context to understand what the user is referring to.\n"
    
    # Build intelligent analysis prompt
    analysis_prompt = f"""You are an expert penetration tester analyzing a user's security testing request.

CURRENT SYSTEM CONTEXT:
{network_explanation}
{conversation_summary}

USER REQUEST: "{user_message}"

Your job is to:
1. Understand what the user wants to accomplish
2. Select the CORRECT tool for the job
3. Determine the correct target and options
4. Explain your reasoning in detail

CONTEXT AWARENESS:
- If user says "scan it", "check that", "try again" - refer to previous commands/targets
- If user says "the server", "that host", "same network" - use context from previous conversation
- If user references results ("the third one", "192.168.0.5") - understand from previous outputs

AVAILABLE TOOL CATEGORIES:

**NETWORK INFORMATION:**
- ifconfig / ip: Show network interfaces and IP addresses
- iwconfig / iw: Show wireless interfaces
- route / ip route: Show routing table
- arp: Show ARP cache
- netstat / ss: Show network connections

**NETWORK SCANNING:**
- nmap: Port and network scanning
  - Host discovery: -sn (no port scan)
  - Quick scan: -F (top 100 ports)
  - Service detection: -sV
  - Single host: any options
  - Subnet (/24): use -sn only (too slow otherwise)
- masscan: Fast port scanner
- netdiscover: ARP-based host discovery

**WIRELESS:**
- airmon-ng: Enable/disable monitor mode
  - start <interface>: Enable monitor mode
  - stop <interface>mon: Disable monitor mode
- airodump-ng: Capture wireless packets (needs monitor mode interface)
- iwconfig / iw: Check wireless interface info

**WEB SCANNING:**
- nikto: Web vulnerability scanner
- dirb / gobuster: Directory enumeration
- sqlmap: SQL injection testing

**PASSWORD ATTACKS:**
- hydra: Network protocol brute forcing
- john: Password hash cracking

CRITICAL RULES:
1. For "show interfaces" / "list interfaces" / "network interfaces" → Use ifconfig or ip addr
2. For "local network" / "this network" → Use the actual detected network from system context
3. For wireless interface info → Use iwconfig or iw
4. For enabling monitor mode → Use airmon-ng start <interface>
5. For scanning wifi → Need monitor mode interface (wlan0mon, etc)

RESPONSE FORMAT (JSON):
{{
  "reasoning": "Detailed explanation of what user wants and why you chose this approach",
  "tool": "exact-tool-name",
  "target": "target-value-or-empty",
  "options": "command-flags-or-empty",
  "explanation": "Plain English: what this command will do",
  "warnings": ["any warnings or prerequisites"],
  "expected_output": "what the user should expect to see"
}}

EXAMPLES:

Previous: User scanned 192.168.0.0/24 and found host 192.168.0.50
User: "scan that host for open ports"
{{
  "reasoning": "User wants to port scan 192.168.0.50 which was found in the previous network scan. Will use nmap with service detection.",
  "tool": "nmap",
  "target": "192.168.0.50",
  "options": "-sV -T4",
  "explanation": "This will scan 192.168.0.50 for open ports and identify running services.",
  "warnings": [],
  "expected_output": "List of open ports with service versions"
}}

Previous: User ran ifconfig and saw wlan0 interface
User: "enable monitor mode on it"
{{
  "reasoning": "User wants to enable monitor mode on wlan0 which was shown in the previous ifconfig output. Will use airmon-ng.",
  "tool": "airmon-ng",
  "target": "wlan0",
  "options": "start",
  "explanation": "This will enable monitor mode on wlan0, creating wlan0mon interface.",
  "warnings": ["This will create wlan0mon interface", "May kill interfering processes"],
  "expected_output": "Confirmation that monitor mode is enabled"
}}

User: "try that scan again but faster"
Previous: User ran nmap -sV on 192.168.0.50
{{
  "reasoning": "User wants to repeat the nmap scan on 192.168.0.50 but faster. Will use -F flag for quick scan instead of -sV.",
  "tool": "nmap",
  "target": "192.168.0.50",
  "options": "-F -T4",
  "explanation": "This will quickly scan the top 100 ports on 192.168.0.50.",
  "warnings": [],
  "expected_output": "Fast scan showing most common open ports"
}}

User: "show me my network interfaces"
{{
  "reasoning": "User wants to see their network configuration. The correct tool is 'ip' or 'ifconfig' to display all network interfaces with their IP addresses, MAC addresses, and status.",
  "tool": "ip",
  "target": "",
  "options": "addr",
  "explanation": "This will display all network interfaces on the system with their IP addresses, netmasks, and current status.",
  "warnings": [],
  "expected_output": "A list of all interfaces (eth0, wlan0, etc) with their IPv4/IPv6 addresses and MAC addresses"
}}

User: "scan my local network"
System shows: 192.168.11.0/24 network on eth0
{{
  "reasoning": "User wants to discover devices on their local network. From system context, the local network is 192.168.11.0/24. For a /24 subnet (254 hosts), we should use nmap with -sn flag for host discovery only, as full port scanning would take too long.",
  "tool": "nmap",
  "target": "192.168.11.0/24",
  "options": "-sn",
  "explanation": "This will perform a ping scan to discover all active devices on your local network (192.168.11.0/24) without scanning ports.",
  "warnings": ["This will scan 254 IP addresses", "May take 1-3 minutes"],
  "expected_output": "List of IP addresses and MAC addresses of devices on the network"
}}

User: "check wireless interfaces"
{{
  "reasoning": "User wants to see wireless network interface information. The correct tool is 'iwconfig' which shows wireless-specific details like mode, frequency, signal strength, etc.",
  "tool": "iwconfig",
  "target": "",
  "options": "",
  "explanation": "This will show all wireless network interfaces and their current configuration (mode, frequency, power, etc).",
  "warnings": [],
  "expected_output": "Wireless interface details including mode (managed/monitor), ESSID, frequency, and signal strength"
}}

User: "enable monitor mode on wlan0"
{{
  "reasoning": "User wants to put their wireless interface into monitor mode for packet capture. The correct tool is 'airmon-ng start' which will create a monitor mode interface (typically wlan0mon).",
  "tool": "airmon-ng",
  "target": "wlan0",
  "options": "start",
  "explanation": "This will enable monitor mode on wlan0, creating a new interface called wlan0mon that can capture wireless packets.",
  "warnings": ["This will kill interfering processes", "Will create wlan0mon interface", "Original wlan0 may become unavailable"],
  "expected_output": "Confirmation that monitor mode is enabled and new interface wlan0mon is created"
}}

User: "scan wifi networks"
{{
  "reasoning": "User wants to see available WiFi networks. This requires a wireless interface in monitor mode. If not already in monitor mode, they need to run 'airmon-ng start wlan0' first. Assuming monitor mode is enabled, we use airodump-ng.",
  "tool": "airodump-ng",
  "target": "wlan0mon",
  "options": "",
  "explanation": "This will scan for WiFi networks and show SSIDs, BSSIDs, channels, encryption, and connected clients.",
  "warnings": ["Requires monitor mode interface (wlan0mon)", "If not in monitor mode, run: airmon-ng start wlan0 first"],
  "expected_output": "Live updating list of WiFi networks with signal strength, encryption type, and clients"
}}

Now analyze this request:
User: "{user_message}"
System Context: {json.dumps(system_context, indent=2)}

Provide detailed JSON response with your reasoning:"""

    try:
        print(f"\n[LLM] Calling Ollama for analysis...")
        
        response = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL_NAME,
                "messages": [
                    {"role": "system", "content": analysis_prompt},
                    {"role": "user", "content": user_message}
                ],
                "stream": False
            },
            timeout=60
        )
        
        if response.status_code == 200:
            ai_response = response.json()['message']['content']
            
            print(f"\n[LLM RESPONSE]\n{ai_response}\n")
            
            # Add to conversation history
            conversation_history.append({"role": "user", "content": user_message})
            conversation_history.append({"role": "assistant", "content": ai_response})
            
            # Keep only last 50 messages (25 exchanges)
            if len(conversation_history) > 50:
                conversation_history = conversation_history[-50:]
            
            # Extract JSON
            json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
                
                print(f"\n{'='*80}")
                print(f"[ANALYSIS COMPLETE]")
                print(f"Tool: {analysis.get('tool')}")
                print(f"Target: {analysis.get('target')}")
                print(f"Options: {analysis.get('options')}")
                print(f"Reasoning: {analysis.get('reasoning')}")
                print(f"{'='*80}\n")
                
                return jsonify(analysis)
            else:
                return jsonify({
                    'error': 'Could not parse LLM response',
                    'raw_response': ai_response
                }), 500
        else:
            return jsonify({'error': f'Ollama error: {response.status_code}'}), 500
            
    except requests.exceptions.ConnectionError:
        return jsonify({'error': f'Cannot connect to Ollama at {OLLAMA_URL}'}), 500
    except Exception as e:
        print(f"[ANALYSIS ERROR] {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/api/conversation/history')
def get_conversation_history():
    """Get conversation history"""
    global conversation_history
    return jsonify({
        'count': len(conversation_history),
        'messages': conversation_history[-20:]  # Last 20 messages
    })

@app.route('/api/conversation/clear', methods=['POST'])
def clear_conversation():
    """Clear conversation history"""
    global conversation_history
    conversation_history.clear()
    return jsonify({'status': 'cleared'})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/system-context')
def get_context():
    """Get current system context"""
    context = get_system_context()
    explanation = explain_network_context()
    return jsonify({
        'context': context,
        'explanation': explanation
    })

@app.route('/api/tools')
def get_tools():
    """Get all tools from MCP server"""
    try:
        response = requests.post(
            MCP_URL,
            json={"method": "tools/list", "params": {}},
            timeout=5
        )
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'MCP server error'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/execute')
def execute():
    """Execute tool via MCP server with streaming"""
    tool = request.args.get('tool')
    target = request.args.get('target', '')
    options = request.args.get('options', '')
    
    print(f"\n{'='*80}")
    print(f"[WEB EXECUTE] Tool: {tool} | Target: {target} | Options: {options}")
    print(f"{'='*80}")
    
    def generate():
        http = urllib3.PoolManager()
        
        try:
            print(f"[WEB] Calling MCP server at {MCP_URL}")
            
            # Use urllib3 for proper streaming
            mcp_response = http.request(
                'POST',
                MCP_URL,
                body=json.dumps({
                    "method": "tools/call",
                    "params": {
                        "name": tool,
                        "arguments": {"target": target, "options": options}
                    }
                }).encode('utf-8'),
                headers={
                    'Content-Type': 'application/json'
                },
                preload_content=False,  # CRITICAL: Don't buffer response
                timeout=None
            )
            
            print(f"[WEB] MCP responded with status: {mcp_response.status}")
            
            if mcp_response.status != 200:
                error_msg = f'MCP server returned status {mcp_response.status}'
                print(f"[WEB ERROR] {error_msg}")
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
                return
            
            # Send start event
            yield f"data: {json.dumps({'type': 'start', 'tool': tool})}\n\n"
            print(f"[WEB] Sent start event, streaming from MCP...")
            
            # Stream line by line
            line_count = 0
            buffer = b''
            
            for chunk in mcp_response.stream(amt=1024):
                buffer += chunk
                
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    
                    if line_str:
                        # Forward SSE line
                        yield line_str + '\n\n'
                        line_count += 1
                        
                        if line_count % 10 == 0:
                            print(f"[WEB] Streamed {line_count} lines")
            
            # Send any remaining buffer
            if buffer:
                yield buffer.decode('utf-8', errors='ignore') + '\n\n'
            
            print(f"[WEB] Stream completed - {line_count} lines total")
            
        except Exception as e:
            print(f"[WEB ERROR] {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            if 'mcp_response' in locals():
                mcp_response.release_conn()
    
    return Response(
        generate(), 
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

if __name__ == '__main__':
    print("═" * 80)
    print("🚀 INTELLIGENT KALI PENTEST SERVER")
    print("═" * 80)
    print(f"📡 Web UI: http://0.0.0.0:5000")
    print(f"🔧 MCP Server: {MCP_URL}")
    print(f"🤖 AI Engine: {OLLAMA_URL}")
    print(f"🧠 Model: {MODEL_NAME}")
    print("═" * 80)
    print("\n[SYSTEM CONTEXT]")
    print(explain_network_context())
    print("═" * 80)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
