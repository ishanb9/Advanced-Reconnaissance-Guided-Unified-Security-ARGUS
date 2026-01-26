# Kali MCP Pentest-Assist Platform

An AI-powered penetration testing assistance platform that combines Kali Linux security tools with Large Language Models (LLMs) through the Model Context Protocol (MCP). This platform enables natural language interaction with 217+ security tools, providing contextual awareness, intelligent tool selection, and detailed explanations for every action.


## Features

### AI-Powered Intelligence
- **Natural Language Commands**: "scan my local network", "enable monitor mode on wlan0"
- **Contextual Awareness**: Remembers previous commands and results
- **Smart Tool Selection**: AI chooses appropriate tool based on intent
- **Detailed Reasoning**: Explains why each tool and option is selected
- **Network Context Detection**: Detects your network configuration

### Technical Capabilities
- **200+ Kali Tools**: Complete arsenal of penetration testing tools
- **Real-time Streaming**: Live command output with progress tracking
- **MCP Architecture**: Clean separation between AI, tools, and UI
- **Local LLM Support**: Works with Ollama (privacy-focused, no cloud)
- **Manual Override**: Expert users can bypass AI and use tools directly

### Interface
- **Cyber Theme**: Animated background with matrix effects
- **Real-time Execution**: Live output streaming with timers
- **Command History**: Full conversation memory across session
- **Stop Controls**: Halt long-running commands anytime
- **Arsenal Browser**: Search and filter 200+ tools

## 🏗️ Architecture
```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Web Browser   │◄────►│  Flask Web Server │◄────►│   Ollama LLM    │
│  (Port 5000)    │      │   (Port 5000)     │      │  (Port 11434)   │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   MCP Server     │
                         │  (Port 3000)     │
                         └──────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  Kali Linux      │
                         │  Security Tools  │
                         └──────────────────┘
```

### Components

1. **MCP Server** (Node.js) - Port 3000
   - Manages 217 Kali security tools
   - Executes commands with proper permissions
   - Streams real-time output via Server-Sent Events (SSE)

2. **Web Server** (Python Flask) - Port 5000
   - Serves web interface
   - Routes requests between UI and MCP
   - Handles AI integration with Ollama
   - Manages conversation history and context

3. **AI Engine** (Ollama) - Port 11434
   - Processes natural language queries
   - Provides intelligent tool selection
   - Generates detailed explanations
   - Maintains conversation context

## 📋 Prerequisites

- **OS**: Kali Linux (recommended) or any Debian-based Linux
- **Node.js**: v18 or higher
- **Python**: 3.8 or higher
- **Ollama**: Latest version with a compatible model
- **RAM**: 16GB+ recommended (for LLM)
- **Network**: Local network access for scanning

## 🚀 Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/ishanb9/kali-mcp-pentest.git
cd kali-mcp-pentest
```

### 2. Install Dependencies
```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip3 install flask flask-cors requests netifaces --break-system-packages
```

### 3. Install Ollama and Model
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a compatible model (choose one)
ollama pull mistral          # Smaller, faster
ollama pull llama3.1:8b      # Balanced
ollama pull qwen2.5:32b      # Best quality

# Start Ollama service
ollama serve
```

### 4. Configure Application
```bash
# Edit web-server.py to set your Ollama configuration
nano web-server.py

# Update these lines:
OLLAMA_URL = "http://localhost:11434"  # Change if Ollama is on different host
MODEL_NAME = "mistral"                  # Change to your model name
```

### 5. Configure Sudo (Required)

Security tools need root access. Configure passwordless sudo:
```bash
# Add your user to sudoers (replace 'kali' with your username)
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/$USER
sudo chmod 440 /etc/sudoers.d/$USER

# Verify
sudo -n whoami  # Should print 'root' without asking for password
```

### 6. Start Services

**Option A: Manual (Two Terminals)**

Terminal 1 - MCP Server:
```bash
sudo node mcp-server.js
```

Terminal 2 - Web Server:
```bash
python3 web-server.py
```

**Option B: Startup Script (Background)**
```bash
chmod +x start-servers.sh
./start-servers.sh
```

### 7. Access Platform

Open browser and navigate to:
```
http://localhost:5000
```

Or from another device on your network:
```
http://YOUR_KALI_IP:5000
```

## Usage Examples

### Natural Language Commands
```
"show me my network interfaces"
→ AI selects: ifconfig

"scan my local network"
→ AI detects network (e.g., 192.168.11.0/24)
→ AI selects: nmap -sn 192.168.11.0/24

"enable monitor mode on wlan0"
→ AI selects: airmon-ng start wlan0

"scan wifi networks"
→ AI selects: airodump-ng wlan0mon
```

### Contextual Follow-up
```
User: "show my network interfaces"
AI: [runs ifconfig, shows eth0: 192.168.0.114]

User: "scan that network"
AI: [remembers 192.168.0.0/24 from ifconfig]
AI: [runs nmap -sn 192.168.0.0/24]

User: "the third host, scan it for open ports"
AI: [remembers 192.168.0.15 from previous scan]
AI: [runs nmap -sV 192.168.0.15]
```

### Manual Tool Execution

1. Click **ARSENAL** button
2. Search for tool (e.g., "nmap")
3. Click tool to auto-fill
4. Enter target and options
5. Click **EXECUTE**

## Available Tool Categories

- **Information Gathering** (33 tools): nmap, nikto, whois, dnsenum, etc.
- **Wireless Attacks** (16 tools): aircrack-ng, wifite, reaver, etc.
- **Web Applications** (20 tools): burpsuite, sqlmap, dirb, etc.
- **Password Attacks** (18 tools): hydra, john, hashcat, etc.
- **Exploitation** (15 tools): metasploit, beef-xss, etc.
- **Sniffing & Spoofing** (15 tools): wireshark, ettercap, etc.
- **Post Exploitation** (7 tools): weevely, mimikatz, etc.
- **Forensics** (11 tools): autopsy, volatility, etc.
- **And 100+ more...**

## Configuration

### Change Ollama Model
```python
# In web-server.py
MODEL_NAME = "llama3.1:8b"  # Change to your preferred model
```

### Change Network Interface

The platform auto-detects your network. To manually override:
```python
# In web-server.py, modify get_system_context() function
```

### Customize UI Theme
```css
/* In static/css/style.css */
:root {
    --primary: #00d4ff;    /* Change primary color */
    --secondary: #0080ff;  /* Change secondary color */
}
```

## Troubleshooting

### Commands Fail Immediately

**Symptom**: All commands exit with "terminated" error

**Solution**: Check sudo configuration
```bash
sudo -n whoami  # Should work without password
```

### Cannot Connect to Ollama

**Symptom**: "Cannot connect to Ollama at http://..."

**Solutions**:
1. Check Ollama is running: `ps aux | grep ollama`
2. Verify port: `curl http://localhost:11434/api/tags`
3. Update `OLLAMA_URL` in `web-server.py`

### No Tools in Arsenal

**Symptom**: Arsenal shows 0 tools

**Solution**: Check MCP server is running
```bash
curl http://localhost:3000
# Should return 405 Method Not Allowed (server is running)
```

### Browser Shows "Connection Failed"

**Solution**: Check both servers are running
```bash
sudo netstat -tlnp | grep -E '3000|5000'
# Should show both ports listening
```

##  Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Contribution Guide

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test thoroughly
5. Commit: `git commit -m 'Add amazing feature'`
6. Push: `git push origin feature/amazing-feature`
7. Open Pull Request

##  License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

### Third-Party Tools

This platform interfaces with Kali Linux security tools. Each tool has its own license:
- Kali Linux tools: Various licenses (GPL, BSD, etc.)
- Refer to individual tool documentation for licensing information

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

- Only use on networks/systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors assume no liability for misuse of this software
- Users are responsible for complying with all applicable laws

##  Acknowledgments

- **Kali Linux Team** - For the comprehensive security tool suite
- **Anthropic** - For the Model Context Protocol specification
- **Ollama Team** - For local LLM infrastructure
- **Open Source Community** - For all the amazing tools and libraries

##  Roadmap

- [ ] Execute multiple commands in parallel
- [ ] Saved scan profiles and templates
- [ ] Export reports in multiple formats (PDF, HTML, JSON)
- [ ] Handle web enumeration and exploit upload functionalities
- [ ] Custom payload creation or alteration
- [ ] Listen for reverse shells and initiate shells from UI
- [ ] UI enhancements and customization
- [ ] Collaborative team features

