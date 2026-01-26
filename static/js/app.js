// DOM Elements
const arsenalBtn = document.getElementById('arsenalBtn');
const arsenalPanel = document.getElementById('arsenalPanel');
const closeArsenal = document.getElementById('closeArsenal');
const toolsList = document.getElementById('toolsList');
const toolCount = document.getElementById('toolCount');
const searchTools = document.getElementById('searchTools');
const toolInput = document.getElementById('toolInput');
const targetInput = document.getElementById('targetInput');
const optionsInput = document.getElementById('optionsInput');
const executeBtn = document.getElementById('executeBtn');
const output = document.getElementById('output');
const clock = document.getElementById('clock');
const status = document.getElementById('status');
const chatInput = document.getElementById('chatInput');
const chatBtn = document.getElementById('chatBtn');

let allTools = [];
let execCounter = 0;

// Cyber Background Animation
const canvas = document.getElementById('cyberCanvas');
const ctx = canvas.getContext('2d');

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

const particles = [];
const particleCount = 100;

class Particle {
    constructor() {
        this.x = Math.random() * canvas.width;
        this.y = Math.random() * canvas.height;
        this.vx = (Math.random() - 0.5) * 0.5;
        this.vy = (Math.random() - 0.5) * 0.5;
        this.size = Math.random() * 2;
    }
    
    update() {
        this.x += this.vx;
        this.y += this.vy;
        
        if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
        if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }
    
    draw() {
        ctx.fillStyle = 'rgba(0, 212, 255, 0.6)';
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
        ctx.fill();
    }
}

// Initialize particles
for (let i = 0; i < particleCount; i++) {
    particles.push(new Particle());
}

function animateBackground() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw particles
    particles.forEach(particle => {
        particle.update();
        particle.draw();
    });
    
    // Draw connections
    particles.forEach((p1, i) => {
        particles.slice(i + 1).forEach(p2 => {
            const dx = p1.x - p2.x;
            const dy = p1.y - p2.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            if (distance < 150) {
                ctx.strokeStyle = `rgba(0, 212, 255, ${0.2 * (1 - distance / 150)})`;
                ctx.lineWidth = 0.5;
                ctx.beginPath();
                ctx.moveTo(p1.x, p1.y);
                ctx.lineTo(p2.x, p2.y);
                ctx.stroke();
            }
        });
    });
    
    requestAnimationFrame(animateBackground);
}

animateBackground();

window.addEventListener('resize', () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
});

// Clock
function updateClock() {
    const now = new Date();
    const h = String(now.getHours()).padStart(2, '0');
    const m = String(now.getMinutes()).padStart(2, '0');
    const s = String(now.getSeconds()).padStart(2, '0');
    clock.textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);
updateClock();

// Arsenal Panel
arsenalBtn.addEventListener('click', () => {
    arsenalPanel.classList.add('open');
});

closeArsenal.addEventListener('click', () => {
    arsenalPanel.classList.remove('open');
});

// Load Tools
async function loadTools() {
    try {
        console.log('Loading tools from server...');
        const response = await fetch('/api/tools');
        const data = await response.json();
        
        if (data.tools) {
            allTools = data.tools;
            toolCount.textContent = allTools.length;
            renderTools(allTools);
            status.textContent = 'ONLINE';
            status.style.color = '#00ff88';
            console.log(`Loaded ${allTools.length} tools`);
        } else {
            throw new Error('No tools in response');
        }
    } catch (error) {
        console.error('Failed to load tools:', error);
        toolsList.innerHTML = `
            <div class="loading">
                <i class="fas fa-exclamation-triangle"></i>
                <span>Failed to load tools</span>
                <p style="font-size: 12px; margin-top: 10px;">${error.message}</p>
            </div>
        `;
        status.textContent = 'OFFLINE';
        status.style.color = '#ff3366';
    }
}

function renderTools(tools) {
    if (tools.length === 0) {
        toolsList.innerHTML = '<div class="loading">No tools found</div>';
        return;
    }
    
    toolsList.innerHTML = tools.map(tool => `
        <div class="tool-item" onclick="selectTool('${tool.name}')">
            <div class="tool-name">${tool.name}</div>
            <div class="tool-desc">${tool.description}</div>
        </div>
    `).join('');
}

window.selectTool = function(name) {
    toolInput.value = name;
    arsenalPanel.classList.remove('open');
    targetInput.focus();
    console.log(`Selected tool: ${name}`);
};

// Search Tools
searchTools.addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    const filtered = allTools.filter(tool => 
        tool.name.toLowerCase().includes(query) ||
        tool.description.toLowerCase().includes(query)
    );
    renderTools(filtered);
});

// Intelligent Chat with LLM Analysis
async function sendChatMessage() {
    const message = chatInput.value.trim();
    
    if (!message) {
        alert('Please enter a command');
        return;
    }
    
    console.log(`[CHAT] Sending: ${message}`);
    
    chatBtn.disabled = true;
    chatBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>ANALYZING...</span>';
    
    // Show thinking indicator
    const welcome = output.querySelector('.welcome');
    if (welcome) welcome.remove();
    
    const thinkingBlock = document.createElement('div');
    thinkingBlock.className = 'exec-block';
    thinkingBlock.innerHTML = `
        <div class="exec-header">
            <div class="exec-tool"><i class="fas fa-brain"></i> AI ANALYSIS</div>
        </div>
        <div class="exec-output" style="padding: 20px;">
            <div class="output-line"><i class="fas fa-spinner fa-spin"></i> Analyzing your request...</div>
            <div class="output-line"><i class="fas fa-network-wired"></i> Detecting network configuration...</div>
            <div class="output-line"><i class="fas fa-robot"></i> Reasoning about optimal approach...</div>
        </div>
    `;
    output.appendChild(thinkingBlock);
    thinkingBlock.scrollIntoView({ behavior: 'smooth' });
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message })
        });
        
        const analysis = await response.json();
        
        if (analysis.error) {
            thinkingBlock.querySelector('.exec-output').innerHTML = `
                <div class="output-line error"><strong>Error:</strong> ${analysis.error}</div>
            `;
            chatBtn.disabled = false;
            chatBtn.innerHTML = '<i class="fas fa-paper-plane"></i><span>SEND</span>';
            return;
        }
        
        // Display AI reasoning
        thinkingBlock.querySelector('.exec-output').innerHTML = `
            <div class="output-line" style="margin-bottom: 15px;">
                <strong style="color: #00ffcc;">🤖 AI REASONING:</strong><br>
                ${analysis.reasoning}
            </div>
            <div class="output-line" style="margin-bottom: 10px;">
                <strong style="color: #00d4ff;">📋 PLAN:</strong><br>
                ${analysis.explanation}
            </div>
            <div class="output-line" style="margin-bottom: 10px;">
                <strong style="color: #ffaa00;">⚙️ COMMAND:</strong><br>
                <code>sudo ${analysis.tool} ${analysis.options} ${analysis.target}</code>
            </div>
            ${analysis.warnings && analysis.warnings.length > 0 ? `
                <div class="output-line" style="margin-top: 15px;">
                    <strong style="color: #ff3366;">⚠️ WARNINGS:</strong><br>
                    ${analysis.warnings.map(w => `  • ${w}`).join('<br>')}
                </div>
            ` : ''}
            <div class="output-line" style="margin-top: 15px;">
                <strong style="color: #00ff88;">📊 EXPECTED OUTPUT:</strong><br>
                ${analysis.expected_output}
            </div>
        `;
        
        // Fill in manual fields
        toolInput.value = analysis.tool;
        targetInput.value = analysis.target || '';
        optionsInput.value = analysis.options || '';
        
        // Auto-execute after 2 seconds
        chatInput.value = '';
        
        setTimeout(() => {
            executeCommand();
        }, 2000);
        
    } catch (error) {
        console.error('[CHAT ERROR]', error);
        thinkingBlock.querySelector('.exec-output').innerHTML = `
            <div class="output-line error"><strong>Error:</strong> ${error.message}</div>
        `;
    } finally {
        chatBtn.disabled = false;
        chatBtn.innerHTML = '<i class="fas fa-paper-plane"></i><span>SEND</span>';
    }
}

chatBtn.addEventListener('click', sendChatMessage);

chatInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendChatMessage();
});


// Execute Command
async function executeCommand() {
    const tool = toolInput.value.trim();
    const target = targetInput.value.trim();
    const options = optionsInput.value.trim();
    
    if (!tool) {
        alert('Please enter a tool name');
        return;
    }
    
    console.log(`Executing: ${tool} ${options} ${target}`);
    
    executeBtn.disabled = true;
    executeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>EXECUTING...</span>';
    
    // Remove welcome screen
    const welcome = output.querySelector('.welcome');
    if (welcome) welcome.remove();
    
    // Create execution block
    execCounter++;
    const execId = execCounter;
    
    const block = document.createElement('div');
    block.className = 'exec-block';
    block.id = `exec-${execId}`;
    
    const startTime = Date.now();
    
     block.innerHTML = `
        <div class="exec-header">
            <div class="exec-tool">#${execId} ${tool}</div>
            <div class="exec-timer" id="timer-${execId}">0.0s</div>
        </div>
        <div class="exec-command">$ sudo ${tool} ${options} ${target}</div>
        <div class="exec-output" id="output-${execId}">
            <div class="output-line"><i class="fas fa-spinner fa-spin"></i> Starting...</div>
        </div>
        <div class="exec-footer">
            <div class="status running" id="status-${execId}">
                <i class="fas fa-circle-notch fa-spin"></i> RUNNING
            </div>
            <div style="display: flex; align-items: center; gap: 15px;">
                <div id="stats-${execId}">Lines: 0 | Waiting for output...</div>
                <button class="btn-stop" id="stop-${execId}">
                    <i class="fas fa-stop"></i>
                    <span>STOP</span>
                </button>
            </div>
        </div>
    `;
    
    output.appendChild(block);
    block.scrollIntoView({ behavior: 'smooth' });
    
    const outputEl = document.getElementById(`output-${execId}`);
    const timerEl = document.getElementById(`timer-${execId}`);
    const statusEl = document.getElementById(`status-${execId}`);
    const statsEl = document.getElementById(`stats-${execId}`);
    
    let lineCount = 0;
    let lastActivity = Date.now();
    
    // Timer that also monitors for stalls
    const timerInterval = setInterval(() => {
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        timerEl.textContent = `${elapsed}s`;
        
        const inactive = Math.floor((Date.now() - lastActivity) / 1000);
        if (inactive > 5) {
            statsEl.textContent = `Lines: ${lineCount} | No output for ${inactive}s (still running...)`;
        } else {
            statsEl.textContent = `Lines: ${lineCount}`;
        }
    }, 100);
    
    // EventSource with proper configuration
    const url = `/api/execute?tool=${encodeURIComponent(tool)}&target=${encodeURIComponent(target)}&options=${encodeURIComponent(options)}`;
    
    console.log(`[EventSource] Opening: ${url}`);
    const eventSource = new EventSource(url);
    
    // Stop button handler
    const stopBtn = document.getElementById(`stop-${execId}`);
    stopBtn.addEventListener('click', () => {
        console.log(`[STOP] User requested stop for execution #${execId}`);
        
        // Close the event source
        eventSource.close();
        
        // Update UI
        clearInterval(timerInterval);
        statusEl.className = 'status error';
        statusEl.innerHTML = '<i class="fas fa-hand-paper"></i> STOPPED';
        stopBtn.disabled = true;
        
        // Add stop message to output
        const stopLine = document.createElement('div');
        stopLine.className = 'output-line error';
        stopLine.innerHTML = '<strong>[USER STOPPED]</strong> Execution terminated by user';
        outputEl.appendChild(stopLine);
        
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        statsEl.textContent = `Stopped after ${elapsed}s | ${lineCount} lines`;
    });

    // Track connection state
    let hasReceivedData = false;
    
    eventSource.onopen = () => {
        console.log('[EventSource] Connection opened');
    };
    
    eventSource.onmessage = (event) => {
        hasReceivedData = true;
        lastActivity = Date.now();
        
        const data = JSON.parse(event.data);
        console.log('[EventSource] Message:', data.type);
        
        if (data.type === 'start') {
            outputEl.innerHTML = '';
            const startLine = document.createElement('div');
            startLine.className = 'output-line';
            startLine.innerHTML = '<i class="fas fa-play"></i> Command started...';
            outputEl.appendChild(startLine);
            lineCount++;
        } else if (data.type === 'output') {
            const line = document.createElement('div');
            line.className = 'output-line';
            
            if (data.data.includes('[ERROR]') || data.data.includes('[CRITICAL ERROR]')) {
                line.classList.add('error');
            }
            
            line.textContent = data.data;
            outputEl.appendChild(line);
            lineCount++;
            outputEl.scrollTop = outputEl.scrollHeight;
        } else if (data.type === 'complete') {
            console.log('[EventSource] Command completed successfully');
            clearInterval(timerInterval);
            statusEl.className = 'status complete';
            statusEl.innerHTML = '<i class="fas fa-check-circle"></i> COMPLETE';
            stopBtn.disabled = true;
            eventSource.close();
            
            const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
            statsEl.textContent = `Completed in ${elapsed}s | ${lineCount} lines`;
        } else if (data.type === 'error') {
            console.log('[EventSource] Command error:', data.message);
            clearInterval(timerInterval);
            statusEl.className = 'status error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> ERROR';
	    stopBtn.disabled = true;
            
            if (data.message) {
                const errorLine = document.createElement('div');
                errorLine.className = 'output-line error';
                errorLine.innerHTML = `<strong>${data.message}</strong>`;
                outputEl.appendChild(errorLine);
            }
            
            if (data.suggestions && data.suggestions.length > 0) {
                const suggestionsLine = document.createElement('div');
                suggestionsLine.className = 'output-line';
                suggestionsLine.style.marginTop = '10px';
                suggestionsLine.innerHTML = '<strong>💡 Suggestions:</strong>';
                outputEl.appendChild(suggestionsLine);
                
                data.suggestions.forEach(suggestion => {
                    const suggLine = document.createElement('div');
                    suggLine.className = 'output-line';
                    suggLine.style.paddingLeft = '20px';
                    suggLine.textContent = `• ${suggestion}`;
                    outputEl.appendChild(suggLine);
                });
            }
            
            eventSource.close();
        }
    };
    
    eventSource.onerror = (error) => {
        console.error('[EventSource] Error:', error);
        
        // Only show error if we never received data (immediate disconnect)
        if (!hasReceivedData) {
            clearInterval(timerInterval);
            statusEl.className = 'status error';
            statusEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> CONNECTION ERROR';
            stopBtn.disabled = true;
            
            const errorLine = document.createElement('div');
            errorLine.className = 'output-line error';
            errorLine.innerHTML = `
                <strong>[CONNECTION ERROR]</strong><br>
                Failed to establish connection to server.<br>
                <br>
                <strong>Possible causes:</strong><br>
                • MCP server is not running (check Terminal 1)<br>
                • Web server lost connection to MCP<br>
                • Network/firewall blocking connection<br>
                <br>
                <strong>Solutions:</strong><br>
                • Restart MCP server: cd ~/mcp-pentest && node mcp-server.js<br>
                • Check if MCP is running: curl http://localhost:3000<br>
                • Check server logs in terminal
            `;
            outputEl.appendChild(errorLine);
            
            eventSource.close();
        }
    };
    
    // Re-enable button
    setTimeout(() => {
        executeBtn.disabled = false;
        executeBtn.innerHTML = '<i class="fas fa-bolt"></i><span>EXECUTE</span>';
    }, 2000);
}
executeBtn.addEventListener('click', executeCommand);

// Enter key support
[toolInput, targetInput, optionsInput].forEach(input => {
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') executeCommand();
    });
});

// Load tools on startup
loadTools();
console.log('🚀 Kali Pentest Terminal initialized');

// Clear conversation history
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

clearHistoryBtn.addEventListener('click', async () => {
    if (!confirm('Clear conversation history? The AI will forget previous context.')) {
        return;
    }
    
    try {
        const response = await fetch('/api/conversation/clear', {
            method: 'POST'
        });
        
        if (response.ok) {
            console.log('[HISTORY] Conversation cleared');
            
            // Visual feedback
            clearHistoryBtn.innerHTML = '<i class="fas fa-check"></i><span>CLEARED</span>';
            setTimeout(() => {
                clearHistoryBtn.innerHTML = '<i class="fas fa-trash"></i><span>CLEAR</span>';
            }, 2000);
        }
    } catch (error) {
        console.error('[HISTORY ERROR]', error);
    }
});
