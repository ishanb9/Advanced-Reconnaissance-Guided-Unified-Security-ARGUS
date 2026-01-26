# Contributing to Kali MCP Pentest Platform

Thank you for considering contributing to this project! We welcome contributions from the community.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

## 📜 Code of Conduct

### Pledge

We are committed to providing a welcoming and inspiring community for all. Please be respectful and constructive.

### Standards

✅ **Do:**
- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards others

❌ **Don't:**
- Use inappropriate language
- Make personal attacks
- Harass or troll others
- Publish others' private information

## How to Contribute

### Types of Contributions

We welcome:
- 🐛 Bug fixes
- ✨ New features
- 📝 Documentation improvements
- 🎨 UI/UX enhancements
- 🔧 Tool integrations
- 🧪 Test coverage
- 🌍 Translations

### Before You Start

1. Check existing [Issues](https://github.com/ishanb9/kali-mcp-pentest/issues) and [Pull Requests](https://github.com/ishanb9/kali-mcp-pentest/pulls)
2. Open an issue to discuss major changes
3. Fork the repository
4. Create a feature branch

## Development Setup

### Prerequisites
```bash
# System requirements
- Kali Linux or Debian-based OS
- Node.js 18+
- Python 3.8+
- Ollama with a compatible model
- Git
```

### Setup Steps
```bash
# 1. Fork and clone
git clone https://github.com/ishanb9/kali-mcp-pentest.git
cd kali-mcp-pentest

# 2. Create feature branch
git checkout -b feature/your-feature-name

# 3. Install dependencies
npm install
pip3 install -r requirements.txt

# 4. Start development servers
# Terminal 1
sudo node mcp-server.js

# Terminal 2
python3 web-server.py

# 5. Open browser
http://localhost:5000
```

### Project Structure
```
kali-mcp-pentest/
├── mcp-server.js           # MCP tool execution server
├── web-server.py           # Flask web application
├── templates/
│   └── index.html          # Main UI template
├── static/
│   ├── css/
│   │   └── style.css       # Styling
│   └── js/
│       └── app.js          # Frontend logic
├── docs/                   # Documentation
├── tests/                  # Test files
└── README.md
```

## 📏 Coding Standards

### JavaScript (mcp-server.js, app.js)
```javascript
// Use const/let, never var
const toolName = 'nmap';
let outputCount = 0;

// Clear function names
function executeSecurityTool(name, options) { }

// Handle errors properly
try {
  // code
} catch (error) {
  console.error('[ERROR]', error.message);
}

// Add comments for complex logic
// Keep-alive: prevents client timeout during long scans
const heartbeat = setInterval(() => { }, 2000);
```

### Python (web-server.py)
```python
# Follow PEP 8
# Use type hints where helpful
def analyze_query(user_message: str) -> dict:
    """Analyze user query and return tool selection."""
    pass

# Clear error messages
except Exception as e:
    print(f"[ERROR] {e}")
    traceback.print_exc()

# Document complex functions
def get_system_context():
    """
    Detect network configuration and interfaces.
    
    Returns:
        dict: System context including interfaces, networks, gateway
    """
    pass
```

### CSS (style.css)
```css
/* Use CSS variables for theming */
:root {
    --primary: #00d4ff;
    --secondary: #0080ff;
}

/* Clear class names */
.exec-block { }
.output-line { }

/* Comment major sections */
/* ============ Input Bar ============ */
```

### HTML (index.html)
```html
<!-- Semantic HTML -->
<section class="terminal-output">
  <div class="exec-block">
    <!-- content -->
  </div>
</section>

<!-- Clear IDs -->
<button id="executeBtn">Execute</button>
```

## 🔄 Pull Request Process

### 1. Prepare Your Changes
```bash
# Make sure you're on your feature branch
git checkout feature/your-feature-name

# Make changes
# Test thoroughly

# Commit with clear messages
git add .
git commit -m "Add: Feature description"
```

### 2. Commit Message Format
```
Type: Brief description

Detailed explanation if needed

Closes #123
```

**Types:**
- `Add:` New feature
- `Fix:` Bug fix
- `Update:` Modify existing feature
- `Refactor:` Code restructuring
- `Docs:` Documentation only
- `Style:` Formatting, no code change
- `Test:` Add/modify tests

**Examples:**
```
Add: Stop button for running commands

Implements a stop button in the execution footer that allows
users to halt long-running scans. Closes EventSource connection
and updates UI appropriately.

Closes #42
```
```
Fix: MCP server disconnect issue

Resolved premature client disconnect by changing from req.on('close')
to res.on('close') event handler. This properly detects actual
connection termination rather than request body completion.

Fixes #15
```

### 3. Submit Pull Request

1. Push to your fork:
```bash
git push origin feature/your-feature-name
```

2. Go to GitHub and create Pull Request

3. Fill in PR template:
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring

## Testing
- [ ] Tested on Kali Linux
- [ ] MCP server works
- [ ] Web interface functions
- [ ] No console errors

## Screenshots (if applicable)
[Add screenshots]

## Related Issues
Closes #XX
```

### 4. Code Review Process

- Maintainer will review
- Address any requested changes
- Once approved, we'll merge!

## 🐛 Reporting Bugs

### Before Reporting

1. Check [existing issues](https://github.com/ishanb9/kali-mcp-pentest/issues)
2. Try latest version
3. Gather debug information

### Bug Report Template
```markdown
**Describe the bug**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected behavior**
What should happen

**Actual behavior**
What actually happens

**Screenshots**
If applicable

**Environment:**
- OS: [e.g., Kali Linux 2024.1]
- Node.js version: [e.g., 18.19.0]
- Python version: [e.g., 3.11.2]
- Browser: [e.g., Firefox 120]
- Ollama model: [e.g., mistral]

**Console Output**
```
[Paste MCP server output]
[Paste web server output]
[Paste browser console errors]
```

**Additional context**
Any other relevant information
```

## ✨ Feature Requests

### Feature Request Template
```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of desired feature

**Describe alternatives considered**
Other approaches you've thought about

**Use case**
How would this be used?

**Additional context**
Mockups, examples, etc.
```

## 🧪 Testing Guidelines

### Before Submitting PR

Test these scenarios:

**Basic Functionality:**
- [ ] MCP server starts without errors
- [ ] Web server starts without errors
- [ ] UI loads properly
- [ ] Arsenal shows all 217 tools
- [ ] Tool search works

**Command Execution:**
- [ ] Manual tool execution works
- [ ] Natural language commands work
- [ ] Output streams in real-time
- [ ] Stop button halts commands
- [ ] Errors display properly

**AI Features:**
- [ ] LLM analysis returns results
- [ ] Context awareness works
- [ ] Conversation history persists
- [ ] Clear history button works

**Edge Cases:**
- [ ] Long-running commands (nmap)
- [ ] Commands that fail
- [ ] Multiple simultaneous commands
- [ ] Browser refresh during execution


## 🙏 Thank You!

This is an experimental project so please anticipate issues.
Your contributions make this project better for everyone!

---

**Happy Contributing! **
