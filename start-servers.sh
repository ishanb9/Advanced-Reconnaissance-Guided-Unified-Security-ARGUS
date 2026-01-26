#!/bin/bash

echo "Starting Kali Pentest Platform..."
echo "=================================="
echo ""

# Start MCP server as root in background
echo "1. Starting MCP Server (requires sudo)..."
sudo node mcp-server.js &
MCP_PID=$!
sleep 2

# Start web server as normal user
echo "2. Starting Web Server..."
python3 web-server.py &
WEB_PID=$!

echo ""
echo "=================================="
echo "✅ Platform Started!"
echo "=================================="
echo "MCP Server PID: $MCP_PID"
echo "Web Server PID: $WEB_PID"
echo ""
echo "Access UI at: http://localhost:5000"
echo ""
echo "To stop:"
echo "  sudo kill $MCP_PID"
echo "  kill $WEB_PID"
echo "=================================="

# Wait for Ctrl+C
trap "echo 'Stopping servers...'; sudo kill $MCP_PID; kill $WEB_PID; exit" INT
wait
