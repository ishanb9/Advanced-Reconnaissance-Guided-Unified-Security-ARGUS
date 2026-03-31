#!/bin/bash
# setup_vendor.sh — Download vendor JS/CSS files to serve locally
# Run this ONCE on your Kali machine from the platform root directory:
#   bash setup_vendor.sh
#
# This fixes CORB (Cross-Origin Read Blocking) errors for xterm.js
# and removes CDN dependencies for critical libraries.

set -e
VENDOR="static/vendor"
mkdir -p "$VENDOR"

echo "Downloading vendor files to $VENDOR/ ..."

# xterm.js — PTY terminal (CORB-blocked when loaded from CDN)
curl -sL "https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.js" \
  -o "$VENDOR/xterm.min.js" && echo "  ✓ xterm.min.js" || \
  curl -sL "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js" \
    -o "$VENDOR/xterm.min.js" && echo "  ✓ xterm.min.js (jsdelivr fallback)"

curl -sL "https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.css" \
  -o "$VENDOR/xterm.min.css" && echo "  ✓ xterm.min.css" || \
  curl -sL "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" \
    -o "$VENDOR/xterm.min.css" && echo "  ✓ xterm.min.css (jsdelivr fallback)"

echo ""
echo "Sizes:"
ls -lh "$VENDOR/"
echo ""
echo "Done. Restart the server and hard-refresh (Ctrl+Shift+R)."
