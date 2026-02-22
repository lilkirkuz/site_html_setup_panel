#!/bin/zsh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Prefer project-local Node.js if present; fallback to system Node.
if [ -x "$SCRIPT_DIR/.local/node-current/bin/node" ]; then
  export PATH="$SCRIPT_DIR/.local/node-current/bin:$PATH"
fi

if ! command -v node >/dev/null 2>&1; then
  osascript -e 'display alert "Node.js not found" message "Install Node.js or keep .local/node-current in the project folder." as warning'
  exit 1
fi

if [ ! -d "$SCRIPT_DIR/node_modules" ]; then
  npm install
fi

# Open app in browser after short startup delay.
( sleep 2; open "http://localhost:3000" ) &

npm start
