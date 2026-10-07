#!/bin/bash
# ReconHawk Web UI launcher
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
  echo "[!] Run ./install.sh first"
  exit 1
fi

source venv/bin/activate

# Open browser after 1.5s
(sleep 1.5 && xdg-open "http://127.0.0.1:5000" 2>/dev/null || open "http://127.0.0.1:5000" 2>/dev/null) &

echo ""
echo "  🦅 ReconHawk Web UI"
echo "  ─────────────────────────────"
echo "  URL:  http://127.0.0.1:5000"
echo "  Stop: Ctrl+C"
echo ""

python3 app.py
